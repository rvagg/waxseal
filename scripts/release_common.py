"""GitHub, registry and archive helpers shared by the npm and Rust publishers."""

from contextlib import contextmanager
import gzip
import hashlib
import http.client
import json
import os
import pathlib
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_METADATA = 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_UNPACKED = 512 * 1024 * 1024
MAX_CHANGELOG = 4 * 1024 * 1024
MAX_ARTIFACT_ZIP = MAX_ARCHIVE + MAX_METADATA
MAX_VERIFIER_DIAGNOSTIC = 4096
RELEASE_ATTESTATION_TIMEOUT = 300

VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SHA = re.compile(r"[0-9a-f]{40}")
CHANGELOG_HEADING = re.compile(r"^## \[?v?([0-9]+\.[0-9]+\.[0-9]+)\]?(?:\(|\s|$)")
FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


def fail(message):
    raise SystemExit(message)


def canonical_repository(value):
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str):
        return None
    if value.startswith("git+"):
        value = value[4:]
    match = re.fullmatch(
        r"(?:https://github\.com/|ssh://git@github\.com/)([^/\s]+)/([^/\s]+?)(?:\.git)?",
        value,
    )
    if match is None:
        match = re.fullmatch(r"git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?", value)
    if match is None:
        return None
    return f"{match[1]}/{match[2]}"


def release_notes(text, version):
    matches = []
    body = []
    collecting = False
    fence = None
    for line in text.splitlines(keepends=True):
        plain = line.rstrip("\r\n")
        marker = FENCE.match(plain)
        if fence:
            if re.fullmatch(rf" {{0,3}}{re.escape(fence[0])}{{{fence[1]},}}[ \t]*", plain):
                fence = None
            if collecting:
                body.append(line)
            continue
        if marker:
            fence = (marker[1][0], len(marker[1]))
            if collecting:
                body.append(line)
            continue
        heading = CHANGELOG_HEADING.match(plain)
        if heading:
            if collecting:
                matches.append("".join(body).strip())
                body = []
                collecting = False
            if heading[1] == version:
                collecting = True
            continue
        if collecting:
            body.append(line)
    if collecting:
        matches.append("".join(body).strip())
    if len(matches) != 1 or not matches[0]:
        fail("changelog has no unambiguous release notes")
    return matches[0]


def same_metadata(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_metadata(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same_metadata(a, b) for a, b in zip(left, right))
    return left == right


def package_directory(root, value):
    candidate = pathlib.PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts:
        fail("package directory is invalid")
    path = root / pathlib.Path(*candidate.parts)
    try:
        directory = path.resolve(strict=True)
        directory.relative_to(root)
    except (OSError, ValueError):
        fail("package directory is outside the trusted checkout")
    if not directory.is_dir():
        fail("package directory is invalid")
    return directory


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


SYSTEM_CA = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
if not SYSTEM_CA.is_file():
    raise RuntimeError("system certificate bundle is unavailable")
SYSTEM_TRUST = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
SYSTEM_TRUST.check_hostname = True
SYSTEM_TRUST.verify_mode = ssl.CERT_REQUIRED
SYSTEM_TRUST.load_verify_locations(cafile=str(SYSTEM_CA))
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPSHandler(context=SYSTEM_TRUST))
OPENER.addheaders = [("User-Agent", "waxseal/1 (+https://github.com/rvagg/waxseal)")]


class ReadUnavailable(Exception):
    pass


def run(*args, input=None, cwd=None, env=None, timeout=120):
    command_env = os.environ.copy() if env is None else env.copy()
    command_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    if args[0] in {"git", "gh"}:
        token = command_env.get("GH_TOKEN")
        with tempfile.TemporaryDirectory(prefix="waxseal-command-", dir=os.environ.get("RUNNER_TEMP")) as home:
            command_env = {"PATH": command_env["PATH"], "HOME": home,
                           "XDG_CONFIG_HOME": f"{home}/.config", "XDG_CACHE_HOME": f"{home}/.cache"}
            if args[0] == "gh":
                if not token:
                    fail("GitHub job token is required")
                command_env.update({"GH_HOST": "github.com", "GH_TOKEN": token,
                                    "GH_CONFIG_DIR": f"{home}/.config/gh", "GH_PROMPT_DISABLED": "1"})
            else:
                command_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                                    "GIT_TERMINAL_PROMPT": "0"})
            return subprocess.run(args, input=input, cwd=home, env=command_env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  check=True, timeout=timeout).stdout
    return subprocess.run(args, input=input, cwd=cwd, env=command_env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=timeout).stdout


def fail_verifier(error):
    command = " ".join(error.cmd[:3])
    if isinstance(error, subprocess.TimeoutExpired):
        reason = f"timed out after {error.timeout} seconds"
    else:
        reason = f"failed with exit status {error.returncode}"
    streams = []
    for label, value in (("stderr", error.stderr), ("stdout", error.output)):
        if value:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            streams.append(f"{label}:\n{value}")
    details = "\n".join(streams)
    tokens = {os.environ.get(name, "") for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN", "NODE_AUTH_TOKEN", "NPM_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN")}
    for token in sorted(tokens - {""}, key=len, reverse=True):
        details = details.replace(token, "[REDACTED]")
    details = "".join(character if character.isprintable() or character in "\n\t"
                      else ascii(character)[1:-1] for character in details)
    # Captured output must not become GitHub workflow commands.
    details = re.sub(r":{2,}", lambda match: r"\:" * len(match[0]), details).replace("##[", r"##\[")
    if len(details) > MAX_VERIFIER_DIAGNOSTIC:
        marker = "\n[output truncated]"
        details = details[:MAX_VERIFIER_DIAGNOSTIC - len(marker)] + marker
    fail(f"{command} {reason}" + (f"\n{details}" if details else ""))


def gh_json(*args, input=None, timeout=120):
    try:
        return json.loads(run("gh", "api", "--hostname", "github.com", *args, input=input, timeout=timeout))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        fail("GitHub API operation failed")


@contextmanager
def request_deadline(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("release request deadline expired")
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    previous_handler = signal.getsignal(signal.SIGALRM)
    if previous_timer != (0.0, 0.0):
        fail("another real-time timer is active")

    def expired(signum, frame):
        raise TimeoutError("release request deadline expired")

    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
        if time.monotonic() >= deadline:
            raise TimeoutError("release request deadline expired")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def read_url(url, limit, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReadUnavailable(f"registry GET {url}: verification deadline expired")
    try:
        with request_deadline(deadline):
            with OPENER.open(url, timeout=min(30, remaining)) as response:
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) > limit):
                    fail("registry response exceeds the size limit")
                data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        message = f"registry GET {url}: HTTP {status}"
        if status in {404, 408, 429, 500, 502, 503, 504}:
            raise ReadUnavailable(message) from None
        fail(message)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            fail(f"registry GET {url}: TLS certificate verification failed")
        raise ReadUnavailable(f"registry GET {url}: {type(error.reason).__name__}") from None
    except ssl.SSLCertVerificationError:
        fail(f"registry GET {url}: TLS certificate verification failed")
    except (OSError, http.client.IncompleteRead) as error:
        raise ReadUnavailable(f"registry GET {url}: {type(error).__name__}") from None
    if len(data) > limit:
        fail("registry response exceeds the size limit")
    if length is not None and len(data) != int(length):
        raise ReadUnavailable(f"registry GET {url}: response is truncated")
    return data


def output(**values):
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    try:
        with open(destination, "a", encoding="utf-8") as stream:
            for key, value in values.items():
                if not re.fullmatch(r"[a-z][a-z0-9-]*", key) or "\n" in value or "\r" in value:
                    fail("invalid action output")
                stream.write(f"{key}={value}\n")
    except OSError:
        fail("unable to write action output")


def under(root, value, label):
    path = pathlib.Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        fail(f"{label} is outside the trusted checkout")
    return resolved


def read_limited(path, limit, label):
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        fail(f"{label} is invalid")
    if len(data) > limit:
        fail(f"{label} exceeds the size limit")
    return data


def environment_identity():
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    ref = os.environ.get("GITHUB_REF", "")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if (not REPOSITORY.fullmatch(repository) or not SHA.fullmatch(sha) or
            os.environ.get("GITHUB_SERVER_URL") != "https://github.com" or
            os.environ.get("GITHUB_REF_TYPE") != "tag" or os.environ.get("GITHUB_EVENT_NAME") != "push"):
        fail("untrusted GitHub release context")
    tag = ref.removeprefix("refs/tags/")
    if ref != f"refs/tags/{tag}" or not tag.startswith("v") or not VERSION.fullmatch(tag[1:]):
        fail("release tag is invalid")
    prefix = f"{repository}/.github/workflows/"
    if not workflow_ref.startswith(prefix) or "@" not in workflow_ref[len(prefix):]:
        fail("caller workflow identity is invalid")
    signer, workflow_revision = workflow_ref.split("@", 1)
    filename = signer[len(prefix):]
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml", filename) or
            workflow_revision != ref):
        fail("caller workflow identity is invalid")
    return repository, sha, ref, tag, signer


def raw_size(field):
    if field[0] & 0x80:
        fail("release archive uses an unsupported size encoding")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if value and not re.fullmatch(rb"[0-7]+", value):
        fail("release archive has an invalid size")
    return int(value or b"0", 8)


def copy_raw_tar(archive, raw, *, allowed_types=None):
    total = records = 0
    long_name = False
    try:
        with gzip.open(archive, "rb") as source:
            while True:
                header = source.read(512)
                if len(header) != 512:
                    fail("release archive is truncated")
                raw.write(header)
                if header == b"\0" * 512:
                    if long_name:
                        fail("release archive has an orphaned long name")
                    trailer = source.read(512)
                    if trailer != b"\0" * 512:
                        fail("release archive has an invalid trailer")
                    raw.write(trailer)
                    total += 1024
                    if total > MAX_UNPACKED:
                        fail("release archive expands beyond the size limit")
                    while True:
                        padding = source.read(1024 * 1024)
                        if not padding:
                            return
                        total += len(padding)
                        if total > MAX_UNPACKED or any(padding):
                            fail("release archive has an invalid trailer")
                records += 1
                if records > MAX_MEMBERS:
                    fail("release archive has too many records")
                size = raw_size(header[124:136])
                kind = header[156:157]
                if allowed_types is not None:
                    if kind not in allowed_types or (long_name and kind == b"L"):
                        fail("release archive uses unsupported metadata records")
                    if kind == b"L" and size > 4096:
                        fail("release archive long name exceeds the size limit")
                long_name = kind == b"L"
                if kind in (b"x", b"g", b"X", b"L", b"K") and size > MAX_METADATA:
                    fail("release archive metadata exceeds the size limit")
                padded = (size + 511) // 512 * 512
                total += 512 + padded
                if total > MAX_UNPACKED:
                    fail("release archive expands beyond the size limit")
                remaining = padded
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        fail("release archive is truncated")
                    raw.write(chunk)
                    remaining -= len(chunk)
    except (gzip.BadGzipFile, OSError):
        fail("release archive is invalid")


def hash_file(path):
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    fail("release artifact exceeds the size limit")
                digest.update(chunk)
    except OSError:
        fail("release artifact is invalid")
    return digest.hexdigest()


def snapshot_artifact(files, name):
    supplied = pathlib.Path(files)
    if supplied.is_symlink():
        fail("release artifact directory is invalid")
    try:
        directory = supplied.resolve(strict=True)
        inventory = {path.name for path in directory.iterdir()}
    except OSError:
        fail("release artifact directory is invalid")
    archive = directory / name
    if not directory.is_dir() or inventory != {name}:
        fail("release artifact inventory is invalid")
    try:
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
    except OSError:
        fail("release artifact is invalid")
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_ARCHIVE:
        os.close(descriptor)
        fail("release artifact exceeds the size limit")
    runner_temp = pathlib.Path(os.environ.get("RUNNER_TEMP", ""))
    if not runner_temp.is_absolute() or not runner_temp.is_dir():
        os.close(descriptor)
        fail("runner temporary directory is invalid")
    private = pathlib.Path(tempfile.mkdtemp(prefix="waxseal-", dir=runner_temp))
    os.chmod(private, 0o700)
    snapshot = private / name
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(descriptor, "rb") as source, snapshot.open("xb") as destination:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    fail("release artifact exceeds the size limit")
                digest.update(chunk)
                destination.write(chunk)
        os.chmod(snapshot, 0o600)
    except OSError:
        fail("release artifact is invalid")
    return private, snapshot, digest.hexdigest()


def locate_artifact(name):
    repository, sha, _, _, _ = environment_identity()
    run = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[1-9][0-9]*", run) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name):
        fail("release artifact identity is invalid")
    result = gh_json(f"repos/{repository}/actions/runs/{run}/artifacts?name={urllib.parse.quote(name)}&per_page=100")
    if not isinstance(result, dict) or result.get("total_count") != 1:
        fail("release artifact selection is ambiguous")
    entries = result.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        fail("release artifact selection is invalid")
    artifact = entries[0]
    identifier, size, workflow = artifact.get("id"), artifact.get("size_in_bytes"), artifact.get("workflow_run")
    if (type(identifier) is not int or identifier < 1 or artifact.get("name") != name
            or type(size) is not int or not 0 < size <= MAX_ARTIFACT_ZIP or artifact.get("expired") is not False
            or not isinstance(workflow, dict) or workflow.get("id") != int(run) or workflow.get("head_sha") != sha):
        fail("release artifact size or source run differs")
    output(**{"artifact-id": str(identifier)})


def snapshot_zipped_artifact(files, name):
    supplied = pathlib.Path(files)
    try:
        entries = list(supplied.iterdir())
    except OSError:
        fail("release artifact directory is invalid")
    if supplied.is_symlink() or len(entries) != 1:
        fail("release artifact inventory is invalid")
    runner_temp = pathlib.Path(os.environ.get("RUNNER_TEMP", ""))
    if not runner_temp.is_absolute() or not runner_temp.is_dir():
        fail("runner temporary directory is invalid")
    try:
        descriptor = os.open(entries[0], os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        fail("release artifact ZIP is invalid")
    try:
        with os.fdopen(descriptor, "rb") as zipped:
            details = os.fstat(zipped.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_ARTIFACT_ZIP:
                fail("release artifact ZIP exceeds the size limit")
            with zipfile.ZipFile(zipped) as archive:
                members = archive.infolist()
                if len(members) != 1:
                    fail("release artifact ZIP inventory is invalid")
                member = members[0]
                mode = stat.S_IFMT(member.external_attr >> 16)
                if (member.filename != name or member.is_dir() or member.flag_bits & 65
                        or mode not in (0, stat.S_IFREG) or member.file_size > MAX_ARCHIVE
                        or member.compress_size > MAX_ARTIFACT_ZIP
                        or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    fail("release artifact ZIP entry is invalid or oversized")
                private = pathlib.Path(tempfile.mkdtemp(prefix="waxseal-", dir=runner_temp))
                os.chmod(private, 0o700)
                snapshot = private / name
                digest, total = hashlib.sha256(), 0
                with archive.open(member) as source, snapshot.open("xb") as destination:
                    while True:
                        chunk = source.read(min(1024 * 1024, MAX_ARCHIVE - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_ARCHIVE:
                            fail("release artifact expands beyond the size limit")
                        digest.update(chunk)
                        destination.write(chunk)
                if total != member.file_size:
                    fail("release artifact ZIP entry is incomplete")
                os.chmod(snapshot, 0o600)
                return private, snapshot, digest.hexdigest()
    except (OSError, EOFError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        fail("release artifact ZIP is invalid")


def require_tag(repository, tag, sha):
    ref = gh_json(f"repos/{repository}/git/ref/tags/{tag}")
    tag_sha = None
    for _ in range(16):
        target = ref.get("object") if isinstance(ref, dict) else None
        if not isinstance(target, dict):
            break
        kind, object_sha = target.get("type"), target.get("sha")
        if not isinstance(object_sha, str) or not SHA.fullmatch(object_sha):
            break
        if tag_sha is None:
            # Annotated tags are attested by their tag-object digest.
            tag_sha = object_sha
        if kind == "commit":
            if object_sha == sha:
                return tag_sha
            break
        if kind != "tag":
            break
        ref = gh_json(f"repos/{repository}/git/tags/{object_sha}")
    fail("tag does not resolve to the approved commit")


def verify_attestation(identity):
    try:
        run("gh", "attestation", "verify", str(identity["archive"]), "--repo", identity["repository"],
            "--signer-workflow", identity["signer"], "--source-ref", f"refs/tags/{identity['tag']}",
            "--source-digest", identity["sha"], "--signer-digest", identity["sha"], "--deny-self-hosted-runners")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        fail_verifier(error)


def wait_for_release_attestation(identity, tag_sha):
    deadline = time.monotonic() + RELEASE_ATTESTATION_TIMEOUT
    expired = ("Package and immutable GitHub release are already published; "
               f"release attestation was not visible within {RELEASE_ATTESTATION_TIMEOUT} seconds. "
               f"Verify manually: gh release verify {identity['tag']} --repo {identity['repository']}")
    # The verifier hides HTTP lookup errors behind a missing-attestation message.
    endpoint = (f"repos/{identity['repository']}/attestations/sha1:{tag_sha}"
                "?per_page=100&predicate_type=release")
    print("Package and immutable GitHub release are published; checking release attestation.",
          file=sys.stderr, flush=True)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(expired)
        pages = gh_json("--paginate", "--slurp", endpoint, timeout=min(30, remaining))
        if not isinstance(pages, list) or not pages:
            fail("GitHub release attestation response is invalid")
        attestations = []
        for page in pages:
            if (not isinstance(page, dict) or not isinstance(page.get("attestations"), list)
                    or any(not isinstance(entry, dict) or not isinstance(entry.get("initiator"), str)
                           for entry in page["attestations"])):
                fail("GitHub release attestation response is invalid")
            attestations.extend(entry for entry in page["attestations"] if entry["initiator"] == "github")
        if any(not isinstance(entry.get("bundle"), dict)
               and not (isinstance(entry.get("bundle_url"), str) and entry["bundle_url"])
               for entry in attestations):
            fail("GitHub release attestation response is invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(expired)
        if attestations:
            return
        delay = min(5, remaining)
        print(f"GitHub release attestation is not available; checking again in {delay:g}s",
              file=sys.stderr, flush=True)
        time.sleep(delay)


def verify_release(identity, tag_sha):
    wait_for_release_attestation(identity, tag_sha)
    try:
        run("gh", "release", "verify", identity["tag"], "--repo", f"https://github.com/{identity['repository']}")
        run("gh", "release", "verify-asset", identity["tag"], str(identity["archive"]),
            "--repo", f"https://github.com/{identity['repository']}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        fail_verifier(error)
