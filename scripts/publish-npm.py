#!/usr/bin/env python3
"""Validate and publish one source-bound npm release archive."""

import base64
import gzip
import hashlib
import http.client
import json
import os
import pathlib
import re
import shutil
import stat
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "https://registry.npmjs.org"
MAX_METADATA = 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_UNPACKED = 512 * 1024 * 1024
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
MAX_CHANGELOG = 4 * 1024 * 1024
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SHA = re.compile(r"[0-9a-f]{40}")


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


class NpmReadUnavailable(Exception):
    pass


def fail(message):
    raise SystemExit(message)


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


def gh_json(*args, input=None):
    try:
        return json.loads(run("gh", "api", "--hostname", "github.com", *args, input=input))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        fail("GitHub API operation failed")


def read_url(url, limit, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NpmReadUnavailable(f"npm GET {url}: verification deadline expired")
    try:
        with OPENER.open(url, timeout=min(30, remaining)) as response:
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > limit):
                fail("npm response exceeds the size limit")
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        message = f"npm GET {url}: HTTP {status}"
        if status in {404, 408, 429, 500, 502, 503, 504}:
            raise NpmReadUnavailable(message) from None
        fail(message)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            fail(f"npm GET {url}: TLS certificate verification failed")
        raise NpmReadUnavailable(f"npm GET {url}: {type(error.reason).__name__}") from None
    except ssl.SSLCertVerificationError:
        fail(f"npm GET {url}: TLS certificate verification failed")
    except (OSError, http.client.IncompleteRead) as error:
        raise NpmReadUnavailable(f"npm GET {url}: {type(error).__name__}") from None
    if len(data) > limit:
        fail("npm response exceeds the size limit")
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


def package_directory(root, value):
    candidate = pathlib.PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts:
        fail("package directory is invalid")
    directory = under(root, pathlib.Path(*candidate.parts), "package directory")
    if not directory.is_dir():
        fail("package directory is invalid")
    return directory


def read_limited(path, limit, label):
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        fail(f"{label} is invalid")
    if len(data) > limit:
        fail(f"{label} exceeds the size limit")
    return data


def load_json(path, label):
    try:
        return json.loads(read_limited(path, MAX_METADATA, label))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is invalid")


def canonical_repository(value):
    url = value.get("url") if isinstance(value, dict) else value
    if not isinstance(url, str):
        return None
    if url.startswith("git+"):
        url = url[4:]
    match = re.fullmatch(r"(?:https://github\.com/|ssh://git@github\.com/)([^/\s]+)/([^/\s]+?)(?:\.git)?", url)
    if match:
        return f"{match[1]}/{match[2]}"
    match = re.fullmatch(r"git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?", url)
    if match:
        return f"{match[1]}/{match[2]}"
    return None


def validate_publish_config(config):
    if config is None:
        return
    if not isinstance(config, dict):
        fail("npm publish configuration is not allowed")
    allowed = {"access", "tag", "registry", "provenance"}
    if set(config) - allowed:
        fail("npm publish configuration is not allowed")
    if "access" in config and config["access"] != "public":
        fail("npm publish configuration is not allowed")
    if "tag" in config and config["tag"] != "latest":
        fail("npm publish configuration is not allowed")
    if "registry" in config and config["registry"] != REGISTRY:
        fail("npm publish configuration is not allowed")
    if "provenance" in config and config["provenance"] is not True:
        fail("npm publish configuration is not allowed")


def archive_name(package, version):
    return f"{package[1:].replace('/', '-') if package.startswith('@') else package}-{version}.tgz"


def registry_metadata_url(package, version):
    return f"{REGISTRY}/{urllib.parse.quote(package, safe='@').replace('/', '%2F')}/{version}"


def registry_tarball_url(package, version):
    leaf = package.rsplit("/", 1)[-1]
    return f"{REGISTRY}/{package}/-/{leaf}-{version}.tgz"


CHANGELOG_HEADING = re.compile(r"^## \[?v?([0-9]+\.[0-9]+\.[0-9]+)\]?(?:\(|\s|$)")
FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


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


def trusted_identity(source, package_dir):
    repository, sha, ref, tag, signer = environment_identity()
    try:
        head = run("git", "-C", str(source), "rev-parse", "HEAD").strip()
        tagged = run("git", "-C", str(source), "rev-parse", f"{ref}^{{commit}}").strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        fail("trusted checkout cannot verify the release tag")
    if head != sha or tagged != sha:
        fail("trusted checkout does not match the release commit")
    manifest_path = under(source, package_dir / "package.json", "package manifest")
    if not manifest_path.is_file():
        fail("package manifest is invalid")
    manifest = load_json(manifest_path, "package manifest")
    if not isinstance(manifest, dict):
        fail("package manifest is invalid")
    package = manifest.get("name")
    version = manifest.get("version")
    if not isinstance(package, str) or not PACKAGE.fullmatch(package) or not isinstance(version, str) or not VERSION.fullmatch(version):
        fail("package manifest identity is invalid")
    if tag != f"v{version}" or canonical_repository(manifest.get("repository")) != repository:
        fail("package manifest does not match trusted release identity")
    validate_publish_config(manifest.get("publishConfig"))
    changelog = under(source, package_dir / "CHANGELOG.md", "changelog")
    if not changelog.is_file():
        fail("changelog is invalid")
    try:
        text = read_limited(changelog, MAX_CHANGELOG, "changelog").decode("utf-8")
    except UnicodeDecodeError:
        fail("changelog is invalid")
    notes = release_notes(text, version)
    return {"package": package, "version": version, "tag": tag, "repository": repository,
            "sha": sha, "signer": signer, "notes": notes, "manifest": manifest}


def raw_size(field):
    if field[0] & 0x80:
        fail("npm tarball uses an unsupported size encoding")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if value and not re.fullmatch(rb"[0-7]+", value):
        fail("npm tarball has an invalid size")
    return int(value or b"0", 8)


def copy_raw_tar(archive, raw):
    total = 0
    records = 0
    try:
        with gzip.open(archive, "rb") as source:
            while True:
                header = source.read(512)
                if len(header) != 512:
                    fail("npm tarball is truncated")
                raw.write(header)
                if header == b"\0" * 512:
                    trailer = source.read(512)
                    if trailer != b"\0" * 512:
                        fail("npm tarball has an invalid trailer")
                    raw.write(trailer)
                    total += 1024
                    while True:
                        padding = source.read(1024 * 1024)
                        if not padding:
                            return
                        total += len(padding)
                        if total > MAX_UNPACKED or any(padding):
                            fail("npm tarball has an invalid trailer")
                records += 1
                if records > MAX_MEMBERS:
                    fail("npm tarball has too many records")
                size = raw_size(header[124:136])
                kind = header[156:157]
                if kind in (b"x", b"g", b"X", b"L", b"K") and size > MAX_METADATA:
                    fail("npm tarball metadata exceeds the size limit")
                padded = (size + 511) // 512 * 512
                total += 512 + padded
                if total > MAX_UNPACKED:
                    fail("npm tarball expands beyond the size limit")
                remaining = padded
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        fail("npm tarball is truncated")
                    raw.write(chunk)
                    remaining -= len(chunk)
    except (gzip.BadGzipFile, OSError):
        fail("npm tarball is invalid")


def inspect_archive(archive, identity):
    try:
        with tempfile.TemporaryFile() as raw:
            copy_raw_tar(archive, raw)
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:") as tar:
                package_json = None
                unpacked = 0
                names = set()
                for member in tar:
                    name = member.name
                    if (len(names) >= MAX_MEMBERS or name in names or not name.startswith("package/") or
                            "\\" in name or str(pathlib.PurePosixPath(name)) != name.rstrip("/") or
                            ".." in pathlib.PurePosixPath(name).parts):
                        fail("npm tarball member inventory is invalid")
                    names.add(name)
                    if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                        fail("npm tarball contains a non-regular member")
                    unpacked += member.size
                    if unpacked > MAX_UNPACKED:
                        fail("npm tarball expands beyond the size limit")
                    if name == "package/package.json":
                        if package_json is not None or member.size > MAX_METADATA:
                            fail("npm tarball package manifest is invalid")
                        extracted = tar.extractfile(member)
                        if extracted is None:
                            fail("npm tarball package manifest is invalid")
                        package_json = json.loads(extracted.read(MAX_METADATA + 1))
    except (tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, OSError):
        fail("npm tarball is invalid")
    if not isinstance(package_json, dict) or package_json.get("name") != identity["package"] or package_json.get("version") != identity["version"]:
        fail("npm tarball package identity is invalid")
    if canonical_repository(package_json.get("repository")) != identity["repository"]:
        fail("npm tarball repository is invalid")
    validate_publish_config(package_json.get("publishConfig"))


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


def validate_snapshot(source, package_dir, files, expected_sha256=None):
    identity = trusted_identity(source, package_dir)
    name = archive_name(identity["package"], identity["version"])
    directory = pathlib.Path(files)
    try:
        directory = directory.resolve(strict=True)
        runner_temp = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        directory.relative_to(runner_temp)
        inventory = {path.name for path in directory.iterdir()}
    except (KeyError, OSError, ValueError):
        fail("release snapshot directory is invalid")
    archive = directory / name
    if (not directory.is_dir() or not directory.name.startswith("waxseal-") or
            stat.S_IMODE(directory.stat().st_mode) != 0o700 or inventory != {name} or
            archive.is_symlink() or not stat.S_ISREG(archive.lstat().st_mode)):
        fail("release snapshot inventory is invalid")
    sha256 = hash_file(archive)
    if expected_sha256 is not None and sha256 != expected_sha256:
        fail("release snapshot digest does not match validation")
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def validate(source, package_dir, files):
    identity = trusted_identity(source, package_dir)
    name = archive_name(identity["package"], identity["version"])
    directory, archive, sha256 = snapshot_artifact(files, name)
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def require_tag(repository, tag, sha):
    ref = gh_json(f"repos/{repository}/git/ref/tags/{tag}")
    for _ in range(16):
        target = ref.get("object")
        if not isinstance(target, dict):
            break
        kind, object_sha = target.get("type"), target.get("sha")
        if kind == "commit":
            if object_sha == sha:
                return
            break
        if kind != "tag" or not isinstance(object_sha, str):
            break
        ref = gh_json(f"repos/{repository}/git/tags/{object_sha}")
    fail("tag does not resolve to the approved commit")


def node_runtime():
    version = os.environ.get("WAXSEAL_NODE_VERSION", "").removeprefix("v")
    cache = os.environ.get("RUNNER_TOOL_CACHE", "")
    arch = os.environ.get("RUNNER_ARCH", "").lower()
    if not re.fullmatch(r"26\.[0-9]+\.[0-9]+", version) or not pathlib.PurePath(cache).is_absolute() or not arch:
        fail("trusted Node runtime is invalid")
    prefix = pathlib.Path(cache) / "node" / version / arch
    node = prefix / "bin" / "node"
    npm = prefix / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not node.is_file() or not npm.is_file():
        fail("trusted Node runtime is unavailable")
    return node, npm


def npm_env(home):
    userconfig = home / "npmrc"
    globalconfig = home / "npm-globalrc"
    userconfig.write_text("")
    globalconfig.write_text("")
    allowed = {"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GITHUB_ACTIONS",
               "GITHUB_ACTOR", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_RUN_ATTEMPT",
               "GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
               "GITHUB_SERVER_URL", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "RUNNER_ENVIRONMENT"}
    env = {name: value for name, value in os.environ.items() if name in allowed}
    env.update({"HOME": str(home), "PATH": "/usr/local/bin:/usr/bin:/bin", "NPM_CONFIG_USERCONFIG": str(userconfig),
                "NPM_CONFIG_GLOBALCONFIG": str(globalconfig), "NPM_CONFIG_REGISTRY": REGISTRY})
    return env


def require_unpublished(package, version):
    try:
        with OPENER.open(registry_metadata_url(package, version), timeout=30):
            pass
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
    except (urllib.error.URLError, OSError):
        pass
    fail("npm publication status could not be confirmed")


def verify_npm(package, version, sha256, deadline):
    try:
        metadata = json.loads(read_url(registry_metadata_url(package, version), MAX_METADATA, deadline))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("npm metadata verification failed")
    tarball = registry_tarball_url(package, version)
    if metadata.get("name") != package or metadata.get("version") != version:
        fail("npm metadata does not match the approved package")
    dist = metadata.get("dist")
    if not isinstance(dist, dict) or dist.get("tarball") != tarball:
        fail("npm tarball URL is not canonical")
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        fail("npm integrity is invalid")
    try:
        expected = base64.b64decode(integrity[7:], validate=True)
    except ValueError:
        fail("npm integrity is invalid")
    data = read_url(tarball, MAX_ARCHIVE, deadline)
    if hashlib.sha512(data).digest() != expected or hashlib.sha256(data).hexdigest() != sha256:
        fail("npm archive digest does not match the approved asset")


def wait_for_npm(package, version, sha256):
    deadline = time.monotonic() + 300
    while True:
        try:
            verify_npm(package, version, sha256, deadline)
            return
        except NpmReadUnavailable as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"npm publication verification timed out: {error}")
            delay = min(5, remaining)
            print(f"{error}; retrying verification in {delay:g}s", file=sys.stderr, flush=True)
            time.sleep(delay)
            if time.monotonic() >= deadline:
                fail(f"npm publication verification timed out: {error}")


def exact_draft(release, release_id, identity, size, digest, draft):
    assets = release.get("assets")
    return (release.get("id") == release_id and release.get("name") == identity["tag"] and
            release.get("tag_name") == identity["tag"] and release.get("target_commitish") == identity["sha"] and
            release.get("body") == identity["notes"] and release.get("prerelease") is False and
            release.get("draft") is draft and isinstance(assets, list) and len(assets) == 1 and
            assets[0].get("name") == identity["archive-name"] and assets[0].get("size") == size and
            assets[0].get("digest") == digest)


def verify_attestation(identity):
    env = os.environ.copy()
    env["GH_HOST"] = "github.com"
    try:
        run("gh", "attestation", "verify", str(identity["archive"]), "--repo", identity["repository"],
            "--signer-workflow", identity["signer"], "--source-ref", f"refs/tags/{identity['tag']}",
            "--source-digest", identity["sha"], "--signer-digest", identity["sha"], "--deny-self-hosted-runners",
            env=env)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        fail("build attestation verification failed")


def publish(identity):
    node, npm = node_runtime()
    verify_attestation(identity)
    archive = identity["archive"]
    size = archive.stat().st_size
    digest = f"sha256:{identity['archive-sha256']}"
    require_tag(identity["repository"], identity["tag"], identity["sha"])
    releases = gh_json("--paginate", "--slurp", f"repos/{identity['repository']}/releases?per_page=100")
    if (not isinstance(releases, list) or any(release.get("tag_name") == identity["tag"]
            for page in releases if isinstance(page, list) for release in page if isinstance(release, dict))):
        fail("a release already exists for this tag")
    require_unpublished(identity["package"], identity["version"])
    with tempfile.TemporaryDirectory() as temporary:
        temporary = pathlib.Path(temporary)
        env = npm_env(temporary)
        payload = json.dumps({"tag_name": identity["tag"], "target_commitish": identity["sha"],
                              "name": identity["tag"], "body": identity["notes"], "draft": True,
                              "prerelease": False})
        release = gh_json("--method", "POST", f"repos/{identity['repository']}/releases", "--input", "-", input=payload)
        release_id = release.get("id")
        if (not isinstance(release_id, int) or release.get("draft") is not True or release.get("prerelease") is not False or
                release.get("name") != identity["tag"] or release.get("tag_name") != identity["tag"] or
                release.get("target_commitish") != identity["sha"] or release.get("body") != identity["notes"] or release.get("assets") != []):
            fail("GitHub did not create the expected draft")
        run("gh", "api", "--method", "POST", f"https://uploads.github.com/repos/{identity['repository']}/releases/{release_id}/assets?name={identity['archive-name']}",
            "--header", "Content-Type: application/octet-stream", "--input", str(archive))
        require_tag(identity["repository"], identity["tag"], identity["sha"])
        release = gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, True):
            fail("GitHub draft changed unexpectedly")
        copied = temporary / identity["archive-name"]
        shutil.copyfile(archive, copied)
        try:
            run(str(node), str(npm), "publish", str(copied), "--ignore-scripts", "--registry", REGISTRY, "--access", "public",
                cwd=temporary, env=env, timeout=600)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            fail("npm publication failed")
        wait_for_npm(identity["package"], identity["version"], identity["archive-sha256"])
        require_tag(identity["repository"], identity["tag"], identity["sha"])
        release = gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, True):
            fail("GitHub draft changed before publication")
        gh_json("--method", "PATCH", f"repos/{identity['repository']}/releases/{release_id}", "-F", "draft=false")
        release = gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, False) or release.get("immutable") is not True:
            fail("GitHub release publication verification failed")
        try:
            run("gh", "release", "verify", identity["tag"], "--repo", f"https://github.com/{identity['repository']}")
            run("gh", "release", "verify-asset", identity["tag"], str(archive), "--repo", f"https://github.com/{identity['repository']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            fail("GitHub release verification failed")
    url = release.get("html_url")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{identity['repository']}/releases/"):
        fail("GitHub release URL is invalid")
    output(**{"release-url": url})


def check_npm():
    node, npm = node_runtime()
    with tempfile.TemporaryDirectory() as temporary:
        try:
            version = run(str(node), str(npm), "--version", env=npm_env(pathlib.Path(temporary))).strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            fail("trusted npm runtime is unavailable")
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", version)
    if not match or tuple(map(int, match.groups())) < (11, 5, 1):
        fail("npm OIDC support is unavailable")


def arguments(argv):
    commands = {"identity", "validate", "verify-attestation", "publish", "check-npm"}
    if len(argv) < 2 or argv[1] not in commands:
        fail("invalid command")
    command = argv[1]
    if command == "check-npm":
        if len(argv) != 2:
            fail("invalid command arguments")
        return command, {}
    values = {}
    items = argv[2:]
    if len(items) % 2:
        fail("invalid command arguments")
    for key, value in zip(items[::2], items[1::2]):
        if key not in {"--source", "--package-directory", "--files", "--expected-sha256"} or key in values:
            fail("invalid command arguments")
        values[key] = value
    required = {"--source", "--package-directory"}
    if command == "validate":
        required.add("--files")
    elif command != "identity":
        required.update({"--files", "--expected-sha256"})
    if set(values) != required:
        fail("invalid command arguments")
    return command, values


def main(argv):
    command, values = arguments(argv)
    if command == "check-npm":
        check_npm()
        return
    try:
        source = pathlib.Path(values["--source"]).resolve(strict=True)
    except OSError:
        fail("trusted checkout is invalid")
    if not source.is_dir():
        fail("trusted checkout is invalid")
    directory = package_directory(source, values["--package-directory"])
    if command == "identity":
        identity = trusted_identity(source, directory)
        emitted = {key: identity[key] for key in ("package", "version", "tag", "repository", "sha")}
        emitted["archive-name"] = archive_name(identity["package"], identity["version"])
        emitted["signer-workflow"] = identity["signer"]
        output(**emitted)
        print(json.dumps(emitted, sort_keys=True))
        return
    if command == "validate":
        identity = validate(source, directory, values["--files"])
        output(**{"archive-sha256": identity["archive-sha256"], "archive-name": identity["archive-name"],
                  "archive-path": str(identity["archive"]), "files-directory": identity["files-directory"]})
        return
    expected = values["--expected-sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("expected archive digest is invalid")
    identity = validate_snapshot(source, directory, values["--files"], expected)
    if command == "verify-attestation":
        verify_attestation(identity)
        return
    publish(identity)


if __name__ == "__main__":
    main(sys.argv)
