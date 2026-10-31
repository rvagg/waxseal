#!/usr/bin/env python3
"""Check an npm tarball, publish it to npm and create a GitHub release."""

import importlib.util
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse

common_spec = importlib.util.spec_from_file_location(
    "release_common", pathlib.Path(__file__).with_name("release_common.py"))
release_common = importlib.util.module_from_spec(common_spec)
common_spec.loader.exec_module(release_common)

REGISTRY = "https://registry.npmjs.org"
PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")


def load_json(path, label):
    try:
        return json.loads(release_common.read_limited(path, release_common.MAX_METADATA, label))
    except (UnicodeDecodeError, json.JSONDecodeError):
        release_common.fail(f"{label} is invalid")


def validate_publish_config(config):
    if config is None:
        return
    if not isinstance(config, dict):
        release_common.fail("npm publish configuration is not allowed")
    allowed = {"access", "tag", "registry", "provenance"}
    if set(config) - allowed:
        release_common.fail("npm publish configuration is not allowed")
    if "access" in config and config["access"] != "public":
        release_common.fail("npm publish configuration is not allowed")
    if "tag" in config and config["tag"] != "latest":
        release_common.fail("npm publish configuration is not allowed")
    if "registry" in config and config["registry"] != REGISTRY:
        release_common.fail("npm publish configuration is not allowed")
    if "provenance" in config and config["provenance"] is not True:
        release_common.fail("npm publish configuration is not allowed")


def archive_name(package, version):
    return f"{package[1:].replace('/', '-') if package.startswith('@') else package}-{version}.tgz"


def registry_metadata_url(package, version):
    return f"{REGISTRY}/{urllib.parse.quote(package, safe='@').replace('/', '%2F')}/{version}"


def registry_tarball_url(package, version):
    leaf = package.rsplit("/", 1)[-1]
    return f"{REGISTRY}/{package}/-/{leaf}-{version}.tgz"


def trusted_identity(source, package_dir):
    repository, sha, ref, tag, signer = release_common.environment_identity()
    try:
        head = release_common.run("git", "-C", str(source), "rev-parse", "HEAD").strip()
        tagged = release_common.run("git", "-C", str(source), "rev-parse", f"{ref}^{{commit}}").strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        release_common.fail("trusted checkout cannot verify the release tag")
    if head != sha or tagged != sha:
        release_common.fail("trusted checkout does not match the release commit")
    manifest_path = release_common.under(source, package_dir / "package.json", "package manifest")
    if not manifest_path.is_file():
        release_common.fail("package manifest is invalid")
    manifest = load_json(manifest_path, "package manifest")
    if not isinstance(manifest, dict):
        release_common.fail("package manifest is invalid")
    package = manifest.get("name")
    version = manifest.get("version")
    if not isinstance(package, str) or not PACKAGE.fullmatch(package) or not isinstance(version, str) or not release_common.VERSION.fullmatch(version):
        release_common.fail("package manifest identity is invalid")
    if tag != f"v{version}" or release_common.canonical_repository(manifest.get("repository")) != repository:
        release_common.fail("package manifest does not match trusted release identity")
    validate_publish_config(manifest.get("publishConfig"))
    changelog = release_common.under(source, package_dir / "CHANGELOG.md", "changelog")
    if not changelog.is_file():
        release_common.fail("changelog is invalid")
    try:
        text = release_common.read_limited(changelog, release_common.MAX_CHANGELOG, "changelog").decode("utf-8")
    except UnicodeDecodeError:
        release_common.fail("changelog is invalid")
    notes = release_common.release_notes(text, version)
    return {"package": package, "version": version, "tag": tag, "repository": repository,
            "sha": sha, "signer": signer, "notes": notes, "manifest": manifest}


def inspect_archive(archive, identity):
    try:
        with tempfile.TemporaryFile() as raw:
            release_common.copy_raw_tar(archive, raw)
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:") as tar:
                package_json = None
                unpacked = 0
                names = set()
                for member in tar:
                    name = member.name
                    if (len(names) >= release_common.MAX_MEMBERS or name in names or not name.startswith("package/") or
                            "\\" in name or str(pathlib.PurePosixPath(name)) != name.rstrip("/") or
                            ".." in pathlib.PurePosixPath(name).parts):
                        release_common.fail("npm tarball member inventory is invalid")
                    names.add(name)
                    if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                        release_common.fail("npm tarball contains a non-regular member")
                    unpacked += member.size
                    if unpacked > release_common.MAX_UNPACKED:
                        release_common.fail("npm tarball expands beyond the size limit")
                    if name == "package/package.json":
                        if package_json is not None or member.size > release_common.MAX_METADATA:
                            release_common.fail("npm tarball package manifest is invalid")
                        extracted = tar.extractfile(member)
                        if extracted is None:
                            release_common.fail("npm tarball package manifest is invalid")
                        package_json = json.loads(extracted.read(release_common.MAX_METADATA + 1))
    except (tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, OSError):
        release_common.fail("npm tarball is invalid")
    if not isinstance(package_json, dict) or package_json.get("name") != identity["package"] or package_json.get("version") != identity["version"]:
        release_common.fail("npm tarball package identity is invalid")
    if release_common.canonical_repository(package_json.get("repository")) != identity["repository"]:
        release_common.fail("npm tarball repository is invalid")
    validate_publish_config(package_json.get("publishConfig"))


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
        release_common.fail("release snapshot directory is invalid")
    archive = directory / name
    if (not directory.is_dir() or not directory.name.startswith("waxseal-") or
            stat.S_IMODE(directory.stat().st_mode) != 0o700 or inventory != {name} or
            archive.is_symlink() or not stat.S_ISREG(archive.lstat().st_mode)):
        release_common.fail("release snapshot inventory is invalid")
    sha256 = release_common.hash_file(archive)
    if expected_sha256 is not None and sha256 != expected_sha256:
        release_common.fail("release snapshot digest does not match validation")
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def validate(source, package_dir, files):
    identity = trusted_identity(source, package_dir)
    name = archive_name(identity["package"], identity["version"])
    directory, archive, sha256 = release_common.snapshot_artifact(files, name)
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def node_runtime():
    version = os.environ.get("WAXSEAL_NODE_VERSION", "").removeprefix("v")
    cache = os.environ.get("RUNNER_TOOL_CACHE", "")
    arch = os.environ.get("RUNNER_ARCH", "").lower()
    if not re.fullmatch(r"26\.[0-9]+\.[0-9]+", version) or not pathlib.PurePath(cache).is_absolute() or not arch:
        release_common.fail("trusted Node runtime is invalid")
    prefix = pathlib.Path(cache) / "node" / version / arch
    node = prefix / "bin" / "node"
    npm = prefix / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not node.is_file() or not npm.is_file():
        release_common.fail("trusted Node runtime is unavailable")
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
        with release_common.request_deadline(time.monotonic() + 30):
            with release_common.OPENER.open(registry_metadata_url(package, version), timeout=30):
                pass
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
    except (urllib.error.URLError, OSError):
        pass
    release_common.fail("npm publication status could not be confirmed")


def verify_npm(package, version, sha256, deadline):
    try:
        metadata = json.loads(release_common.read_url(registry_metadata_url(package, version), release_common.MAX_METADATA, deadline))
    except (UnicodeDecodeError, json.JSONDecodeError):
        release_common.fail("npm metadata verification failed")
    tarball = registry_tarball_url(package, version)
    if metadata.get("name") != package or metadata.get("version") != version:
        release_common.fail("npm metadata does not match the approved package")
    dist = metadata.get("dist")
    if not isinstance(dist, dict) or dist.get("tarball") != tarball:
        release_common.fail("npm tarball URL is not canonical")
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        release_common.fail("npm integrity is invalid")
    try:
        expected = base64.b64decode(integrity[7:], validate=True)
    except ValueError:
        release_common.fail("npm integrity is invalid")
    data = release_common.read_url(tarball, release_common.MAX_ARCHIVE, deadline)
    if hashlib.sha512(data).digest() != expected or hashlib.sha256(data).hexdigest() != sha256:
        release_common.fail("npm archive digest does not match the approved asset")


def wait_for_npm(package, version, sha256):
    deadline = time.monotonic() + 300
    while True:
        try:
            verify_npm(package, version, sha256, deadline)
            return
        except release_common.ReadUnavailable as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                release_common.fail(f"npm publication verification timed out: {error}")
            delay = min(5, remaining)
            print(f"{error}; retrying verification in {delay:g}s", file=sys.stderr, flush=True)
            time.sleep(delay)
            if time.monotonic() >= deadline:
                release_common.fail(f"npm publication verification timed out: {error}")


def exact_draft(release, release_id, identity, size, digest, draft):
    assets = release.get("assets")
    return (release.get("id") == release_id and release.get("name") == identity["tag"] and
            release.get("tag_name") == identity["tag"] and release.get("target_commitish") == identity["sha"] and
            release.get("body") == identity["notes"] and release.get("prerelease") is False and
            release.get("draft") is draft and isinstance(assets, list) and len(assets) == 1 and
            assets[0].get("name") == identity["archive-name"] and assets[0].get("size") == size and
            assets[0].get("digest") == digest)


def publish(identity):
    node, npm = node_runtime()
    release_common.verify_attestation(identity)
    archive = identity["archive"]
    size = archive.stat().st_size
    digest = f"sha256:{identity['archive-sha256']}"
    release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
    releases = release_common.gh_json("--paginate", "--slurp", f"repos/{identity['repository']}/releases?per_page=100")
    if (not isinstance(releases, list) or any(release.get("tag_name") == identity["tag"]
            for page in releases if isinstance(page, list) for release in page if isinstance(release, dict))):
        release_common.fail("a release already exists for this tag")
    require_unpublished(identity["package"], identity["version"])
    with tempfile.TemporaryDirectory() as temporary:
        temporary = pathlib.Path(temporary)
        env = npm_env(temporary)
        payload = json.dumps({"tag_name": identity["tag"], "target_commitish": identity["sha"],
                              "name": identity["tag"], "body": identity["notes"], "draft": True,
                              "prerelease": False})
        release = release_common.gh_json("--method", "POST", f"repos/{identity['repository']}/releases", "--input", "-", input=payload)
        release_id = release.get("id")
        if (not isinstance(release_id, int) or release.get("draft") is not True or release.get("prerelease") is not False or
                release.get("name") != identity["tag"] or release.get("tag_name") != identity["tag"] or
                release.get("target_commitish") != identity["sha"] or release.get("body") != identity["notes"] or release.get("assets") != []):
            release_common.fail("GitHub did not create the expected draft")
        release_common.run("gh", "api", "--method", "POST", f"https://uploads.github.com/repos/{identity['repository']}/releases/{release_id}/assets?name={identity['archive-name']}",
            "--header", "Content-Type: application/octet-stream", "--input", str(archive))
        release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
        release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, True):
            release_common.fail("GitHub draft changed unexpectedly")
        copied = temporary / identity["archive-name"]
        shutil.copyfile(archive, copied)
        try:
            release_common.run(str(node), str(npm), "publish", str(copied), "--ignore-scripts", "--registry", REGISTRY, "--access", "public",
                cwd=temporary, env=env, timeout=600)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            release_common.fail("npm publication failed")
        wait_for_npm(identity["package"], identity["version"], identity["archive-sha256"])
        tag_sha = release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
        release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, True):
            release_common.fail("GitHub draft changed before publication")
        release_common.gh_json("--method", "PATCH", f"repos/{identity['repository']}/releases/{release_id}", "-F", "draft=false")
        release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
        if not exact_draft(release, release_id, identity, size, digest, False) or release.get("immutable") is not True:
            release_common.fail("GitHub release publication verification failed")
        release_common.verify_release(identity, tag_sha)
    url = release.get("html_url")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{identity['repository']}/releases/"):
        release_common.fail("GitHub release URL is invalid")
    release_common.output(**{"release-url": url})


def check_npm():
    node, npm = node_runtime()
    with tempfile.TemporaryDirectory() as temporary:
        try:
            version = release_common.run(str(node), str(npm), "--version", env=npm_env(pathlib.Path(temporary))).strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            release_common.fail("trusted npm runtime is unavailable")
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", version)
    if not match or tuple(map(int, match.groups())) < (11, 5, 1):
        release_common.fail("npm OIDC support is unavailable")


def arguments(argv):
    commands = {"identity", "validate", "verify-attestation", "publish", "check-npm"}
    if len(argv) < 2 or argv[1] not in commands:
        release_common.fail("invalid command")
    command = argv[1]
    if command == "check-npm":
        if len(argv) != 2:
            release_common.fail("invalid command arguments")
        return command, {}
    values = {}
    items = argv[2:]
    if len(items) % 2:
        release_common.fail("invalid command arguments")
    for key, value in zip(items[::2], items[1::2]):
        if key not in {"--source", "--package-directory", "--files", "--expected-sha256"} or key in values:
            release_common.fail("invalid command arguments")
        values[key] = value
    required = {"--source", "--package-directory"}
    if command == "validate":
        required.add("--files")
    elif command != "identity":
        required.update({"--files", "--expected-sha256"})
    if set(values) != required:
        release_common.fail("invalid command arguments")
    return command, values


def main(argv):
    command, values = arguments(argv)
    if command == "check-npm":
        check_npm()
        return
    try:
        source = pathlib.Path(values["--source"]).resolve(strict=True)
    except OSError:
        release_common.fail("trusted checkout is invalid")
    if not source.is_dir():
        release_common.fail("trusted checkout is invalid")
    directory = release_common.package_directory(source, values["--package-directory"])
    if command == "identity":
        identity = trusted_identity(source, directory)
        emitted = {key: identity[key] for key in ("package", "version", "tag", "repository", "sha")}
        emitted["archive-name"] = archive_name(identity["package"], identity["version"])
        emitted["signer-workflow"] = identity["signer"]
        release_common.output(**emitted)
        print(json.dumps(emitted, sort_keys=True))
        return
    if command == "validate":
        identity = validate(source, directory, values["--files"])
        release_common.output(**{"archive-sha256": identity["archive-sha256"], "archive-name": identity["archive-name"],
                  "archive-path": str(identity["archive"]), "files-directory": identity["files-directory"]})
        return
    expected = values["--expected-sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        release_common.fail("expected archive digest is invalid")
    identity = validate_snapshot(source, directory, values["--files"], expected)
    if command == "verify-attestation":
        release_common.verify_attestation(identity)
        return
    publish(identity)


if __name__ == "__main__":
    main(sys.argv)
