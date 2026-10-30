#!/usr/bin/env python3
"""Check a Cargo archive, upload it to crates.io and create a GitHub release."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

common_spec = importlib.util.spec_from_file_location(
    "release_common", pathlib.Path(__file__).with_name("release_common.py"))
release_common = importlib.util.module_from_spec(common_spec)
common_spec.loader.exec_module(release_common)

CRATES = "https://crates.io"
INDEX = "https://index.crates.io"
STATIC = "https://static.crates.io"
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
DEPENDENCY_SECTIONS = (("dependencies", "normal"), ("dev-dependencies", "dev"),
                       ("build-dependencies", "build"))
DEPENDENCY_FIELDS = frozenset({"version", "package", "features", "optional", "default-features", "default_features"})


def archive_name(package, version):
    return f"{package}-{version}.crate"


def index_path(package):
    name = package.lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def index_url(package):
    return f"{INDEX}/{index_path(package)}"


def archive_url(package, version):
    return f"{STATIC}/crates/{package}/{archive_name(package, version)}"


def parse_manifest_bytes(data, label):
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        release_common.fail(f"{label} is invalid")


def string_list(value, label):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        release_common.fail(f"{label} is invalid")
    return value


def feature_metadata(manifest):
    features = manifest.get("features", {})
    if not isinstance(features, dict):
        release_common.fail("Cargo features are invalid")
    for value in features.values():
        string_list(value, "Cargo feature")
    return features


def dependency_metadata(manifest):
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        release_common.fail("Cargo target dependencies are invalid")
    scopes = [(None, manifest), *targets.items()]
    dependencies = []
    for platform, table in scopes:
        if not isinstance(table, dict) or any(key.endswith("_dependencies") for key in table):
            release_common.fail("Cargo dependency table is unsupported")
        for section, kind in DEPENDENCY_SECTIONS:
            entries = table.get(section, {})
            if not isinstance(entries, dict):
                release_common.fail("Cargo dependencies are invalid")
            for alias, value in entries.items():
                if isinstance(value, str):
                    value = {"version": value}
                if not isinstance(value, dict) or set(value) - DEPENDENCY_FIELDS:
                    release_common.fail("Cargo dependency source or setting is unsupported")
                name, version = value.get("package", alias), value.get("version")
                optional = value.get("optional", False)
                defaults = value.get("default-features", value.get("default_features", True))
                if (not PACKAGE.fullmatch(alias) or not isinstance(name, str) or not PACKAGE.fullmatch(name)
                        or not isinstance(version, str) or not version.strip()
                        or type(optional) is not bool or type(defaults) is not bool
                        or {"default-features", "default_features"} <= set(value)):
                    release_common.fail("Cargo dependency is invalid")
                dependencies.append({
                    "name": name, "version_req": version,
                    "features": string_list(value.get("features", []), "Cargo dependency features"),
                    "optional": optional, "default_features": defaults,
                    "target": platform, "kind": kind, "registry": None,
                    "explicit_name_in_toml": alias if name != alias else None,
                })
    return sorted(dependencies, key=lambda entry: (entry["kind"], entry["target"] or "",
                                                  entry["explicit_name_in_toml"] or entry["name"]))


def package_metadata(manifest):
    package = manifest["package"]
    values = {field: package.get(field) for field in (
        "description", "documentation", "homepage", "license", "repository", "links")}
    values.update(license_file=package.get("license-file"), rust_version=package.get("rust-version"))
    if any(value is not None and not isinstance(value, str) for value in values.values()):
        release_common.fail("Cargo package metadata is invalid")
    if not values["description"] or not (values["license"] or values["license_file"]):
        release_common.fail("crates.io requires a description and a license or license file")
    for field in ("authors", "keywords", "categories"):
        values[field] = string_list(package.get(field, []), f"Cargo {field}")
    badges = manifest.get("badges", {})
    if (not isinstance(badges, dict) or any(not isinstance(value, dict)
            or any(not isinstance(item, str) for item in value.values()) for value in badges.values())):
        release_common.fail("Cargo badges are invalid")
    values["badges"] = badges
    return values


def validate_manifest(manifest, repository, tag):
    package = manifest.get("package")
    if not isinstance(package, dict) or "workspace" in manifest or "workspace" in package:
        release_common.fail("single-package Cargo manifest is required")
    if "patch" in manifest or "replace" in manifest:
        release_common.fail("Cargo dependency overrides are unsupported")
    edition = package.get("edition", "2015")
    resolver = package.get("resolver", {"2021": "2", "2024": "3"}.get(edition, "1")) if isinstance(edition, str) else None
    if (edition not in ("2015", "2018", "2021", "2024") or resolver not in ("1", "2", "3")):
        release_common.fail("Cargo edition or resolver is unsupported")
    publishing = package.get("publish", True)
    if publishing is not True and not (isinstance(publishing, list) and publishing
            and all(isinstance(value, str) for value in publishing) and "crates-io" in publishing):
        release_common.fail("Cargo package does not permit crates.io publishing")
    name, version = package.get("name"), package.get("version")
    if (not isinstance(name, str) or not PACKAGE.fullmatch(name) or not isinstance(version, str)
            or not release_common.VERSION.fullmatch(version)):
        release_common.fail("Cargo manifest identity is invalid")
    if (tag != f"v{version}" or not isinstance(package.get("repository"), str)
            or release_common.canonical_repository(package["repository"]) != repository):
        release_common.fail("Cargo manifest does not match trusted release identity")
    dependency_metadata(manifest)
    feature_metadata(manifest)
    package_metadata(manifest)
    return name, version


def trusted_identity(source, package_dir):
    repository, sha, ref, tag, signer = release_common.environment_identity()
    try:
        head = release_common.run("git", "-C", str(source), "rev-parse", "HEAD").strip()
        tagged = release_common.run("git", "-C", str(source), "rev-parse", f"{ref}^{{commit}}").strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        release_common.fail("trusted checkout cannot verify the release tag")
    if head != sha or tagged != sha:
        release_common.fail("trusted checkout does not match the release commit")
    manifest_path = release_common.under(source, package_dir / "Cargo.toml", "Cargo manifest")
    manifest_bytes = release_common.read_limited(manifest_path, release_common.MAX_METADATA, "Cargo manifest")
    manifest = parse_manifest_bytes(manifest_bytes, "Cargo manifest")
    package, version = validate_manifest(manifest, repository, tag)
    changelog = release_common.under(source, package_dir / "CHANGELOG.md", "changelog")
    try:
        notes = release_common.release_notes(
            release_common.read_limited(changelog, release_common.MAX_CHANGELOG, "changelog").decode("utf-8"), version)
    except UnicodeDecodeError:
        release_common.fail("changelog is invalid")
    relative = package_dir.relative_to(source).as_posix()
    return {"package": package, "version": version, "tag": tag, "repository": repository,
            "sha": sha, "signer": signer, "notes": notes, "manifest": manifest,
            "manifest-bytes": manifest_bytes, "package-directory": package_dir,
            "source": source, "path-in-vcs": "" if relative == "." else relative}


def archive_member(archive, prefix, name):
    try:
        member = archive.getmember(prefix + name)
    except KeyError:
        release_common.fail("crate source metadata or README is missing")
    if not member.isfile() or member.size > release_common.MAX_METADATA:
        release_common.fail("crate source metadata or README is invalid")
    with archive.extractfile(member) as source:
        return source.read(release_common.MAX_METADATA + 1)


def bind_build_settings(manifest, identity, archive, prefix):
    original = identity["manifest"]
    source_package, package = original["package"], manifest["package"]
    auto = {"autolib", "autobins", "autoexamples", "autotests", "autobenches"}
    generated = auto | {"edition", "resolver", "build", "readme", "publish"}
    edition = source_package.get("edition", "2015")
    default_resolver = {"2021": "2", "2024": "3"}.get(edition, "1")
    resolver = source_package.get("resolver", default_resolver)
    if (package.get("edition", "2015") != edition or package.get("resolver", default_resolver) != resolver
            or any(package.get(key) is not False for key in auto)
            or not release_common.same_metadata(
                {key: value for key, value in package.items() if key not in generated},
                {key: value for key, value in source_package.items() if key not in generated})):
        release_common.fail("crate package settings differ from approved source")
    build = source_package.get("build")
    if build is None or build is True:
        build = "build.rs" if (identity["package-directory"] / "build.rs").is_file() else False
    if not release_common.same_metadata(package.get("build", False), build):
        release_common.fail("crate build script differs from approved source")
    if build is not False:
        approved_file(build, identity, archive, prefix)
    normalized = {"package", "features", "target", "lib", "bin", "example", "test", "bench",
                  *(section for section, _ in DEPENDENCY_SECTIONS)}
    if not release_common.same_metadata(
            {key: value for key, value in manifest.items() if key not in normalized},
            {key: value for key, value in original.items() if key not in normalized}):
        release_common.fail("crate build configuration differs from approved source")
    for kind, flag, directory in (("lib", "autolib", "src"), ("bin", "autobins", "src/bin"),
                                  ("example", "autoexamples", "examples"), ("test", "autotests", "tests"),
                                  ("bench", "autobenches", "benches")):
        declared = target_rows(original, kind, identity["package"])
        packaged = target_rows(manifest, kind, identity["package"])
        if not declared.keys() <= packaged.keys():
            release_common.fail("crate omits an approved explicit target")
        if (kind == "lib" and source_package.get(flag, True) is True
                and (identity["package-directory"] / "src/lib.rs").is_file() and not packaged):
            release_common.fail("crate omits the approved library")
        for name, target in packaged.items():
            expected = declared.get(name)
            if expected is None:
                if (source_package.get(flag, True) is not True
                        or (kind == "lib" and name != identity["package"].replace("-", "_"))):
                    release_common.fail("crate introduces a disabled or renamed automatic target")
                expected = {}
            if (set(target) - set(expected) - {"name", "path"}
                    or any(not release_common.same_metadata(value, target.get(key)) for key, value in expected.items())):
                release_common.fail("crate target settings differ from approved source")
            path = target.get("path")
            if "path" not in expected:
                allowed = {f"{directory}/{name}.rs", f"{directory}/{name}/main.rs"}
                if kind == "lib":
                    allowed = {"src/lib.rs"}
                elif kind == "bin" and name == identity["package"]:
                    allowed.add("src/main.rs")
                if path not in allowed:
                    release_common.fail("crate target path differs from approved source")
            approved_file(path, identity, archive, prefix)


def target_rows(manifest, kind, package):
    value = manifest.get(kind)
    if value is None:
        return {}
    rows = [value] if kind == "lib" else value
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        release_common.fail("Cargo targets are invalid")
    targets = {}
    for row in rows:
        name = row.get("name", package.replace("-", "_") if kind == "lib" else None)
        if not isinstance(name, str) or not PACKAGE.fullmatch(name) or name in targets:
            release_common.fail("Cargo target names are invalid")
        targets[name] = row
    return targets


def approved_file(value, identity, archive, prefix):
    relative = pathlib.PurePosixPath(value) if isinstance(value, str) else None
    if (relative is None or relative.is_absolute() or ".." in relative.parts or str(relative) != value
            or "\\" in value or "\0" in value):
        release_common.fail("crate build path is invalid")
    source = release_common.under(identity["source"], identity["package-directory"] / value, "build source")
    try:
        member = archive.getmember(prefix + value)
    except KeyError:
        release_common.fail("crate build source is missing")
    if not source.is_file() or not member.isfile():
        release_common.fail("crate build source is invalid")


def bind_manifest(manifest, identity, archive, prefix):
    package, version = validate_manifest(manifest, identity["repository"], identity["tag"])
    original = identity["manifest"]
    if (package != identity["package"] or version != identity["version"]
            or dependency_metadata(manifest) != dependency_metadata(original)
            or feature_metadata(manifest) != feature_metadata(original)
            or package_metadata(manifest) != package_metadata(original)):
        release_common.fail("crate manifest differs from approved source metadata")
    bind_build_settings(manifest, identity, archive, prefix)


def readme_metadata(archive, prefix, manifest, identity):
    readme = manifest["package"].get("readme")
    original = identity["manifest"]["package"].get("readme")
    if readme is False or readme is None:
        if original not in (False, None):
            release_common.fail("crate README differs from approved source")
        return None, None
    path = pathlib.PurePosixPath(readme) if isinstance(readme, str) else None
    if (path is None or path.is_absolute() or ".." in path.parts or str(path) != readme
            or (original is not None and original != readme)
            or (original is None and readme not in {"README.md", "README.txt", "README"})):
        release_common.fail("crate README path is invalid or differs from approved source")
    data = archive_member(archive, prefix, readme)
    approved = release_common.under(identity["source"], identity["package-directory"] / readme, "README")
    if data != release_common.read_limited(approved, release_common.MAX_METADATA, "README"):
        release_common.fail("crate README differs from approved source")
    try:
        return data.decode("utf-8"), readme
    except UnicodeDecodeError:
        release_common.fail("crate README is not UTF-8")


def inspect_archive(archive, identity):
    prefix = f"{identity['package']}-{identity['version']}/"
    try:
        with tempfile.TemporaryFile() as raw:
            release_common.copy_raw_tar(archive, raw, allowed_types={b"0", b"\0", b"5", b"L"})
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:") as contents:
                names, unpacked = set(), 0
                for member in contents:
                    name = member.name
                    if (len(names) >= release_common.MAX_MEMBERS or name in names or not name.startswith(prefix)
                            or "\\" in name or "\0" in name or ".." in pathlib.PurePosixPath(name).parts
                            or str(pathlib.PurePosixPath(name)) != name.rstrip("/")):
                        release_common.fail("crate member inventory is invalid")
                    names.add(name)
                    if (not (member.isdir() or member.isfile()) or member.issparse()
                            or (member.isdir() and member.size) or (member.isfile() and name.endswith("/"))):
                        release_common.fail("crate contains a non-regular member")
                    unpacked += member.size
                    if unpacked > release_common.MAX_UNPACKED:
                        release_common.fail("crate expands beyond the size limit")
                original = archive_member(contents, prefix, "Cargo.toml.orig")
                if original != identity["manifest-bytes"]:
                    release_common.fail("crate Cargo.toml.orig differs from approved source")
                manifest = parse_manifest_bytes(archive_member(contents, prefix, "Cargo.toml"), "crate Cargo.toml")
                bind_manifest(manifest, identity, contents, prefix)
                readme, filename = readme_metadata(contents, prefix, manifest, identity)
                details = json.loads(archive_member(contents, prefix, ".cargo_vcs_info.json"))
    except (tarfile.TarError, OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        release_common.fail("crate is invalid")
    git = details.get("git") if isinstance(details, dict) else None
    if (not isinstance(git, dict) or git.get("sha1") != identity["sha"]
            or git.get("dirty", False) is not False or details.get("path_in_vcs") != identity["path-in-vcs"]):
        release_common.fail("crate VCS identity is invalid")
    identity.update({"crate-manifest": manifest, "crate-readme": readme, "crate-readme-file": filename})


def validate_snapshot(source, package_dir, files, expected=None):
    identity = trusted_identity(source, package_dir)
    name = archive_name(identity["package"], identity["version"])
    supplied = pathlib.Path(files)
    try:
        directory = supplied.resolve(strict=True)
        directory.relative_to(pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True))
        inventory = {path.name for path in directory.iterdir()}
    except (KeyError, OSError, ValueError):
        release_common.fail("release snapshot directory is invalid")
    archive = directory / name
    if (supplied.is_symlink() or not directory.name.startswith("waxseal-")
            or stat.S_IMODE(directory.stat().st_mode) != 0o700 or inventory != {name}
            or archive.is_symlink() or not stat.S_ISREG(archive.lstat().st_mode)):
        release_common.fail("release snapshot inventory is invalid")
    sha256 = release_common.hash_file(archive)
    if expected is not None and sha256 != expected:
        release_common.fail("release snapshot digest does not match validation")
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def validate(source, package_dir, files, *, artifact_zip=False):
    identity = trusted_identity(source, package_dir)
    name = archive_name(identity["package"], identity["version"])
    snapshot = release_common.snapshot_zipped_artifact if artifact_zip else release_common.snapshot_artifact
    directory, archive, sha256 = snapshot(files, name)
    inspect_archive(archive, identity)
    identity.update({"archive": archive, "archive-name": name, "archive-sha256": sha256,
                     "files-directory": str(directory)})
    return identity


def require_unpublished(package, version):
    try:
        with release_common.request_deadline(time.monotonic() + 30):
            with release_common.OPENER.open(f"{CRATES}/api/v1/crates/{package}/{version}", timeout=30):
                pass
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        if status == 404:
            return
    except (urllib.error.URLError, OSError):
        pass
    release_common.fail("crates.io publication status could not be confirmed as unpublished")


def verify_crate(package, version, sha256, deadline):
    try:
        records = release_common.read_url(index_url(package), release_common.MAX_METADATA, deadline).decode("utf-8").splitlines()
    except UnicodeDecodeError:
        release_common.fail("crates.io index verification failed")
    matches = []
    for line in records:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            release_common.fail("crates.io index verification failed")
        if not isinstance(record, dict) or record.get("name") != package:
            release_common.fail("crates.io index verification failed")
        if record.get("vers") == version:
            matches.append(record)
    if not matches:
        raise release_common.ReadUnavailable("crates.io index does not yet contain the published version")
    if len(matches) != 1 or matches[0].get("yanked") is not False or matches[0].get("cksum") != sha256:
        release_common.fail("crates.io index does not match the approved crate")
    data = release_common.read_url(archive_url(package, version), release_common.MAX_ARCHIVE, deadline)
    if hashlib.sha256(data).hexdigest() != sha256:
        release_common.fail("crates.io archive digest does not match the approved asset")


def wait_for_crate(package, version, sha256):
    deadline = time.monotonic() + 300
    while True:
        try:
            verify_crate(package, version, sha256, deadline)
            return
        except release_common.ReadUnavailable as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                release_common.fail(f"crates.io publication verification timed out: {error}")
            delay = min(5, remaining)
            print(f"{error}; retrying verification in {delay:g}s", file=sys.stderr, flush=True)
            time.sleep(delay)
            if time.monotonic() >= deadline:
                release_common.fail(f"crates.io publication verification timed out: {error}")


def exact_release(release, release_id, identity, size, digest, draft):
    assets = release.get("assets")
    return (release.get("id") == release_id and release.get("name") == identity["tag"]
            and release.get("tag_name") == identity["tag"] and release.get("target_commitish") == identity["sha"]
            and release.get("body") == identity["notes"] and release.get("prerelease") is False
            and release.get("draft") is draft and isinstance(assets, list) and len(assets) == 1
            and assets[0].get("name") == identity["archive-name"] and assets[0].get("size") == size
            and assets[0].get("digest") == digest)


def crate_metadata(identity):
    manifest = identity["crate-manifest"]
    return {"name": identity["package"], "vers": identity["version"], "deps": dependency_metadata(manifest),
            "features": feature_metadata(manifest), **package_metadata(manifest),
            "readme": identity.get("crate-readme"), "readme_file": identity.get("crate-readme-file")}


def upload_crate(identity):
    token = os.environ.get("CARGO_REGISTRY_TOKEN", "")
    if not re.fullmatch(r"[!-~]+", token):
        release_common.fail("crates.io temporary token is missing or invalid")
    data = release_common.read_limited(identity["archive"], release_common.MAX_ARCHIVE, "release artifact")
    metadata = json.dumps(crate_metadata(identity), separators=(",", ":"), ensure_ascii=True).encode()
    body = struct.pack("<I", len(metadata)) + metadata + struct.pack("<I", len(data)) + data
    request = urllib.request.Request(
        f"{CRATES}/api/v1/crates/new", data=body, method="PUT",
        headers={"Authorization": token, "Content-Type": "application/octet-stream", "Content-Length": str(len(body))})
    try:
        with release_common.request_deadline(time.monotonic() + 60):
            with release_common.OPENER.open(request, timeout=60) as response:
                result = response.read(release_common.MAX_METADATA + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        release_common.fail(f"crates.io upload failed with HTTP {status}; no automatic retry")
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        release_common.fail("crates.io upload outcome is uncertain; inspect before retrying")
    if len(result) > release_common.MAX_METADATA:
        release_common.fail("crates.io upload response exceeds the size limit")
    try:
        decoded = json.loads(result)
    except (UnicodeDecodeError, json.JSONDecodeError):
        release_common.fail("crates.io upload response is invalid; inspect before retrying")
    if not isinstance(decoded, dict) or decoded.get("errors"):
        release_common.fail("crates.io upload was rejected")


def publish(identity):
    release_common.verify_attestation(identity)
    archive = identity["archive"]
    size, digest = archive.stat().st_size, f"sha256:{identity['archive-sha256']}"
    release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
    pages = release_common.gh_json("--paginate", "--slurp", f"repos/{identity['repository']}/releases?per_page=100")
    if (not isinstance(pages, list) or any(not isinstance(page, list) for page in pages)
            or any(not isinstance(release, dict) or release.get("tag_name") == identity["tag"]
                   for page in pages for release in page)):
        release_common.fail("release inventory is invalid or a release already exists for this tag")
    require_unpublished(identity["package"], identity["version"])
    payload = json.dumps({"tag_name": identity["tag"], "target_commitish": identity["sha"], "name": identity["tag"],
                          "body": identity["notes"], "draft": True, "prerelease": False})
    release = release_common.gh_json("--method", "POST", f"repos/{identity['repository']}/releases", "--input", "-", input=payload)
    release_id = release.get("id")
    if (type(release_id) is not int or release_id < 1 or release.get("draft") is not True
            or release.get("prerelease") is not False or release.get("name") != identity["tag"]
            or release.get("tag_name") != identity["tag"] or release.get("target_commitish") != identity["sha"]
            or release.get("body") != identity["notes"] or release.get("assets") != []):
        release_common.fail("GitHub did not create the expected draft")
    release_common.run("gh", "api", "--method", "POST",
                       f"https://uploads.github.com/repos/{identity['repository']}/releases/{release_id}/assets?name={identity['archive-name']}",
                       "--header", "Content-Type: application/octet-stream", "--input", str(archive))
    release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
    release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
    if not exact_release(release, release_id, identity, size, digest, True):
        release_common.fail("GitHub draft changed unexpectedly")
    upload_crate(identity)
    wait_for_crate(identity["package"], identity["version"], identity["archive-sha256"])
    release_common.require_tag(identity["repository"], identity["tag"], identity["sha"])
    release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
    if not exact_release(release, release_id, identity, size, digest, True):
        release_common.fail("GitHub draft changed before publication")
    release_common.gh_json("--method", "PATCH", f"repos/{identity['repository']}/releases/{release_id}", "-F", "draft=false")
    release = release_common.gh_json(f"repos/{identity['repository']}/releases/{release_id}")
    if not exact_release(release, release_id, identity, size, digest, False) or release.get("immutable") is not True:
        release_common.fail("GitHub release publication verification failed")
    try:
        release_common.run("gh", "release", "verify", identity["tag"], "--repo", f"https://github.com/{identity['repository']}")
        release_common.run("gh", "release", "verify-asset", identity["tag"], str(archive), "--repo", f"https://github.com/{identity['repository']}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        release_common.fail("GitHub release verification failed")
    url = release.get("html_url")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{identity['repository']}/releases/"):
        release_common.fail("GitHub release URL is invalid")
    release_common.output(**{"release-url": url})


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "artifact", "validate", "verify-attestation", "publish"))
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--package-directory", required=True)
    parser.add_argument("--files", type=pathlib.Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--artifact-name")
    parser.add_argument("--artifact-zip", action="store_true")
    args = parser.parse_args(argv[1:])
    if ((args.command in {"identity", "artifact"}) != (args.files is None)
            or (args.command == "artifact") != (args.artifact_name is not None)
            or (args.artifact_zip and args.command != "validate")
            or (args.command in {"verify-attestation", "publish"}) != (args.expected_sha256 is not None)):
        parser.error("command and artifact arguments differ")
    try:
        source = args.source.resolve(strict=True)
    except OSError:
        release_common.fail("trusted checkout is invalid")
    if not source.is_dir():
        release_common.fail("trusted checkout is invalid")
    directory = release_common.package_directory(source, args.package_directory)
    if args.command == "artifact":
        release_common.locate_artifact(args.artifact_name)
        return
    if args.command == "identity":
        identity = trusted_identity(source, directory)
        emitted = {key: identity[key] for key in ("package", "version", "tag", "repository", "sha")}
        emitted.update({"archive-name": archive_name(identity["package"], identity["version"]),
                        "signer-workflow": identity["signer"]})
        release_common.output(**emitted)
        print(json.dumps(emitted, sort_keys=True))
        return
    if args.command == "validate":
        identity = validate(source, directory, args.files, artifact_zip=args.artifact_zip)
        release_common.output(**{"archive-sha256": identity["archive-sha256"], "archive-name": identity["archive-name"],
                                 "archive-path": str(identity["archive"]), "files-directory": identity["files-directory"]})
        return
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        release_common.fail("expected archive digest is invalid")
    identity = validate_snapshot(source, directory, args.files, args.expected_sha256)
    if args.command == "verify-attestation":
        release_common.verify_attestation(identity)
    else:
        publish(identity)


if __name__ == "__main__":
    main(sys.argv)
