#!/usr/bin/env python3
"""Cargo archive checks and crates.io upload protocol regressions."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "publish-crate.py"
spec = importlib.util.spec_from_file_location("publish_crate", SCRIPT)
publish_crate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish_crate)
common = publish_crate.release_common
SHA = "a" * 40
MANIFEST = b'''[package]
name = "example"
version = "1.2.3"
edition = "2024"
description = "Example crate"
repository = "https://github.com/owner/repo.git"
license = "MIT"
readme = "README.md"
rust-version = "1.85"
'''


def tarball(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, kind, data in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                archive.addfile(member)
    return gzip.compress(output.getvalue())


def normalized_manifest(manifest):
    controls = b"autolib = false\nautobins = false\nautoexamples = false\nautotests = false\nautobenches = false\n"
    return (manifest.replace(b"[package]\n", b"[package]\n" + controls)
            + b'\n[lib]\nname = "example"\npath = "src/lib.rs"\n')


def crate_archive(manifest=MANIFEST, vcs=None, extra=(), original=None, readme="README.md", docs=b"# Example\n", normalized=None):
    if vcs is None:
        vcs = json.dumps({"git": {"sha1": SHA}, "path_in_vcs": ""}).encode()
    prefix = "example-1.2.3/"
    return tarball([(prefix + "Cargo.toml", tarfile.REGTYPE, normalized_manifest(manifest) if normalized is None else normalized),
                    (prefix + "Cargo.toml.orig", tarfile.REGTYPE, manifest if original is None else original),
                    (prefix + ".cargo_vcs_info.json", tarfile.REGTYPE, vcs),
                    (prefix + "src/lib.rs", tarfile.REGTYPE, b"pub const EXAMPLE: bool = true;\n"),
                    (prefix + readme, tarfile.REGTYPE, docs), *extra])


def source_identity(root, manifest=MANIFEST):
    (root / "Cargo.toml").write_bytes(manifest)
    (root / "README.md").write_bytes(b"# Example\n")
    (root / "src").mkdir(exist_ok=True)
    (root / "src/lib.rs").write_bytes(b"pub const EXAMPLE: bool = true;\n")
    return {"package": "example", "version": "1.2.3", "repository": "owner/repo", "tag": "v1.2.3",
            "sha": SHA, "manifest-bytes": manifest, "manifest": publish_crate.parse_manifest_bytes(manifest, "source"),
            "path-in-vcs": "", "source": root, "package-directory": root}


def response(data):
    result = io.BytesIO(data)
    result.headers = {"Content-Length": str(len(data))}
    return result


class ArchiveValidationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.identity = source_identity(self.root)
        self.archive = self.root / "example-1.2.3.crate"

    def reject(self, data):
        self.archive.write_bytes(data)
        with self.assertRaises(SystemExit):
            publish_crate.inspect_archive(self.archive, self.identity.copy())

    def test_rejects_unsafe_duplicate_and_link_members(self):
        for entries in ([('example-1.2.3/../escape', tarfile.REGTYPE, b'x')],
                        [('example-1.2.3/link', tarfile.SYMTYPE, b'')],
                        [('example-1.2.3/README.md', tarfile.REGTYPE, b'changed')]):
            with self.subTest(entries=entries):
                self.reject(crate_archive(extra=entries))

    def test_rejects_changed_original_or_normalized_dependency_and_features(self):
        self.reject(crate_archive(manifest=MANIFEST.replace(b"Example", b"Changed")))
        for suffix, old, new in ((b'\n[dependencies]\nserde = "1"\n', b'serde = "1"', b'serde = "2"'),
                                 (b'\n[features]\ndefault = []\n', b'default = []', b'default = ["other"]')):
            source = MANIFEST + suffix
            self.identity = source_identity(self.root, source)
            with self.subTest(suffix=suffix):
                self.reject(crate_archive(manifest=source.replace(old, new), original=source))

    def test_rejects_dirty_foreign_or_wrong_directory_vcs_identity(self):
        for details in ({"git": {"sha1": SHA, "dirty": True}, "path_in_vcs": ""},
                        {"git": {"sha1": "b" * 40}, "path_in_vcs": ""},
                        {"git": {"sha1": SHA}, "path_in_vcs": "another-package"}):
            with self.subTest(details=details):
                self.reject(crate_archive(vcs=json.dumps(details).encode()))

    def test_clean_cargo_archive_preserves_source_readme(self):
        self.archive.write_bytes(crate_archive())
        publish_crate.inspect_archive(self.archive, self.identity)
        self.assertEqual(self.identity["crate-readme"], "# Example\n")
        self.assertEqual(self.identity["crate-readme-file"], "README.md")
        self.reject(crate_archive(docs=b"Replaced documentation"))

    def test_reads_bounded_cargo_gnu_long_names(self):
        filename = "a" * 140 + "/README.md"
        source = MANIFEST.replace(b'"README.md"', json.dumps(filename).encode())
        self.identity = source_identity(self.root, source)
        destination = self.root / filename
        destination.parent.mkdir()
        destination.write_bytes(b"Long-path documentation\n")
        self.archive.write_bytes(crate_archive(source, readme=filename, docs=destination.read_bytes()))
        publish_crate.inspect_archive(self.archive, self.identity)
        self.assertEqual(self.identity["crate-readme"], "Long-path documentation\n")
        self.reject(crate_archive(extra=[("example-1.2.3/" + "a" * 4097, tarfile.REGTYPE, b"x")]))

    def test_rejects_normalized_edition_build_and_target_changes(self):
        normalized = normalized_manifest(MANIFEST)
        for old, new in ((b'edition = "2024"\n', b''),
                         (b'edition = "2024"', b'edition = "2015"'),
                         (b'autobins = false', b'autobins = true'),
                         (b'path = "src/lib.rs"', b'path = "README.md"'),
                         (b'[lib]', b'[lib]\nproc-macro = true'),
                         (b'[package]', b'[package]\nresolver = "1"'),
                         (b'[package]', b'[package]\nbuild = "README.md"')):
            with self.subTest(old=old, new=new):
                self.reject(crate_archive(normalized=normalized.replace(old, new)))

    def test_rejects_lost_explicit_resolver(self):
        source = MANIFEST + b'resolver = "2"\n'
        self.identity = source_identity(self.root, source)
        normalized = normalized_manifest(source).replace(b'resolver = "2"\n', b'')
        self.reject(crate_archive(source, normalized=normalized))



class ArtifactEnvelopeTest(unittest.TestCase):
    def test_rejects_compressed_bomb_traversal_and_extra_members(self):
        for members in ((("example-1.2.3.crate", b"a" * 1025),),
                        (("../example-1.2.3.crate", b"x"),),
                        (("example-1.2.3.crate", b"x"), ("extra", b"x"))):
            with self.subTest(names=tuple(name for name, _ in members)), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                files = root / "files"
                files.mkdir()
                with zipfile.ZipFile(files / "artifact.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for name, data in members:
                        archive.writestr(name, data)
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), \
                        mock.patch.object(common, "MAX_ARCHIVE", 1024), self.assertRaises(SystemExit):
                    common.snapshot_zipped_artifact(files, "example-1.2.3.crate")
                self.assertFalse((root / "example-1.2.3.crate").exists())

    def test_rejects_foreign_or_oversized_artifact_before_download(self):
        name = "release-files-42-2"
        valid = {"id": 17, "name": name, "size_in_bytes": 100, "expired": False,
                 "workflow_run": {"id": 42, "head_sha": SHA}}
        environment = SourceBoundValidationTest().environment() | {"GITHUB_RUN_ID": "42"}
        for change in ({"size_in_bytes": common.MAX_ARTIFACT_ZIP + 1},
                       {"workflow_run": {"id": 43, "head_sha": SHA}},
                       {"workflow_run": {"id": 42, "head_sha": "b" * 40}},
                       {"name": "other"}, {"expired": True}, {"id": True}):
            with self.subTest(change=change), mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(common, "gh_json", return_value={"total_count": 1, "artifacts": [valid | change]}), \
                    self.assertRaises(SystemExit):
                common.locate_artifact(name)
        for count in (0, 2):
            with self.subTest(count=count), mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(common, "gh_json", return_value={"total_count": count, "artifacts": [valid] * count}), \
                    self.assertRaises(SystemExit):
                common.locate_artifact(name)

    def test_rejects_unsafe_zip_modes_corruption_and_limits(self):
        for case in ("symlink", "directory", "compression", "encrypted", "crc", "size", "zip-limit"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                files = root / "files"
                files.mkdir()
                path = files / "artifact.zip"
                member = zipfile.ZipInfo("example-1.2.3.crate" + ("/" if case == "directory" else ""))
                if case == "symlink":
                    member.external_attr = 0o120777 << 16
                if case == "compression":
                    member.compress_type = zipfile.ZIP_BZIP2
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(member, b"approved payload")
                raw = bytearray(path.read_bytes())
                central = raw.index(b"PK\x01\x02")
                if case == "encrypted":
                    raw[6:8] = (1).to_bytes(2, "little")
                    raw[central + 8:central + 10] = (1).to_bytes(2, "little")
                elif case == "crc":
                    raw[30 + len(member.filename.encode())] ^= 32
                elif case == "size":
                    raw[central + 24:central + 28] = (len(b"approved payload") + 1).to_bytes(4, "little")
                path.write_bytes(raw)
                limit = len(raw) - 1 if case == "zip-limit" else common.MAX_ARTIFACT_ZIP
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), \
                        mock.patch.object(common, "MAX_ARTIFACT_ZIP", limit), self.assertRaises(SystemExit):
                    common.snapshot_zipped_artifact(files, "example-1.2.3.crate")

    def test_rejects_symlinked_artifact_file_and_directory(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                actual = root / "actual"
                actual.mkdir()
                data = io.BytesIO()
                with zipfile.ZipFile(data, "w") as archive:
                    archive.writestr("example-1.2.3.crate", b"approved payload")
                if kind == "file":
                    (root / "archive.zip").write_bytes(data.getvalue())
                    (actual / "artifact.zip").symlink_to(root / "archive.zip")
                    supplied = actual
                else:
                    (actual / "artifact.zip").write_bytes(data.getvalue())
                    supplied = root / "alias"
                    supplied.symlink_to(actual, target_is_directory=True)
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), self.assertRaises(SystemExit):
                    common.snapshot_zipped_artifact(supplied, "example-1.2.3.crate")


class SourceBoundValidationTest(unittest.TestCase):
    def environment(self):
        return {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_SHA": SHA, "GITHUB_REF": "refs/tags/v1.2.3",
                "GITHUB_REF_TYPE": "tag", "GITHUB_EVENT_NAME": "push", "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/publish.yml@refs/tags/v1.2.3"}

    def test_rechecks_private_snapshot_digest_before_using_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, files = pathlib.Path(temporary) / "source", pathlib.Path(temporary) / "files"
            root.mkdir()
            files.mkdir()
            source_identity(root)
            (root / "CHANGELOG.md").write_text("## v1.2.3\n\nRelease notes.\n")
            (files / "example-1.2.3.crate").write_bytes(crate_archive())
            with mock.patch.dict(os.environ, self.environment() | {"RUNNER_TEMP": temporary}, clear=True), \
                    mock.patch.object(common, "run", return_value=SHA + "\n"):
                identity = publish_crate.validate(root, root, files)
                self.assertEqual(identity["path-in-vcs"], "")
                identity["archive"].write_bytes(crate_archive(extra=[("example-1.2.3/lib.rs", tarfile.REGTYPE, b"changed")]))
                with self.assertRaises(SystemExit):
                    publish_crate.validate_snapshot(root, root, identity["files-directory"], identity["archive-sha256"])

    def test_rejects_workspace_non_registry_sources_and_mistyped_features(self):
        for suffix in (b'\n[workspace]\nmembers = []\n',
                       b'\npublish = false\n',
                       b'\n[patch.crates-io]\n',
                       b'\n[replace]\n',
                       b'\n[dependencies]\nother = { git = "https://example.invalid/other" }\n',
                       b'\n[target.\'cfg(unix)\'.dependencies]\nother = { path = "../other" }\n',
                       b'\n[dependencies]\nother = { version = "1", registry-index = "https://example.invalid" }\n',
                       b'\n[features]\ndefault = [1]\n',
                       b'\n[dependencies]\nother = { version = "1", optional = 1 }\n'):
            with self.subTest(suffix=suffix), self.assertRaises(SystemExit):
                publish_crate.validate_manifest(publish_crate.parse_manifest_bytes(MANIFEST + suffix, "manifest"),
                                                "owner/repo", "v1.2.3")


class UploadFramingTest(unittest.TestCase):
    def identity(self, archive):
        return {"archive": archive, "package": "example", "version": "1.2.3", "repository": "owner/repo",
                "crate-manifest": publish_crate.parse_manifest_bytes(MANIFEST + b'''\n[dependencies]
serde = "1"
short = { package = "real-package", version = "2", default-features = false }
[target.'cfg(unix)'.build-dependencies]
cc = "1"
[badges]
maintenance = { status = "actively-developed" }
''', "manifest"), "crate-readme": "# Example\n", "crate-readme-file": "README.md"}

    def test_uses_documented_framing_dependency_names_and_readme_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.crate"
            archive.write_bytes(b"crate bytes")
            @contextlib.contextmanager
            def receive(request, timeout):
                self.assertEqual(request.full_url, "https://crates.io/api/v1/crates/new")
                self.assertEqual(request.get_method(), "PUT")
                self.assertEqual(request.get_header("Authorization"), "secret")
                body = request.data
                metadata_size = int.from_bytes(body[:4], "little")
                metadata = json.loads(body[4:4 + metadata_size])
                offset = 4 + metadata_size
                self.assertEqual(int.from_bytes(body[offset:offset + 4], "little"), len(b"crate bytes"))
                self.assertEqual(body[offset + 4:], b"crate bytes")
                self.assertEqual(metadata["readme"], "# Example\n")
                self.assertEqual(metadata["readme_file"], "README.md")
                self.assertEqual(metadata["rust_version"], "1.85")
                deps = {entry["name"]: entry for entry in metadata["deps"]}
                self.assertEqual(deps["serde"]["version_req"], "1")
                self.assertIsNone(deps["serde"]["explicit_name_in_toml"])
                self.assertEqual(deps["real-package"]["explicit_name_in_toml"], "short")
                self.assertFalse(deps["real-package"]["default_features"])
                self.assertEqual((deps["cc"]["target"], deps["cc"]["kind"]), ("cfg(unix)", "build"))
                self.assertEqual(metadata["badges"]["maintenance"]["status"], "actively-developed")
                yield response(b'{"warnings":{}}')
            with mock.patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "secret"}, clear=True), \
                    mock.patch.object(common.OPENER, "open", side_effect=receive):
                publish_crate.upload_crate(self.identity(archive))

    def test_never_retries_ambiguous_upload_or_2xx_api_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.crate"
            archive.write_bytes(b"crate bytes")
            for result in (urllib.error.URLError("lost response"), response(b'{"errors":[{"detail":"no"}]}')):
                with self.subTest(result=type(result).__name__), \
                        mock.patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "secret"}, clear=True), \
                        mock.patch.object(common.OPENER, "open", side_effect=[result]) as requests:
                    with self.assertRaises(SystemExit):
                        publish_crate.upload_crate(self.identity(archive))
                    self.assertEqual(requests.call_count, 1)


    def test_upload_timeout_is_uncertain_and_never_retried(self):
        elapsed = [0]

        class SlowResponse(io.BytesIO):
            def read(self, size):
                elapsed[0] = 61
                return super().read(size)

        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.crate"
            archive.write_bytes(b"crate bytes")
            with mock.patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "secret"}, clear=True), \
                    mock.patch.object(common.OPENER, "open", return_value=SlowResponse(b'{"warnings":{}}')) as requests, \
                    mock.patch.object(common.time, "monotonic", side_effect=lambda: elapsed[0]):
                with self.assertRaises(SystemExit):
                    publish_crate.upload_crate(self.identity(archive))
                self.assertEqual(requests.call_count, 1)


class RegistryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.archive = crate_archive()
        self.sha256 = hashlib.sha256(self.archive).hexdigest()
        self.record = {"name": "example", "vers": "1.2.3", "cksum": self.sha256, "yanked": False}
        self.elapsed = 0

    @contextlib.contextmanager
    def registry(self, replies):
        def pause(seconds):
            self.elapsed += seconds
        with mock.patch.object(common.OPENER, "open", side_effect=replies) as requests, \
                mock.patch.object(common.time, "monotonic", side_effect=lambda: self.elapsed), \
                mock.patch.object(common.time, "sleep", side_effect=pause), contextlib.redirect_stderr(io.StringIO()):
            yield requests

    def test_waits_for_existing_index_to_gain_new_version_and_retries_transient_reads(self):
        historical = json.dumps(self.record | {"vers": "1.2.2"}).encode()
        with self.registry([response(historical), urllib.error.HTTPError("index", 503, "x", {}, None),
                            response(json.dumps(self.record).encode()), response(self.archive)]):
            publish_crate.wait_for_crate("example", "1.2.3", self.sha256)
        self.assertEqual(self.elapsed, 10)

    def test_integrity_yank_duplicate_and_malformed_index_are_final(self):
        for data in (json.dumps(self.record | {"cksum": "b" * 64}).encode(),
                     json.dumps(self.record | {"yanked": True}).encode(),
                     (json.dumps(self.record) + "\n") .encode() * 2, b'[]'):
            with self.subTest(data=data), self.registry([response(data)]) as requests:
                with self.assertRaises(SystemExit):
                    publish_crate.wait_for_crate("example", "1.2.3", self.sha256)
                self.assertEqual(requests.call_count, 1)
                self.assertEqual(self.elapsed, 0)
        with self.registry([response(json.dumps(self.record).encode()), response(b"changed")]):
            with self.assertRaises(SystemExit):
                publish_crate.wait_for_crate("example", "1.2.3", self.sha256)

    def test_truncated_index_cannot_be_accepted_as_missing_version(self):
        partial = response(json.dumps(self.record | {"vers": "1.2.2"}).encode())
        partial.headers["Content-Length"] = str(int(partial.headers["Content-Length"]) + 10)
        with self.registry([partial]):
            with self.assertRaises(common.ReadUnavailable):
                publish_crate.verify_crate("example", "1.2.3", self.sha256, 30)

    def test_publication_waits_for_index_and_attestation_without_repeating_put(self):
        self.publication(mismatch=False)

    def test_integrity_failure_leaves_draft_unpublished(self):
        self.publication(mismatch=True)

    def publication(self, mismatch):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.crate"
            archive.write_bytes(self.archive)
            identity = UploadFramingTest().identity(archive) | {
                "archive-name": archive.name, "archive-sha256": self.sha256, "tag": "v1.2.3", "sha": SHA,
                "notes": "Approved notes.", "signer": "owner/repo/.github/workflows/publish.yml"}
            state = {"release": None, "puts": 0, "reads": 0, "finalizations": 0, "attestations": 0}

            def github(*args, input=None, timeout=120):
                if args[-1].startswith("repos/owner/repo/attestations/"):
                    state["attestations"] += 1
                    return [{"attestations": [] if state["attestations"] == 1 else [{"initiator": "github", "bundle": {}}]}]
                if "--slurp" in args:
                    return [[]]
                if "--method" in args and args[args.index("--method") + 1] == "POST":
                    state["release"] = json.loads(input) | {"id": 7, "assets": [],
                        "html_url": "https://github.com/owner/repo/releases/tag/v1.2.3"}
                elif "--method" in args:
                    state["finalizations"] += 1
                    state["release"].update(draft=False, immutable=True)
                return state["release"].copy()

            def command(*args, **kwargs):
                if args[1:3] == ("api", "--method"):
                    state["release"]["assets"] = [{"name": archive.name, "size": archive.stat().st_size,
                                                   "digest": "sha256:" + self.sha256}]
                if args[:3] == ("gh", "release", "verify") and state["attestations"] < 2:
                    raise subprocess.CalledProcessError(1, args,
                        stderr=f"no attestations for tag v1.2.3 (sha1:{SHA})")
                return ""

            def registry(request, timeout):
                if isinstance(request, str):
                    if request.startswith(publish_crate.CRATES):
                        raise urllib.error.HTTPError(request, 404, "absent", {}, None)
                    if request.startswith(publish_crate.INDEX):
                        state["reads"] += 1
                        version = "1.2.2" if state["reads"] == 1 else "1.2.3"
                        checksum = "b" * 64 if mismatch else self.sha256
                        return response(json.dumps(self.record | {"vers": version, "cksum": checksum}).encode())
                    return response(self.archive)
                state["puts"] += 1
                return response(b'{"warnings":{}}')

            with mock.patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "secret"}, clear=True), \
                    mock.patch.object(common, "gh_json", side_effect=github), \
                    mock.patch.object(common, "run", side_effect=command), \
                    mock.patch.object(common, "require_tag", return_value=SHA), mock.patch.object(common, "verify_attestation"), \
                    mock.patch.object(common.OPENER, "open", side_effect=registry), \
                    mock.patch.object(common.time, "monotonic", side_effect=lambda: self.elapsed), \
                    mock.patch.object(common.time, "sleep", side_effect=lambda seconds: setattr(self, "elapsed", self.elapsed + seconds)), \
                    contextlib.redirect_stderr(io.StringIO()):
                if mismatch:
                    with self.assertRaises(SystemExit):
                        publish_crate.publish(identity)
                else:
                    publish_crate.publish(identity)
            self.assertEqual(state["puts"], 1)
            self.assertEqual(state["finalizations"], 0 if mismatch else 1)
            self.assertEqual(state["release"]["draft"], mismatch)


if __name__ == "__main__":
    unittest.main()
