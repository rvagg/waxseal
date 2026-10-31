#!/usr/bin/env python3
"""npm archive, package identity and publication regressions."""

import base64
import contextlib
import gzip
import hashlib
import http.client
import importlib.util
import io
import json
import os
import pathlib
import ssl
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "publish-npm.py"
spec = importlib.util.spec_from_file_location("publish_npm", SCRIPT)
publish_npm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish_npm)
SHA = "a" * 40
ATTESTATION_NOT_FOUND = json.loads((pathlib.Path(__file__).parent / "fixtures" / "release-attestation-404.json").read_text())


def tarball(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, kind, data in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                archive.addfile(member)
    return gzip.compress(output.getvalue())


def package_archive(name, version, repository):
    manifest = json.dumps({"name": name, "version": version,
                           "repository": f"https://github.com/{repository}.git"}).encode()
    return tarball([("package/package.json", tarfile.REGTYPE, manifest)])


def raw_header(size, kind=b"0"):
    header = bytearray(512)
    header[124:136] = size
    header[156:157] = kind
    return bytes(header)


class ArchiveValidationTest(unittest.TestCase):
    identity = {"package": "example", "version": "1.2.3", "repository": "owner/repo"}

    def valid_entries(self):
        manifest = json.dumps({"name": "example", "version": "1.2.3",
                               "repository": "https://github.com/owner/repo.git"}).encode()
        return [("package/package.json", tarfile.REGTYPE, manifest)]

    def reject(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            archive = pathlib.Path(directory) / "example-1.2.3.tgz"
            archive.write_bytes(tarball(self.valid_entries() + entries))
            with self.assertRaises(SystemExit):
                publish_npm.inspect_archive(archive, self.identity)

    def reject_before_tarfile(self, data):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as raw:
            archive = pathlib.Path(directory) / "example-1.2.3.tgz"
            archive.write_bytes(data)
            with self.assertRaises(SystemExit):
                publish_npm.release_common.copy_raw_tar(archive, raw)

    def test_rejects_unsafe_alias_and_duplicate_members(self):
        for entries in (
            [("package/../other.json", tarfile.REGTYPE, b"safe")],
            [("package//other.json", tarfile.REGTYPE, b"safe")],
            [("package/duplicate.txt", tarfile.REGTYPE, b"one"),
             ("package/duplicate.txt", tarfile.REGTYPE, b"two")],
        ):
            with self.subTest(entries=entries):
                self.reject(entries)

    def test_rejects_link_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                self.reject([("package/link", kind, b"")])

    def test_rejects_oversize_pax_and_gnu_metadata_before_tarfile(self):
        for kind in (b"x", b"g", b"X", b"L", b"K"):
            with self.subTest(kind=kind):
                self.reject_before_tarfile(gzip.compress(raw_header(b"4000001\0", kind) + b"\0" * 1024))

    def test_rejects_invalid_raw_sizes_before_tarfile(self):
        for size in (b"-1\0", bytes([0x80]) + b"\0" * 11):
            with self.subTest(size=size):
                self.reject_before_tarfile(gzip.compress(raw_header(size) + b"\0" * 1024))

    def test_rejects_trailing_nonzero_and_concatenated_payload_before_tarfile(self):
        valid = tarball(self.valid_entries())
        raw = gzip.decompress(valid)
        self.reject_before_tarfile(gzip.compress(raw + b"x"))
        self.reject_before_tarfile(valid + gzip.compress(b"x"))

    def test_rejects_decompression_cap_before_payload_allocation(self):
        self.reject_before_tarfile(gzip.compress(raw_header(b"40000000000\0") + b"\0" * 1024))


class SourceBoundValidationTest(unittest.TestCase):
    def source(self, root, name="example", version="1.2.3"):
        (root / "package.json").write_text(json.dumps({
            "name": name, "version": version,
            "repository": "https://github.com/owner/repo.git",
        }))
        (root / "CHANGELOG.md").write_text("## v1.2.3\n\nRelease notes.\n")

    def environment(self):
        return {
            "GITHUB_REPOSITORY": "owner/repo", "GITHUB_SHA": SHA,
            "GITHUB_REF": "refs/tags/v1.2.3", "GITHUB_REF_TYPE": "tag",
            "GITHUB_EVENT_NAME": "push", "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
        }

    def trusted(self, root, environment=None):
        with mock.patch.dict(os.environ, environment or self.environment(), clear=True), \
             mock.patch.object(publish_npm.release_common, "run", return_value=f"{SHA}\n"):
            return publish_npm.trusted_identity(root, root)

    def test_accepts_generic_unscoped_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.source(root)
            identity = self.trusted(root)
        self.assertEqual({key: identity[key] for key in ("package", "version", "repository")},
                         {"package": "example", "version": "1.2.3", "repository": "owner/repo"})

    def test_validates_generic_unscoped_archive_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "source"
            files = pathlib.Path(temporary) / "files"
            root.mkdir()
            files.mkdir()
            self.source(root)
            (files / "example-1.2.3.tgz").write_bytes(package_archive("example", "1.2.3", "owner/repo"))
            environment = self.environment()
            environment["RUNNER_TEMP"] = temporary
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(publish_npm.release_common, "run", return_value=f"{SHA}\n"):
                identity = publish_npm.validate(root, root, files)
            self.assertEqual(identity["archive-name"], "example-1.2.3.tgz")

    def test_rejects_changed_valid_snapshot_against_attested_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "source"
            files = pathlib.Path(temporary) / "files"
            root.mkdir()
            files.mkdir()
            self.source(root)
            (files / "example-1.2.3.tgz").write_bytes(package_archive("example", "1.2.3", "owner/repo"))
            environment = self.environment() | {"RUNNER_TEMP": temporary}
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(publish_npm.release_common, "run", return_value=f"{SHA}\n"):
                identity = publish_npm.validate(root, root, files)
                manifest = json.dumps({
                    "name": "example", "version": "1.2.3",
                    "repository": "https://github.com/owner/repo.git",
                }).encode()
                identity["archive"].write_bytes(tarball([
                    ("package/package.json", tarfile.REGTYPE, manifest),
                    ("package/index.js", tarfile.REGTYPE, b"export const changed = true\n"),
                ]))
                snapshot = pathlib.Path(identity["files-directory"])
                with self.assertRaises(SystemExit):
                    publish_npm.validate_snapshot(root, root, snapshot, identity["archive-sha256"])
                changed_digest = publish_npm.release_common.hash_file(identity["archive"])
                accepted = publish_npm.validate_snapshot(root, root, snapshot, changed_digest)
                self.assertEqual(accepted["archive-sha256"], changed_digest)

    def test_resolves_setup_node_output_without_allowing_version_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = pathlib.Path(temporary) / "node" / "26.12.1" / "x64"
            node = prefix / "bin" / "node"
            npm = prefix / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
            node.parent.mkdir(parents=True)
            npm.parent.mkdir(parents=True)
            node.touch()
            npm.touch()
            with mock.patch.dict(os.environ, {
                "WAXSEAL_NODE_VERSION": "v26.12.1",
                "RUNNER_TOOL_CACHE": temporary, "RUNNER_ARCH": "X64",
            }, clear=True):
                self.assertEqual(publish_npm.node_runtime(), (node, npm))
                for version in ("v24.12.1", "../26.12.1", "26.12.1/../../bin"):
                    with self.subTest(version=version), mock.patch.dict(os.environ, {
                        "WAXSEAL_NODE_VERSION": version,
                    }):
                        with self.assertRaises(SystemExit):
                            publish_npm.node_runtime()

    def test_short_fence_cannot_expose_version_headings_inside_code(self):
        text = ("## v1.2.3\nBefore\n````markdown\n```\n"
                "## v1.2.4\nInside code\n````\nAfter code\n"
                "## v1.2.4\nOutside release\n")
        notes = publish_npm.release_common.release_notes(text, "1.2.3")
        self.assertIn("Inside code", notes)
        self.assertIn("After code", notes)
        self.assertNotIn("Outside release", notes)

    def test_rejects_foreign_workflow_identity_and_non_push_event(self):
        for changes in (
            {"GITHUB_WORKFLOW_REF": "other/repo/.github/workflows/release.yml@refs/tags/v1.2.3"},
            {"GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/release.yml@refs/heads/main"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
        ):
            environment = self.environment()
            environment.update(changes)
            with self.subTest(changes=changes), mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(SystemExit):
                    publish_npm.release_common.environment_identity()

    def test_rejects_escaping_package_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "root"
            outside = pathlib.Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)
            for directory in ("..", "/tmp", "escape"):
                with self.subTest(directory=directory):
                    with self.assertRaises(SystemExit):
                        publish_npm.release_common.package_directory(root, directory)

    def test_extracts_fenced_crlf_utf8_changelog_notes(self):
        text = ("## v1.2.3\r\n\r\nRésumé\r\n\r\n## Context\r\n\r\n"
                "```markdown\r\n## v1.2.3\r\n```\r\n\r\n## v1.2.4\r\nLater\r\n")
        notes = publish_npm.release_common.release_notes(text, "1.2.3")
        self.assertIn("Résumé", notes)
        self.assertIn("## Context", notes)
        self.assertIn("## v1.2.3", notes)

    def test_rejects_ambiguous_empty_and_prerelease_changelog_sections(self):
        for text in (
            "## v1.2.3\nFirst\n## v1.2.3\nSecond\n",
            "## v1.2.3\n## v1.2.4\nLater\n",
            "## v1.2.3-beta\nPreview\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(SystemExit):
                    publish_npm.release_common.release_notes(text, "1.2.3")

    def test_allows_only_documented_publish_configuration(self):
        publish_npm.validate_publish_config({
            "access": "public", "tag": "latest", "registry": publish_npm.REGISTRY, "provenance": True,
        })
        for config in (
            {"tag": "next"},
            {"_auth": "secret"},
            {"registry": "https://registry.example.com"},
            {"registry": f"{publish_npm.REGISTRY}/"},
        ):
            with self.subTest(config=config):
                with self.assertRaises(SystemExit):
                    publish_npm.validate_publish_config(config)

    def test_npm_environment_drops_configuration_poisoning(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token",
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY_ID": "12345",
            "GITHUB_REPOSITORY_OWNER_ID": "6789", "RUNNER_ENVIRONMENT": "github-hosted",
            "NODE_OPTIONS": "--require=/tmp/payload", "HTTPS_PROXY": "http://proxy", "SSL_CERT_FILE": "/tmp/ca",
            "GH_TOKEN": "github-token", "NPM_CONFIG__AUTH": "npm-token",
        }, clear=True):
            env = publish_npm.npm_env(pathlib.Path(temporary))
        self.assertEqual(env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"], "oidc-token")
        self.assertEqual({key: env[key] for key in (
            "GITHUB_SERVER_URL", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "RUNNER_ENVIRONMENT",
        )}, {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY_ID": "12345",
             "GITHUB_REPOSITORY_OWNER_ID": "6789", "RUNNER_ENVIRONMENT": "github-hosted"})
        for name in ("NODE_OPTIONS", "HTTPS_PROXY", "SSL_CERT_FILE", "GH_TOKEN", "NPM_CONFIG__AUTH"):
            self.assertNotIn(name, env)

    def test_rejects_artifact_identity_different_from_trusted_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "source"
            files = pathlib.Path(temporary) / "files"
            root.mkdir()
            files.mkdir()
            self.source(root)
            (files / "example-1.2.3.tgz").write_bytes(package_archive("other", "1.2.3", "owner/repo"))
            environment = self.environment()
            environment["RUNNER_TEMP"] = temporary
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(publish_npm.release_common, "run", return_value=f"{SHA}\n"):
                with self.assertRaises(SystemExit):
                    publish_npm.validate(root, root, files)

    def test_accepts_scoped_archive_with_canonical_registry_urls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "source"
            files = pathlib.Path(temporary) / "files"
            root.mkdir()
            files.mkdir()
            self.source(root, "@scope/name")
            (files / "scope-name-1.2.3.tgz").write_bytes(package_archive("@scope/name", "1.2.3", "owner/repo"))
            environment = self.environment()
            environment["RUNNER_TEMP"] = temporary
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(publish_npm.release_common, "run", return_value=f"{SHA}\n"):
                identity = publish_npm.validate(root, root, files)
            self.assertEqual(identity["archive-name"], "scope-name-1.2.3.tgz")
        self.assertEqual(publish_npm.registry_metadata_url("@scope/name", "1.2.3"),
                         "https://registry.npmjs.org/@scope%2Fname/1.2.3")
        self.assertEqual(publish_npm.registry_tarball_url("@scope/name", "1.2.3"),
                         "https://registry.npmjs.org/@scope/name/-/name-1.2.3.tgz")
        self.assertEqual(publish_npm.release_common.canonical_repository("git+ssh://git@github.com/owner/repo.git"), "owner/repo")

    def test_existing_draft_prevents_all_publication_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.tgz"
            archive.write_bytes(b"approved")
            identity = {"repository": "owner/repo", "tag": "v1.2.3", "sha": SHA,
                        "package": "example", "version": "1.2.3", "archive": archive,
                        "archive-name": archive.name, "archive-sha256": "0" * 64,
                        "notes": "Release notes."}
            state = {"draft": False, "npm": False}

            def github(*args, **kwargs):
                if "--method" in args and args[args.index("--method") + 1] == "POST":
                    state["draft"] = True
                return [[{"tag_name": "v1.2.3"}]]

            def command(*args, **kwargs):
                if args[0] == "npm":
                    state["npm"] = True
                return ""

            with mock.patch.object(publish_npm.release_common, "gh_json", side_effect=github), \
                 mock.patch.object(publish_npm.release_common, "require_tag"), \
                 mock.patch.object(publish_npm, "node_runtime", return_value=(pathlib.Path("/node"), pathlib.Path("/npm"))), \
                 mock.patch.object(publish_npm.release_common, "verify_attestation"), \
                 mock.patch.object(publish_npm.release_common, "run", side_effect=command):
                with self.assertRaises(SystemExit):
                    publish_npm.publish(identity)
            self.assertFalse(state["draft"])
            self.assertFalse(state["npm"])


class RegistryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.archive = package_archive("example", "1.2.3", "owner/repo")
        self.sha256 = hashlib.sha256(self.archive).hexdigest()
        self.metadata_url = publish_npm.registry_metadata_url("example", "1.2.3")
        self.tarball_url = publish_npm.registry_tarball_url("example", "1.2.3")

    def metadata(self, archive=None):
        data = self.archive if archive is None else archive
        return json.dumps({
            "name": "example", "version": "1.2.3",
            "dist": {"tarball": self.tarball_url,
                     "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()},
        }).encode()

    @staticmethod
    def response(data):
        response = io.BytesIO(data)
        response.headers = {"Content-Length": str(len(data))}
        return response

    def http_error(self, status, tarball=False):
        return urllib.error.HTTPError(self.tarball_url if tarball else self.metadata_url,
                                      status, "untrusted server response", {}, None)

    @contextlib.contextmanager
    def registry(self, responses):
        self.elapsed = 0
        self.messages = io.StringIO()

        def pause(seconds):
            self.elapsed += seconds

        with mock.patch.object(publish_npm.release_common.OPENER, "open", side_effect=responses) as requests, \
             mock.patch.object(publish_npm.time, "monotonic", side_effect=lambda: self.elapsed), \
             mock.patch.object(publish_npm.time, "sleep", side_effect=pause), \
             contextlib.redirect_stderr(self.messages):
            yield requests

    def verify(self):
        publish_npm.wait_for_npm("example", "1.2.3", self.sha256)

    def test_finishes_after_metadata_and_tarball_errors_without_republishing(self):
        responses = [self.http_error(429), self.http_error(503), self.response(self.metadata()),
                     self.http_error(404, tarball=True), self.response(self.metadata()),
                     self.response(self.archive)]
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "example-1.2.3.tgz"
            archive.write_bytes(self.archive)
            identity = {"repository": "owner/repo", "tag": "v1.2.3", "sha": SHA,
                        "package": "example", "version": "1.2.3", "archive": archive,
                        "archive-name": archive.name, "archive-sha256": self.sha256,
                        "notes": "Release notes."}
            state = {"npm_publications": 0, "attestations": 0, "finalizations": 0,
                     "drafts": 0, "asset_uploads": 0, "verify": 0, "verify_asset": 0}
            original_github = publish_npm.release_common.gh_json

            def github(*args, input=None, **kwargs):
                if args[-1].startswith("repos/owner/repo/attestations/"):
                    return original_github(*args, input=input, **kwargs)
                if args[-1].endswith("/git/ref/tags/v1.2.3"):
                    return {"object": {"type": "tag", "sha": "b" * 40}}
                if args[-1].endswith("/git/tags/" + "b" * 40):
                    return {"object": {"type": "commit", "sha": SHA}}
                if args[0] == "--paginate":
                    return [[]]
                if args[:2] == ("--method", "POST"):
                    state["drafts"] += 1
                    state["release"] = json.loads(input) | {
                        "id": 17, "assets": [], "immutable": False,
                        "html_url": "https://github.com/owner/repo/releases/tag/v1.2.3",
                    }
                elif args[:2] == ("--method", "PATCH"):
                    state["finalizations"] += 1
                    state["release"].update(draft=False, immutable=True)
                return state["release"]

            def command(*args, **kwargs):
                if args[:2] == ("gh", "api") and args[-1].startswith("repos/owner/repo/attestations/"):
                    state["attestations"] += 1
                    if state["attestations"] == 1 or f"/attestations/sha1:{'b' * 40}?" not in args[-1]:
                        raise subprocess.CalledProcessError(ATTESTATION_NOT_FOUND["returncode"], args,
                            output=ATTESTATION_NOT_FOUND["stdout"], stderr=ATTESTATION_NOT_FOUND["stderr"])
                    return json.dumps([{"attestations": [{"initiator": "github", "bundle": {}}]}])
                if args[:3] == ("/node", "/npm", "publish"):
                    state["npm_publications"] += 1
                elif args[:2] == ("gh", "api"):
                    state["asset_uploads"] += 1
                    state["release"]["assets"] = [{
                        "name": archive.name, "size": len(self.archive),
                        "digest": "sha256:" + self.sha256,
                    }]
                if args[:3] == ("gh", "release", "verify"):
                    state["verify"] += 1
                elif args[:3] == ("gh", "release", "verify-asset"):
                    state["verify_asset"] += 1
                if args[:3] == ("gh", "release", "verify") and state["attestations"] < 2:
                    raise subprocess.CalledProcessError(1, args,
                        stderr=f"no attestations for tag v1.2.3 (sha1:{SHA})")
                return ""

            with self.registry(responses), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(publish_npm.release_common, "gh_json", side_effect=github), \
                 mock.patch.object(publish_npm, "require_unpublished"), \
                 mock.patch.object(publish_npm, "node_runtime", return_value=(pathlib.Path("/node"), pathlib.Path("/npm"))), \
                 mock.patch.object(publish_npm.release_common, "verify_attestation"), \
                 mock.patch.object(publish_npm.release_common, "run", side_effect=command):
                publish_npm.publish(identity)
            self.assertEqual(state["npm_publications"], 1)
            self.assertEqual(state["drafts"], 1)
            self.assertEqual(state["asset_uploads"], 1)
            self.assertEqual(state["finalizations"], 1)
            self.assertFalse(state["release"]["draft"])
            self.assertTrue(state["release"]["immutable"])
            self.assertEqual((state["verify"], state["verify_asset"]), (1, 1))

    def test_recovers_from_connection_reset_and_truncated_response(self):
        truncated = self.response(self.metadata())
        truncated.read = mock.Mock(side_effect=http.client.IncompleteRead(b"partial", 100))
        with self.registry([
            urllib.error.URLError(ConnectionResetError("untrusted transport message")),
            truncated, self.response(self.metadata()), self.response(self.archive),
        ]):
            self.verify()

    def test_permanent_http_failure_is_not_retried_and_does_not_echo_response(self):
        with self.registry([self.http_error(403)]) as requests:
            with self.assertRaises(SystemExit) as failure:
                self.verify()
        self.assertEqual(requests.call_count, 1)
        self.assertIn("403", str(failure.exception))
        self.assertIn(self.metadata_url, str(failure.exception))
        self.assertNotIn("untrusted server response", str(failure.exception))
        self.assertEqual(self.elapsed, 0)

    def test_certificate_failure_is_not_retried(self):
        error = urllib.error.URLError(ssl.SSLCertVerificationError("untrusted TLS message"))
        with self.registry([error]) as requests:
            with self.assertRaises(SystemExit):
                self.verify()
        self.assertEqual(requests.call_count, 1)
        self.assertEqual(self.elapsed, 0)

    def test_persistent_transient_error_exhausts_budget_with_last_status(self):
        def unavailable(*args, **kwargs):
            raise self.http_error(503)

        with self.registry(unavailable):
            with self.assertRaises(SystemExit) as failure:
                self.verify()
        self.assertGreater(self.elapsed, 0)
        self.assertLessEqual(self.elapsed, 300)
        self.assertIn("503", str(failure.exception))
        self.assertIn(self.metadata_url, str(failure.exception))

    def test_changed_registry_bytes_are_not_retried_or_adopted(self):
        changed = b"not the attested archive"
        with self.registry([self.response(self.metadata(changed)), self.response(changed)]) as requests:
            with self.assertRaises(SystemExit):
                self.verify()
        self.assertEqual(requests.call_count, 2)
        self.assertEqual(self.elapsed, 0)

    def test_invalid_metadata_is_not_retried(self):
        with self.registry([self.response(b"not JSON")]) as requests:
            with self.assertRaises(SystemExit):
                self.verify()
        self.assertEqual(requests.call_count, 1)
        self.assertEqual(self.elapsed, 0)


if __name__ == "__main__":
    unittest.main()
