#!/usr/bin/env python3
"""Release visibility waits remain bounded and separate from signature checks."""
import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "release_common.py"
spec = importlib.util.spec_from_file_location("release_common", SCRIPT)
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
SHA = "a" * 40
TAG_SHA = "b" * 40
IDENTITY = {"repository": "owner/repo", "sha": SHA, "tag": "v1.2.3", "archive": pathlib.Path("example.crate")}
READY = {"attestations": [{"initiator": "github", "bundle": {}}]}


class ReleaseVerificationTest(unittest.TestCase):
    @contextlib.contextmanager
    def commands(self, read, failure=None, failed_command="verify"):
        self.elapsed = 0
        self.reads = 0
        self.verifications = []

        def command(*args, **kwargs):
            if args[:2] == ("gh", "api"):
                self.reads += 1
                result = read(args[-1])
                if isinstance(result, list) and "--paginate" not in args:
                    result = result[0]
                elif isinstance(result, dict) and "--slurp" in args:
                    result = [result]
                return result if isinstance(result, str) else json.dumps(result)
            self.verifications.append(args[2])
            if args[2] == failed_command and failure is not None:
                raise failure
            return ""

        def pause(seconds):
            self.elapsed += seconds

        with mock.patch.object(common, "run", side_effect=command), \
                mock.patch.object(common.time, "monotonic", side_effect=lambda: self.elapsed), \
                mock.patch.object(common.time, "sleep", side_effect=pause), \
                contextlib.redirect_stderr(io.StringIO()):
            yield

    def test_annotated_tag_waits_for_tag_object_after_approved_commit_check(self):
        def read(endpoint):
            if "/git/ref/tags/" in endpoint:
                return {"object": {"type": "tag", "sha": TAG_SHA}}
            if endpoint.endswith("/git/tags/" + TAG_SHA):
                return {"object": {"type": "commit", "sha": SHA}}
            return READY if "/attestations/sha1:" + TAG_SHA + "?" in endpoint else {"attestations": []}
        with self.commands(read):
            tag_sha = common.require_tag("owner/repo", "v1.2.3", SHA)
            common.verify_release(IDENTITY, tag_sha)
        self.assertEqual(self.elapsed, 0)
        self.assertEqual(self.verifications, ["verify", "verify-asset"])

    def test_tag_pointing_at_an_unapproved_commit_stops_before_verification(self):
        with self.commands(lambda endpoint: {"object": {"type": "commit", "sha": TAG_SHA}}):
            with self.assertRaises(SystemExit):
                tag_sha = common.require_tag("owner/repo", "v1.2.3", SHA)
                common.verify_release(IDENTITY, tag_sha)
        self.assertEqual(self.reads, 1)
        self.assertEqual(self.verifications, [])

    def test_unavailable_attestation_exhausts_budget_and_names_manual_verification(self):
        with self.commands(lambda endpoint: {"attestations": []}):
            with self.assertRaises(SystemExit) as caught:
                common.verify_release(IDENTITY, SHA)
        self.assertEqual(self.elapsed, common.RELEASE_ATTESTATION_TIMEOUT)
        self.assertEqual(self.verifications, [])
        self.assertIn("already published", str(caught.exception))
        self.assertIn("gh release verify v1.2.3 --repo owner/repo", str(caught.exception))

    def test_record_arriving_after_deadline_cannot_succeed(self):
        def read(endpoint):
            self.elapsed += common.RELEASE_ATTESTATION_TIMEOUT
            return READY
        with self.commands(read), self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual(self.verifications, [])

    def test_permission_error_is_not_treated_as_absence(self):
        def read(endpoint):
            raise subprocess.CalledProcessError(1, ("gh", "api"), stderr="HTTP 403: forbidden")
        with self.commands(read), self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, []))

    def test_api_timeout_is_not_retried(self):
        def read(endpoint):
            raise subprocess.TimeoutExpired(("gh", "api"), 30)
        with self.commands(read), self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, []))

    def test_malformed_json_is_fatal(self):
        with self.commands(lambda endpoint: "not JSON"), self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, []))

    def test_malformed_github_record_is_fatal(self):
        with self.commands(lambda endpoint: {"attestations": [{"initiator": "github", "bundle": None}]}), \
                self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, []))

    def test_user_created_record_does_not_replace_github_release_attestation(self):
        replies = iter([{"attestations": [{"initiator": "user", "bundle": {}}]}, READY])
        with self.commands(lambda endpoint: next(replies)):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual(self.reads, 2)
        self.assertGreater(self.elapsed, 0)
        self.assertEqual(self.verifications, ["verify", "verify-asset"])

    def test_github_record_on_later_page_prevents_false_absence(self):
        pages = [{"attestations": [{"initiator": "user", "bundle": {}}] * 100}, READY]
        with self.commands(lambda endpoint: pages):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual(self.elapsed, 0)
        self.assertEqual(self.verifications, ["verify", "verify-asset"])

    def test_generic_missing_attestation_verifier_error_is_not_retried(self):
        error = subprocess.CalledProcessError(1, ("gh", "release", "verify"),
            stderr=f"no attestations for tag v1.2.3 (sha1:{SHA})")
        with self.commands(lambda endpoint: READY, failure=error), self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, ["verify"]))

    def test_asset_integrity_failure_is_fatal_after_release_verification(self):
        error = subprocess.CalledProcessError(1, ("gh", "release", "verify-asset"),
            stderr="attestation does not contain the asset digest")
        with self.commands(lambda endpoint: READY, failure=error, failed_command="verify-asset"), \
                self.assertRaises(SystemExit):
            common.verify_release(IDENTITY, SHA)
        self.assertEqual((self.reads, self.elapsed, self.verifications), (1, 0, ["verify", "verify-asset"]))


if __name__ == "__main__":
    unittest.main()
