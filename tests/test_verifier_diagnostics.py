#!/usr/bin/env python3
"""Verifier failures retain useful output without leaking tokens or log commands."""
import importlib.util
import os
import pathlib
import subprocess
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "release_common.py"
spec = importlib.util.spec_from_file_location("release_common", SCRIPT)
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
COMMAND = ("gh", "release", "verify-asset", "v1.2.3", "example.crate", "--repo", "owner/repo")


class VerifierDiagnosticsTest(unittest.TestCase):
    def diagnostic(self, error, tokens=None):
        with mock.patch.dict(os.environ, tokens or {}, clear=True), self.assertRaises(SystemExit) as caught:
            common.fail_verifier(error)
        return str(caught.exception)

    def test_exit_failure_identifies_verifier_status_and_both_streams(self):
        message = self.diagnostic(subprocess.CalledProcessError(
            23, COMMAND, output="asset digest differs", stderr="HTTP 403: permission denied"))
        self.assertIn("gh release verify-asset", message)
        self.assertIn("exit status 23", message)
        self.assertIn("asset digest differs", message)
        self.assertIn("HTTP 403: permission denied", message)

    def test_timeout_preserves_partial_byte_output_and_invalid_utf8(self):
        message = self.diagnostic(subprocess.TimeoutExpired(
            COMMAND, 120, output=b"downloaded asset\n", stderr=b"verification stalled\xff"))
        self.assertIn("gh release verify-asset", message)
        self.assertIn("timed out after 120 seconds", message)
        self.assertIn("downloaded asset", message)
        self.assertIn("verification stalled\ufffd", message)

    def test_overlapping_token_values_are_removed_from_both_streams(self):
        tokens = {name: "fixture-token-" + name for name in (
            "GH_TOKEN", "GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN", "NODE_AUTH_TOKEN", "NPM_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN")}
        tokens["GH_TOKEN"] = "fixture-token"
        secrets = " ".join(tokens.values())
        message = self.diagnostic(subprocess.CalledProcessError(
            1, COMMAND, output=secrets, stderr=secrets), tokens)
        self.assertNotIn("fixture-token", message)
        self.assertNotIn("_REQUEST_TOKEN", message)
        self.assertIn("[REDACTED]", message)

    def test_redaction_precedes_combined_output_limit(self):
        secret = "boundary-sensitive-token"
        error = subprocess.CalledProcessError(1, COMMAND,
            stderr="x" * (common.MAX_VERIFIER_DIAGNOSTIC - len("\n[output truncated]") - 18) + secret,
            output="y" * common.MAX_VERIFIER_DIAGNOSTIC)
        message = self.diagnostic(error, {"GH_TOKEN": secret})
        self.assertNotIn("boundary-", message)
        self.assertIn("[REDACTED]", message)
        self.assertIn("[output truncated]", message)
        self.assertEqual(len(message.split("\n", 1)[1]), common.MAX_VERIFIER_DIAGNOSTIC)

    def test_captured_workflow_commands_and_terminal_controls_are_inert(self):
        hostile = ("::error::forged\n##[warning]forged\n\x1b[31mhidden\rreplaced\u202e"
                   "\nordinary text :::error title=forged :::::forged")
        message = self.diagnostic(subprocess.CalledProcessError(1, COMMAND, stderr=hostile))
        self.assertNotIn("::", message)
        self.assertNotIn("##[", message)
        for character in ("\x1b", "\r", "\u202e"):
            self.assertNotIn(character, message)
        self.assertIn(r"\:\:error\:\:", message)
        self.assertIn(r"##\[warning]", message)


if __name__ == "__main__":
    unittest.main()
