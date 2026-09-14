"""Tests for the vendor runner without invoking Cargo or allocating build caches."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_vendor


class RunnerTests(unittest.TestCase):
    def run_runner(self, arguments, environment=None, failure=None):
        with patch.dict(os.environ, environment or {}, clear=True), \
                patch("sys.argv", ["test_vendor.py", *arguments]), \
                patch("test_vendor.subprocess.run", side_effect=failure) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            test_vendor.main()
            return run.call_args_list

    def test_all_defaults(self):
        calls = self.run_runner(["all", "--offline"])
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertIn("--locked", call.args[0])
            self.assertIn("--offline", call.args[0])
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["cwd"], test_vendor.ROOT)
            env = call.kwargs["env"]
            for key in ["CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL"]:
                self.assertEqual(env[key], "0")
            self.assertEqual(env["CARGO_TARGET_DIR"], str(test_vendor.ROOT / "target/vendor-tests"))
        self.assertIn("--features", calls[0].args[0])
        self.assertNotIn("--features", calls[1].args[0])

    def test_explicit_environment_and_single_suite(self):
        calls = self.run_runner(["quinn-proto"], {
            "CARGO_PROFILE_TEST_DEBUG": "2", "CARGO_TARGET_DIR": "custom-cache",
        })
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs["env"]["CARGO_PROFILE_TEST_DEBUG"], "2")
        self.assertEqual(calls[0].kwargs["env"]["CARGO_TARGET_DIR"], str(Path("custom-cache").resolve()))
        self.assertNotIn("--offline", calls[0].args[0])

    def test_dry_run_executes_nothing(self):
        self.assertEqual(self.run_runner(["--dry-run"]), [])

    def test_cargo_failure_is_not_hidden(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_runner([], failure=subprocess.CalledProcessError(101, "cargo"))


if __name__ == "__main__":
    unittest.main()
