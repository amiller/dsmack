"""A failed or cancelled workload must make `dsmack-compose-runner run` exit nonzero."""
import pathlib, sys, unittest
from unittest.mock import patch
sys.path[:0] = [str(pathlib.Path(__file__).parent / "source/runner-content"),
               str(pathlib.Path(__file__).parent / "source/runner-content/lib")]
from dsmack_compose_runner import cli

class RunnerExit(unittest.TestCase):
    def run_with_status(self, status, exit_code):
        argv = ["run", __file__, "--run-id", "r", "--daemon-endpoint", "unix:///x", "--workspace-root", "/w",
                "--control-dir", "/c", "--base-bundle", "/b", "--admission", "/a"]
        with patch.object(cli, "validate_manifest_bytes"), \
             patch.object(cli, "run_manifest", return_value=({}, {"status": status, "exit_code": exit_code})):
            return cli.main(argv)

    def test_completed_exits_zero(self):
        self.assertEqual(self.run_with_status("completed", 0), 0)

    def test_failed_exits_nonzero(self):
        self.assertEqual(self.run_with_status("failed", 1), 1)

    def test_failed_with_zero_exit_code_exits_nonzero(self):
        self.assertEqual(self.run_with_status("failed", 0), 1)

    def test_cancelled_exits_nonzero(self):
        self.assertEqual(self.run_with_status("cancelled", None), 1)
