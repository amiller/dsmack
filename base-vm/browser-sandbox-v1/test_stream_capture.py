"""Prevent accidental stdout/stderr export from sealed-output workloads."""
import pathlib, sys, unittest
from unittest.mock import Mock
sys.path[:0] = [str(pathlib.Path(__file__).parent / "source/runner-content"),
               str(pathlib.Path(__file__).parent / "source/runner-content/lib")]
from dsmack_compose_runner.lifecycle import _capture_streams, _ps_containers

class StreamCapture(unittest.TestCase):
    def test_no_capture_never_reads_task_logs(self):
        control = Mock()
        self.assertEqual(_capture_streams(control, {}, 1024, []), {})
        control.run.assert_not_called()
        control.run_capped.assert_not_called()

    def test_only_declared_stream_is_returned_and_capped(self):
        control = Mock()
        control.run_capped.return_value = (0, b"ok", b"private diagnostic", False, True)
        self.assertEqual(_capture_streams(control, {"container_name": "task"}, 1024, ["stdout"]), {"stdout": b"ok"})

    def test_ps_finds_every_service_in_compose_json_lines(self):
        control = Mock()
        control.run.return_value = (0, b'{"Service":"gateway","Name":"g"}\n{"Service":"client","Name":"c"}\n', b"")
        with unittest.mock.patch("dsmack_compose_runner.lifecycle._compose_argv", return_value=[]):
            self.assertEqual(_ps_containers(control, {"completion_service": "client"}, "p"), ({"gateway": "g", "client": "c"}, "c"))

