"""Reload the launchd-owned launcher without stopping its serving generation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pool_service', Path(__file__).with_name('pool-service.py'))
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class ServiceTests(unittest.TestCase):
    def invoke(self, action, root):
        with patch('sys.argv', ['pool-service.py', action, '--root', str(root),
                               '--command', str(root/'command.json')]):
            service.main()

    def test_launchd_exec_uses_stable_restart_config_across_fresh_states(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(service.os, 'execv', side_effect=SystemExit) as execute:
            root = Path(tmp)
            (root/'command.json').write_text(json.dumps(['/python', '/source/mac-pool.py']))
            with self.assertRaises(SystemExit):
                self.invoke('run', root)
            first = execute.call_args.args[1]
            with self.assertRaises(SystemExit):
                self.invoke('run', root)
            second = execute.call_args.args[1]
            self.assertEqual(first[first.index('--restart-config')+1], str(root/'restart.json'))
            self.assertEqual(second[second.index('--restart-config')+1], str(root/'restart.json'))
            self.assertNotEqual(first[first.index('--state')+1], second[second.index('--state')+1])

    def test_launchd_start_reaps_stopped_generations_before_exec(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(service.os, 'execv', side_effect=SystemExit) as execute, \
                patch('dsmack_gc.reap') as reap, patch('dsmack_gc.DSMACK', Path(tmp)/'.dsmack'):
            root = Path(tmp)
            (root/'command.json').write_text(json.dumps(['/python', '/source/mac-pool.py']))
            with self.assertRaises(SystemExit):
                self.invoke('run', root)
            reap.assert_called_once_with(root.resolve())
            execute.assert_called_once()

    def test_explicit_restart_config_is_used_by_launcher(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(service.os, 'execv', side_effect=SystemExit) as execute:
            root = Path(tmp)
            command = ['/python', '/source/mac-pool.py', '--restart-config=/releases/next.json']
            (root/'command.json').write_text(json.dumps(command))
            with self.assertRaises(SystemExit):
                self.invoke('run', root)
            self.assertEqual(execute.call_args.args[1][:-2], command)

    def test_reload_sends_hup_to_launchd_job_without_restarting_it(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(service.subprocess, 'run') as run:
            root = Path(tmp)
            (root/'command.json').write_text(json.dumps(['/python', '/source/mac-pool.py']))
            self.invoke('reload', root)
            run.assert_called_once_with(['launchctl', 'kill', 'SIGHUP',
                'gui/'+str(service.os.getuid())+'/org.dsmack.pool.staging'], check=True)


if __name__ == '__main__':
    unittest.main()
