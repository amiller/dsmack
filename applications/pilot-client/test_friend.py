import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('friend', Path(__file__).with_name('friend.py'))
friend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(friend)


class InvitationControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.dsmack-friend-control-', dir=Path.home())
        self.root = Path(self.temp.name)
        self.native = 'a' * 32
        self.profile = 'bounty-board-search-primary-review-v1'
        self.install = self.root / 'install'
        self.runs = self.root / 'runs'
        self.install.mkdir(mode=0o700)
        self.runs.mkdir(mode=0o700)
        closure = self.write('closure.json', {'attempt_id': self.native})
        self.task = {'schema': 'dsmack-alpha-local-task/2', 'profile_id': self.profile,
                     'closure_context': closure}
        for role in ('checker_context', 'challenge', 'key_id', 'workload_disk',
                     'workload_admission', 'workload_signature'):
            self.task[role] = self.write(role + '.json', {})
        self.value = {'schema': 'dsmack-friend-invitation/1', 'native_execution_id': self.native,
                      'profile_id': self.profile, 'install_root': str(self.install),
                      'run_parent': str(self.runs), 'task': self.write('task.json', self.task)}
        for role in ('bootstrap', 'inventory', 'signature'):
            self.value[role] = self.write(role + '.json', {})

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def parse(self):
        d = self.write('invitation.json', self.value)
        return friend.invitation(d['path'], d['sha256'])

    def test_valid_metadata_never_dispatches(self):
        with patch.object(friend.subprocess, 'run', side_effect=AssertionError('dispatch forbidden')):
            value, task = self.parse()
        self.assertEqual(value['native_execution_id'], self.native)
        self.assertEqual(task['schema'], 'dsmack-alpha-local-task/2')

    def test_packet_digest_mismatch_refuses(self):
        d = self.write('invitation.json', self.value)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            friend.invitation(d['path'], '0' * 64)

    def test_changed_selected_task_refuses(self):
        Path(self.value['task']['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError, 'selected file changed'):
            self.parse()

    def test_private_task_refuses_without_reading_credential(self):
        self.task['private_input_path'] = '/never/read/credentials'
        self.value['task'] = self.write('task.json', self.task)
        with self.assertRaisesRegex(ValueError, 'credential-free task/2'):
            self.parse()

    def test_native_identity_mismatch_refuses(self):
        self.value['native_execution_id'] = 'b' * 32
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            self.parse()

    def test_symlink_and_parent_traversal_refuse(self):
        target = Path(self.value['task']['path'])
        link = self.root / 'alias.json'
        link.symlink_to(target)
        self.value['task']['path'] = str(link)
        with self.assertRaisesRegex(ValueError, 'unprotected local path'):
            self.parse()
        with self.assertRaisesRegex(ValueError, 'canonical absolute'):
            friend.protected(str(self.root / 'install' / '..' / 'task.json'))

    def test_unsupported_profile_and_command_refuse(self):
        self.value['profile_id'] = 'bounty-board-search-generate-v1'
        with self.assertRaisesRegex(ValueError, 'credential-free starter'):
            self.parse()
        with self.assertRaisesRegex(ValueError, 'unsupported command'):
            friend.argv('enroll', {}, Path('/never/execute'))

    def test_dispatch_uses_existing_closed_interface(self):
        value, _ = self.parse()
        entry = self.install / 'alpha_coordinator.py'
        run = friend.argv('run', value, entry)
        check = friend.argv('check', value, entry)
        self.assertEqual(run[1:5], ['-I', '-B', str(entry), '--execute'])
        self.assertIn('--check-only', check)
        self.assertEqual(run[-1], str(self.runs / ('attempt-' + self.native + '.control') / 'plan.json'))


if __name__ == '__main__':
    unittest.main()
