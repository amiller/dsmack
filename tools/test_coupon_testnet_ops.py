import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import coupon_testnet_ops as ops


class RemoteBarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.value = {'state_dir': str(self.root), 'container': 'fixture-node',
            'image_digest': 'sha256:' + '1' * 64, 'volume': 'fixture-state',
            'mount_path': '/operator/fixture', 'ssh_config': str(self.root / 'ssh.conf'),
            'ssh_target': 'fixture-target', 'authority_dir': str(self.root),
            'approval_public_key': '2' * 64, 'approval_file': str(self.root / 'approval.json'),
            'config_file': str(self.root / 'config.json'), 'owner_dir': str(self.root)}
        self.calls = []
        self.metadata = {'issuing_jobs': 0, 'obligation_fingerprint': 'a' * 64,
                         'owner_expires_at_unix': 4600, 'approval_expires_at_unix': 20000}
        self.item = {'Image': self.value['image_digest'], 'State': {'Running': True, 'Paused': False},
                    'HostConfig': {'LogConfig': {'Type': 'none'}},
                    'Mounts': [{'Name': 'fixture-state', 'Destination': '/operator/fixture'}]}

    def test_exact_image_log_volume_and_no_claim_child_checked(self):
        adapter = ops.Ops(self.value)
        def remote(args, **kwargs):
            if args[1] == 'inspect': return json.dumps([self.item]).encode()
            return b'PID COMMAND\n1 MainThread\n2 python-worker\n'
        adapter.remote = remote
        self.assertTrue(adapter.inspect_container())
        for name in ('image', 'logs', 'volume'):
            with self.subTest(name=name):
                changed = json.loads(json.dumps(self.item))
                if name == 'image': changed['Image'] = 'sha256:' + '9' * 64
                elif name == 'logs': changed['HostConfig']['LogConfig']['Type'] = 'json-file'
                else: changed['Mounts'][0]['Name'] = 'other-volume'
                adapter.remote = lambda args, **kwargs: json.dumps([changed]).encode()
                with self.assertRaises(ops.Refused): adapter.inspect_container()
        adapter.remote = lambda args, **kwargs: (json.dumps([self.item]).encode() if args[1] == 'inspect'
            else b'PID COMMAND\n1 MainThread\n2 python-worker\n3 python-worker\n')
        self.assertFalse(adapter.inspect_container())

    def test_claim_racing_idle_barrier_unpauses_never_kills_or_starts(self):
        adapter = ops.Ops(self.value)
        adapter.inspect_container = lambda **kwargs: not kwargs.get('paused', False)
        adapter.metadata = lambda **kwargs: self.metadata
        adapter.remote = lambda args, **kwargs: self.calls.append(args) or b''
        # Pure fixture signing: the barrier is the behavior under test, not an
        # invented genuine approval/key. No network or provider call occurs.
        with patch.object(ops, 'load_authority', return_value=(object(), '2' * 64)), \
             patch.object(ops, 'approval', return_value={}), \
             patch.object(ops, 'configuration', return_value={}), \
             patch.object(ops, 'sign', return_value=b'{"fixture":true}'), \
             patch.object(ops, 'protected_bytes', return_value=b'{"payload":{"provider":{"session_jwt":"old"}}}'), \
             patch.object(ops, 'private_json', return_value={'session_jwt': 'new'}):
            with self.assertRaises(ops.Refused): adapter.rotate()
        self.assertEqual(self.calls, [['docker', 'pause', 'fixture-node'], ['docker', 'unpause', 'fixture-node']])
        self.assertFalse(any('kill' in args or 'start' in args for args in self.calls))

    def test_wal_store_full_fingerprint_code_prints_no_rows_or_credential(self):
        # Exercise the actual metadata program against a disposable SQLite/WAL
        # fixture; the secret canary must influence the hash but never stdout.
        import sqlite3, subprocess
        (self.root / 'state').mkdir()
        db = sqlite3.connect(self.root / 'state/state.sqlite')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE coupons(state TEXT, envelope TEXT)')
        db.execute('CREATE TABLE issuance_progress(stage TEXT)')
        db.execute('INSERT INTO coupons VALUES(?,?)', ('delivered', 'fixture-private-canary'))
        db.execute('INSERT INTO issuance_progress VALUES(?)', ('delivery_committed',)); db.commit()
        (self.root / 'config.json').write_text(json.dumps({'payload': {'provider': {'session_jwt': 'synthetic.eyJleHAiOjQ2MDB9.signature'}}}))
        (self.root / 'approval.json').write_text(json.dumps({'payload': {'expires_at': '2030-01-01T00:00:00Z'}}))
        result = subprocess.check_output([sys.executable, '-c', ops.METADATA, str(self.root)])
        self.assertNotIn(b'fixture-private-canary', result)
        first = json.loads(result)['obligation_fingerprint']
        db.execute('UPDATE issuance_progress SET stage=?', ('receipt_hash_invalid',)); db.commit()
        second = json.loads(subprocess.check_output([sys.executable, '-c', ops.METADATA, str(self.root)]))['obligation_fingerprint']
        self.assertNotEqual(first, second); db.close()


if __name__ == '__main__': unittest.main()
