import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .peer_worker import Worker
from .spike import RedemptionError, decrypt_secret


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.path = root / 'config.json'
        self.config = {'version': 1, 'state_dir': str(root / 'state'),
            'sponsor_subject': 'peer:sponsor', 'observer_subject': 'peer:observer',
            'provider': {'mode': 'synthetic'}, 'peers': {
                'Sponsor1': {'subject': 'peer:sponsor', 'roles': ['sponsor']},
                'Recipient1': {'subject': 'peer:recipient', 'roles': ['recipient']},
                'Observer1': {'subject': 'peer:observer', 'roles': ['observer']}}}
        self.write_config()
        self.worker = Worker(self.path)

    def write_config(self):
        self.path.write_text(json.dumps(self.config))
        self.path.chmod(0o600)

    def tearDown(self):
        self.worker.close()
        self.directory.cleanup()

    def call(self, kind, peer='Sponsor1', **fields):
        return self.worker.request({'seq': 1, 'kind': kind, 'peer': peer, **fields})

    def test_protected_provision_scoped_encrypted_delivery_and_signer_restart(self):
        coupon = self.call('provision', budget=5_000_000_000, recipient_peer='Recipient1')['coupon']
        private = X25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        frame = base64.b64encode(json.dumps({'id': 'a', 'op': 'claim', 'coupon': coupon,
                                             'recipient_key': public}).encode()).decode()
        claimed = self.call('dispatch', peer='Recipient1', frame=frame)
        result = json.loads(base64.b64decode(claimed['frame']))['result']
        aad = (self.worker.store.digest(coupon) + ':' + result['key_id']).encode()
        self.assertTrue(decrypt_secret(result['envelope'], private, aad).startswith('synthetic-only-'))
        observer_key = (Path(self.config['state_dir']) / 'observer.key').read_bytes()
        self.worker.close()
        self.worker = Worker(self.path)
        self.assertEqual(self.call('dispatch', peer='Recipient1', frame=frame), claimed)
        self.assertEqual((Path(self.config['state_dir']) / 'observer.key').read_bytes(), observer_key)
        self.assertEqual(self.worker.store.db.execute("SELECT count(*) FROM synthetic_events WHERE kind='create'").fetchone()[0], 1)
        with self.assertRaises(RedemptionError):
            self.call('dispatch', peer='Unknown1', frame=frame)
        wrong = self.call('dispatch', peer='Sponsor1', frame=frame)
        self.assertFalse(json.loads(base64.b64decode(wrong['frame']))['ok'])

    def test_wire_cannot_supply_identity_or_provision(self):
        for fields in ({'principal': {}}, {'roles': ['sponsor']}, {'authenticated': True}):
            with self.assertRaises(RedemptionError):
                self.call('provision', budget=1, recipient_peer='Recipient1', **fields)
        with self.assertRaises(RedemptionError):
            self.call('provision', peer='Recipient1', budget=1, recipient_peer='Recipient1')
        with self.assertRaises(RedemptionError):
            self.call('provision', budget=1, recipient_peer='Observer1')

    def test_protected_reconciliation_inventory_never_retries(self):
        coupon = self.call('provision', budget=1, recipient_peer='Recipient1')['coupon']
        digest = self.worker.store.digest(coupon)
        self.worker.store.db.execute("UPDATE coupons SET state='issuing' WHERE digest=?", (digest,))
        result = self.call('pending')
        self.assertEqual(result, {'pending': [{'digest': digest, 'state': 'issuing'}], 'automatic_retry_allowed': False})
        self.assertNotIn(coupon, json.dumps(result))
        with self.assertRaises(RedemptionError):
            self.call('pending', peer='Recipient1')
        self.assertEqual(self.worker.store.db.execute('SELECT state FROM coupons').fetchone()[0], 'issuing')

    def test_permissions_links_and_single_worker_lock(self):
        with self.assertRaises(BlockingIOError):
            Worker(self.path)
        self.worker.close()
        self.path.chmod(0o644)
        with self.assertRaises(RedemptionError):
            Worker(self.path)
        self.path.chmod(0o600)
        linked = self.path.with_name('link.json')
        linked.symlink_to(self.path)
        with self.assertRaises(OSError):
            Worker(linked)
        lock = Path(self.config['state_dir']) / 'worker.lock'
        lock.chmod(0o644)
        with self.assertRaises(RedemptionError):
            Worker(self.path)
        lock.chmod(0o600)
        self.worker = Worker(self.path)

    def test_account_and_signer_binding_reject_silent_reconfiguration(self):
        self.worker.close()
        self.config['sponsor_subject'] = 'peer:new'
        self.write_config()
        with self.assertRaises(RedemptionError):
            Worker(self.path)
        self.config['sponsor_subject'] = 'peer:sponsor'
        self.write_config()
        key = Path(self.config['state_dir']) / 'observer.key'
        key.write_bytes(os.urandom(32))
        with self.assertRaises(RedemptionError):
            Worker(self.path)

    def test_database_larger_than_message_limit_restarts(self):
        for _ in range(200):
            self.call('provision', budget=1, recipient_peer='Recipient1')
        self.worker.store.db.execute('CREATE TABLE growth (data BLOB)')
        self.worker.store.db.execute('INSERT INTO growth VALUES (?)', (b'x' * 150_000,))
        self.worker.close()
        self.assertGreater((Path(self.config['state_dir']) / 'state.sqlite').stat().st_size, 100_000)
        self.worker = Worker(self.path)
        self.assertEqual(self.worker.store.db.execute('SELECT count(*) FROM coupons').fetchone()[0], 200)

    def test_abrupt_restart_recovers_large_uncheckpointed_wal(self):
        self.worker.close()
        process = subprocess.Popen([sys.executable, '-m', 'experiments.coupon_redemption.peer_worker',
                                    '--config', str(self.path)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(json.loads(process.stdout.readline())['ready'])
            for sequence in range(80):
                process.stdin.write(json.dumps({'seq': sequence, 'kind': 'provision', 'peer': 'Sponsor1',
                    'budget': 1, 'recipient_peer': 'Recipient1'}).encode() + b'\n')
                process.stdin.flush()
                self.assertTrue(json.loads(process.stdout.readline())['ok'])
            self.assertGreater((Path(self.config['state_dir']) / 'state.sqlite-wal').stat().st_size, 100_000)
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
        self.worker = Worker(self.path)
        self.assertEqual(self.worker.store.db.execute('SELECT count(*) FROM coupons').fetchone()[0], 80)

    def test_near_credentials_are_protected_setup_not_persisted_or_queried(self):
        self.worker.close()
        self.config['state_dir'] = str(Path(self.directory.name) / 'near-state')
        credentials = Path(self.directory.name) / 'credentials.json'
        credentials.write_text(json.dumps({'session_jwt': 'synthetic-management-only',
                                           'reporting_token': 'synthetic-reporting-only'}))
        credentials.chmod(0o600)
        self.config['provider'] = {'mode': 'near', 'workspace_id': '11111111-1111-4111-8111-111111111111',
            'organization_id': '22222222-2222-4222-8222-222222222222', 'credentials_file': str(credentials)}
        self.write_config()
        credentials.chmod(0o644)
        with self.assertRaises(RedemptionError):
            Worker(self.path)
        credentials.chmod(0o600)
        self.worker = Worker(self.path)
        self.call('provision', budget=1, recipient_peer='Recipient1')
        dump = '\n'.join(self.worker.store.db.iterdump())
        self.assertNotIn('synthetic-management-only', dump)
        self.assertNotIn('synthetic-reporting-only', dump)
        # Constructing/provisioning never performs a provider request: this
        # test has no reachable network dependency and creates no upstream key.


if __name__ == '__main__':
    unittest.main()
