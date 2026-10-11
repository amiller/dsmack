import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .async_service_v4 import AsyncCouponServiceV4, PENDING
from .service import Principal
from .spike import Store, IssuedKey


class FileProvider:
    def __init__(self, path, crash=False):
        self.path, self.crash = path, crash

    def create_key(self, _name, _budget):
        with self.path.open('a') as output:
            output.write('create\n'); output.flush(); os.fsync(output.fileno())
        if self.crash:
            os._exit(77)  # The provider performed its effect; no delivery ACK.
        return IssuedKey('synthetic-key', 'synthetic-secret')


class AsyncServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / 'state.sqlite')
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = {'peer_id': 'IssuerPeer00000001', 'policy': 'dstack-tdx-coupon-v1',
            'identity_policy_sha256': '11'*32, 'issuance_policy_sha256': '22'*32,
            'issuer_public_key_sha256': hashlib.sha256(raw).hexdigest()}
        self.gate = multiprocessing.get_context('fork').Event()
        self.provider = FileProvider(self.root / 'effects')
        self.service = self.make(lambda *_args: self.gate.wait(20))
        self.bundle = self.service.provision(Principal('operator:sponsor', frozenset({'sponsor'})),
            '5000000000', '2099-01-01T00:00:00Z')
        self.public = X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def make(self, authorize):
        return AsyncCouponServiceV4(self.store, self.provider, self.key,
            sponsor_subject='operator:sponsor', observer_subject='operator:observer',
            issuer_peer_id=self.issuer['peer_id'], provider_binding={'mode':'synthetic'},
            issuer_binding=self.issuer, issuance_authorizer=authorize, max_active_jobs=1,
            clock=lambda: datetime.now(timezone.utc))

    def request(self, op='claim', peer='UnknownPeer00001', **fields):
        request = {'id':'r','op':op,'coupon':self.bundle['coupon']}
        if op in ('claim','status'):
            request.update(recipient_key=base64.b64encode(self.public).decode(), offer_hash=self.bundle['offer_hash'])
        request.update(fields)
        return json.loads(self.service.dispatch(json.dumps(request).encode(), Principal('guest',frozenset()),
            local_peer=self.issuer['peer_id'],remote_peer=peer))

    def wait_state(self, state):
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            if self.store.db.execute('SELECT state FROM coupons').fetchone()[0] == state:
                return
            time.sleep(.02)
        self.fail('state transition deadline')

    def tearDown(self):
        self.service.close_jobs(); self.store.close(); self.temporary.cleanup()

    def test_pending_lookup_authenticates_original_winner_key_hash_then_delivery(self):
        self.assertEqual(self.request()['result'],PENDING)
        self.assertEqual(self.request('status')['result']['state'],'in_progress')
        self.assertEqual(self.request()['result'],PENDING)
        self.assertFalse(self.request(peer='UnknownPeer00002')['ok'])
        self.assertFalse(self.request('status',peer='UnknownPeer00002')['ok'])
        self.assertFalse(self.request('status',offer_hash='ff'*32)['ok'])
        self.assertFalse(self.request('status',recipient_key=base64.b64encode(bytes(32)).decode())['ok'])
        minimal=json.dumps({'id':'r','op':'status','coupon':self.bundle['coupon']}).encode()
        self.assertFalse(json.loads(self.service.dispatch(minimal,Principal('guest',frozenset()),
            local_peer=self.issuer['peer_id'],remote_peer='UnknownPeer00001'))['ok'])
        self.assertFalse((self.root/'effects').exists())
        self.gate.set(); self.wait_state('delivered')
        first=self.request()['result'];self.assertIn('envelope',first)
        self.assertEqual(self.request()['result'],first)
        self.assertEqual((self.root/'effects').read_text(),'create\n')

    def test_crash_after_committed_intent_never_resumes_job(self):
        self.assertTrue(self.request()['ok'])
        job=next(iter(self.service.jobs.values()));job.kill();job.join(3)
        self.assertEqual(self.request('status')['result']['state'],'reconciliation_required')
        self.service.close_jobs(); self.service=self.make(lambda *_: self.fail('must not resume'))
        self.assertFalse(self.request()['ok'])
        self.assertFalse((self.root/'effects').exists())

    def test_crash_after_guard_before_provider_does_not_recreate_permission(self):
        self.service.close_jobs()
        def guard(*_args):
            (self.root/'guard-consumed').write_text('consumed')
            self.gate.wait(20)
        self.service=self.make(guard)
        self.assertTrue(self.request()['ok'])
        deadline=time.monotonic()+5
        while not (self.root/'guard-consumed').exists() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue((self.root/'guard-consumed').exists())
        job=next(iter(self.service.jobs.values()));job.kill();job.join(3)
        self.service.close_jobs();self.service=self.make(lambda *_: self.fail('no receipt recovery'))
        self.assertFalse(self.request()['ok']);self.assertFalse((self.root/'effects').exists())

    def test_crash_after_provider_post_preserves_one_effect_and_bound_winner(self):
        self.service.close_jobs();self.provider=FileProvider(self.root/'effects',crash=True)
        self.service=self.make(lambda *_: None)
        self.assertTrue(self.request()['ok'])
        deadline=time.monotonic()+5
        while not (self.root/'effects').exists() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue((self.root/'effects').exists())
        for job in self.service.jobs.values():job.join(3)
        self.service.close_jobs();self.service=self.make(lambda *_: self.fail('no retry'))
        self.assertEqual(self.request('status')['result']['state'],'reconciliation_required')
        self.assertFalse(self.request()['ok']);self.assertFalse(self.request(peer='UnknownPeer00002')['ok'])
        self.assertEqual((self.root/'effects').read_text(),'create\n')

    def test_quota_denies_second_job_without_consuming_ready_coupon(self):
        self.assertTrue(self.request()['ok'])
        old=self.bundle
        self.bundle=self.service.provision(Principal('operator:sponsor',frozenset({'sponsor'})),
            '5000000000','2099-01-01T00:00:00Z')
        self.assertFalse(self.request()['ok'])
        self.assertEqual(self.request('status')['result']['state'],'ready')
        self.bundle=old


if __name__=='__main__':unittest.main()
