import base64
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .evidence import canonical as evidence_canonical, authorize_deposit_release
from .offer_v3 import offer_hash_v3, delivery_aad_v3, peer_hash, recipient_subject
from .service import DsmackCouponService, Principal
from .service_v2 import DsmackCouponServiceV2
from .service_v3 import DsmackCouponServiceV3
from .spike import Store, RedemptionError, IssuedKey, decrypt_secret
from .test_service import Provider


class ServiceV3Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'state.sqlite'
        self.store = Store(self.path)
        self.provider = Provider()
        self.signing = Ed25519PrivateKey.generate()
        self.sponsor = Principal('operator:sponsor', frozenset({'sponsor'}))
        self.observer = Principal('operator:observer', frozenset({'observer'}))
        self.now = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
        self.service = self.construct(self.store)
        self.bundle = self.service.provision(self.sponsor, '5000000000', '2026-10-10T13:00:00Z')
        self.coupon = self.bundle['coupon']
        self.private = X25519PrivateKey.generate()
        self.public_bytes = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = base64.b64encode(self.public_bytes).decode()

    def construct(self, store):
        return DsmackCouponServiceV3(store, self.provider, self.signing,
            sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject,
            issuer_peer_id='Issuer1', provider_binding={'mode': 'synthetic'}, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def request(self, op, peer='PeerA', principal=None, service=None, **fields):
        request = {'id': 'a', 'op': op, 'coupon': self.coupon, **fields}
        principal = principal or Principal(recipient_subject(peer), frozenset())
        return json.loads((service or self.service).dispatch(json.dumps(request).encode(), principal,
            local_peer='Issuer1', remote_peer=peer))

    def claim(self, peer='PeerA', public=None, service=None, **fields):
        return self.request('claim', peer, service=service, recipient_key=public or self.public,
                            offer_hash=self.bundle['offer_hash'], **fields)

    def test_unclaimed_offer_and_status_need_only_authenticated_peer_and_token(self):
        self.assertNotIn('recipient_subject', self.bundle['offer'])
        self.assertEqual(self.bundle['offer']['claim_policy'], 'first-authenticated-bearer')
        self.assertEqual(offer_hash_v3(self.bundle['offer']), self.bundle['offer_hash'])
        for peer in ('PeerA', 'PeerB'):
            self.assertEqual(self.request('offer', peer)['result']['offer_hash'], self.bundle['offer_hash'])
            self.assertEqual(self.request('status', peer)['result']['state'], 'ready')
        for field in ('peer', 'principal', 'roles', 'claim_policy', 'offer', 'provider'):
            frame = {'id': 'a', 'op': 'claim', 'coupon': self.coupon, 'recipient_key': self.public,
                     'offer_hash': self.bundle['offer_hash'], field: 'caller-controlled'}
            response = self.service.dispatch(json.dumps(frame).encode(), Principal('guest', frozenset()),
                                             local_peer='Issuer1', remote_peer='PeerA')
            self.assertFalse(json.loads(response)['ok'])
        self.assertEqual(self.provider.creates, 0)

    def test_shared_v3_offer_and_peer_bound_aad_vector(self):
        vector = json.loads((Path(__file__).parent / 'fixtures' / 'offer-v3.json').read_text())
        self.assertEqual(offer_hash_v3(vector['offer']), vector['offer_hash'])
        self.assertEqual(peer_hash(vector['recipient_peer']), vector['recipient_peer_sha256'])
        self.assertEqual(delivery_aad_v3(vector['offer']['coupon_digest'], vector['provider_key_id'],
            base64.b64decode(vector['recipient_public_key']), vector['offer_hash'], vector['recipient_peer']).decode(),
            vector['aad_utf8'])

    def test_atomic_claim_has_one_winner_before_provider_and_no_loser_retrieval(self):
        barrier = threading.Barrier(2)
        release = threading.Event()
        entered = threading.Event()
        calls = []
        def create(name, budget):
            with sqlite3.connect(self.path) as check:
                row = check.execute('SELECT c.state,c.recipient,g.recipient,w.peer,w.delivery_key,w.offer_hash '
                    'FROM coupons c JOIN service_grants g USING(digest) JOIN service_v3_claims w USING(digest)').fetchone()
            self.assertEqual(row[0], 'issuing')
            self.assertEqual(row[1], row[4])
            self.assertEqual(row[2], recipient_subject(row[3]))
            self.assertEqual(row[5], self.bundle['offer_hash'])
            calls.append(row[3])
            entered.set()
            self.assertTrue(release.wait(5))
            return IssuedKey('key1', 'synthetic-secret')
        self.provider.create_key = create
        def compete(peer):
            store = Store(self.path)
            try:
                service = self.construct(store)
                barrier.wait(timeout=5)
                return peer, self.claim(peer, service=service)
            finally:
                store.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(compete, peer) for peer in ('PeerA', 'PeerB')]
            try:
                done, _ = wait(futures, timeout=3, return_when=FIRST_COMPLETED)
                self.assertEqual(len(done), 1)
                self.assertFalse(next(iter(done)).result()[1]['ok'])
                self.assertTrue(entered.wait(3), "winning provider call must begin before inspecting its fixture")
                self.assertEqual(len(calls), 1)
                self.assertEqual(self.request('status', calls[0])['result']['state'], 'reconciliation_required')
            finally:
                release.set()
            results = [future.result(timeout=5) for future in futures]
        winner, result = next(item for item in results if item[1]['ok'])
        loser = 'PeerB' if winner == 'PeerA' else 'PeerA'
        self.assertEqual(self.claim(winner), result)
        for op in ('offer', 'status'):
            self.assertFalse(self.request(op, loser)['ok'])
            self.assertTrue(self.request(op, 'OperatorSponsor', self.sponsor)['ok'])
            self.assertTrue(self.request(op, 'OperatorObserver', self.observer)['ok'])
        self.assertFalse(self.claim(loser)['ok'])
        self.assertEqual(len(calls), 1)
        delivered = result['result']
        aad = delivery_aad_v3(Store.digest(self.coupon), delivered['key_id'], self.public_bytes,
                              self.bundle['offer_hash'], winner)
        self.assertEqual(decrypt_secret(delivered['envelope'], self.private, aad), 'synthetic-secret')

    def test_winner_peer_key_and_hash_replay_binding_survives_restart_and_expiry(self):
        first = self.claim()
        self.assertTrue(first['ok'])
        self.now += timedelta(days=1)
        self.store.close()
        self.store = Store(self.path)
        self.service = self.construct(self.store)
        self.assertEqual(self.claim(), first)
        self.assertEqual(self.request('offer')['result']['offer_hash'], self.bundle['offer_hash'])
        self.assertTrue(self.request('status')['result']['claim_expired'])
        self.assertFalse(self.claim('PeerB')['ok'])
        self.assertFalse(self.claim(public=base64.b64encode(b'\x09' * 32).decode())['ok'])
        self.assertFalse(self.request('claim', recipient_key=self.public, offer_hash='ab' * 32)['ok'])
        self.assertEqual(self.provider.creates, 1)
        delivered = first['result']
        wrong = delivery_aad_v3(Store.digest(self.coupon), delivered['key_id'], self.public_bytes,
                               self.bundle['offer_hash'], 'PeerB')
        with self.assertRaises(RedemptionError):
            decrypt_secret(delivered['envelope'], self.private, wrong)

    def test_expired_wrong_hash_and_invalid_key_never_record_winner(self):
        self.assertFalse(self.request('claim', recipient_key=self.public, offer_hash='ab' * 32)['ok'])
        self.assertFalse(self.claim(public=base64.b64encode(b'\0' * 32).decode())['ok'])
        self.now = datetime(2026, 10, 10, 13, tzinfo=timezone.utc)
        self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM service_v3_claims').fetchone()[0], 0)
        self.assertEqual(self.store.db.execute('SELECT state,recipient FROM coupons').fetchone()[0], 'ready')
        self.assertEqual(self.provider.creates, 0)

    def test_expiry_is_rechecked_inside_atomic_guard(self):
        original = self.store.redeem
        def advance(*args, **kwargs):
            self.now = datetime(2026, 10, 10, 13, tzinfo=timezone.utc)
            return original(*args, **kwargs)
        self.store.redeem = advance
        self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM service_v3_claims').fetchone()[0], 0)
        self.assertEqual(self.provider.creates, 0)

    def test_guard_write_failure_rolls_back_winner_grant_and_intent(self):
        original = self.store.redeem
        def fail_intent(*args, **kwargs):
            guard = kwargs['claim_guard']
            def fail_after_bind(row):
                guard(row)
                raise RuntimeError('synthetic failure before intent commit')
            kwargs['claim_guard'] = fail_after_bind
            return original(*args, **kwargs)
        self.store.redeem = fail_intent
        self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM service_v3_claims').fetchone()[0], 0)
        row = self.store.db.execute('SELECT state,recipient FROM coupons').fetchone()
        self.assertEqual(tuple(row), ('ready', None))
        self.assertEqual(self.store.db.execute('SELECT recipient FROM service_grants').fetchone()[0],
                         'unbound:' + Store.digest(self.coupon))
        self.assertEqual(self.provider.creates, 0)

    def test_ambiguous_creation_and_process_death_keep_winner_without_retry(self):
        self.provider.fail = True
        self.assertFalse(self.claim()['ok'])
        self.assertFalse(self.claim()['ok'])
        self.assertFalse(self.claim('PeerB')['ok'])
        self.assertEqual(self.provider.creates, 1)
        self.assertEqual(self.request('status')['result']['state'], 'reconciliation_required')
        self.assertFalse(self.request('status', 'PeerB')['ok'])
        self.store.close()
        self.store = Store(self.path)
        self.service = self.construct(self.store)
        self.provider.fail = False
        self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.provider.creates, 1)

    def test_crash_after_intent_is_durable_and_never_rebinds(self):
        def crash(name, budget):
            self.provider.creates += 1
            raise SystemExit('simulated process death')
        self.provider.create_key = crash
        with self.assertRaises(SystemExit):
            self.claim()
        self.assertEqual(self.store.db.execute('SELECT state FROM coupons').fetchone()[0], 'issuing')
        self.store.close()
        self.store = Store(self.path)
        self.service = self.construct(self.store)
        self.assertFalse(self.claim()['ok'])
        self.assertFalse(self.claim('PeerB')['ok'])
        self.assertEqual(self.provider.creates, 1)

    def test_crash_after_provider_success_preserves_winner_without_plaintext(self):
        with patch('experiments.coupon_redemption.spike.encrypt_secret', side_effect=SystemExit('process death')):
            with self.assertRaises(SystemExit):
                self.claim()
        self.assertEqual(self.provider.creates, 1)
        row = self.store.db.execute('SELECT state,recipient,envelope FROM coupons').fetchone()
        self.assertEqual(tuple(row), ('issuing', self.public_bytes, None))
        self.assertEqual(self.store.db.execute('SELECT peer FROM service_v3_claims').fetchone()[0], 'PeerA')
        self.store.close()
        self.store = Store(self.path)
        self.service = self.construct(self.store)
        self.assertFalse(self.claim()['ok'])
        self.assertFalse(self.claim('PeerB')['ok'])
        self.assertFalse(self.request('status', 'PeerB')['ok'])
        self.assertEqual(self.provider.creates, 1)
        self.assertNotIn('synthetic-secret', '\n'.join(self.store.db.iterdump()))

    def test_cross_protocol_bypass_and_unknown_observer_authority_fail(self):
        v1 = DsmackCouponService(self.store, self.provider, self.signing,
            sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject)
        v2 = DsmackCouponServiceV2(self.store, self.provider, self.signing,
            sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject,
            issuer_peer_id='Issuer1', provider_binding={'mode': 'synthetic'})
        claim = {'id': 'a', 'op': 'claim', 'coupon': self.coupon, 'recipient_key': self.public}
        recipient = Principal('recipient:old', frozenset({'recipient'}))
        self.assertFalse(json.loads(v1.dispatch(json.dumps(claim).encode(), recipient))['ok'])
        self.assertFalse(json.loads(v2.dispatch(json.dumps({**claim, 'offer_hash': self.bundle['offer_hash']}).encode(),
                                                recipient, local_peer='Issuer1'))['ok'])
        old1 = v1.provision(self.sponsor, 1, recipient.subject)
        old2 = v2.provision(self.sponsor, '1', recipient.subject, '2026-10-10T13:00:00Z')
        for coupon in (old1, old2['coupon']):
            self.assertFalse(self.claim(coupon=coupon)['ok'])
        self.claim()
        fields = {'start': '2026-10-10T00:00:00Z', 'end': '2026-10-11T00:00:00Z', 'challenge': 'ab' * 32}
        self.assertFalse(self.request('observe', **fields)['ok'])
        self.assertFalse(self.request('observe', 'PeerB', **fields)['ok'])
        observed = self.request('observe', 'OperatorObserver', self.observer, **fields)['result']
        self.signing.public_key().verify(base64.b64decode(observed['signature']), evidence_canonical(observed['payload']))
        self.assertEqual(observed['payload']['domain'], 'dsmack-coupon-observation-v3')
        self.assertEqual(observed['payload']['recipient_peer_sha256'], peer_hash('PeerA'))
        self.assertEqual(observed['payload']['offer_hash'], self.bundle['offer_hash'])
        self.assertEqual(observed['payload']['recipient_sha256'], hashlib.sha256(self.public_bytes).hexdigest())
        with self.assertRaises(RedemptionError):
            authorize_deposit_release(observed)
        self.assertEqual(self.provider.reads, 1)


if __name__ == '__main__':
    unittest.main()
