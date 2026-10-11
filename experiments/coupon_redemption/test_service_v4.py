import base64
import copy
import hashlib
import json
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .offer_v4 import offer_hash_v4, delivery_aad_v4, peer_hash
from .service import Principal
from .service_v3 import DsmackCouponServiceV3
from .service_v4 import DsmackCouponServiceV4
from .spike import Store, RedemptionError, decrypt_secret
from .test_service import Provider
from .evidence import authorize_deposit_release


class ServiceV4Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'state.sqlite')
        self.provider = Provider()
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = {'peer_id': 'IssuerPeer00000001', 'policy': 'dstack-tdx-coupon-v1',
            'identity_policy_sha256': '11' * 32, 'issuance_policy_sha256': '22' * 32,
            'issuer_public_key_sha256': hashlib.sha256(public).hexdigest()}
        self.sponsor = Principal('operator:sponsor', frozenset({'sponsor'}))
        self.now = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
        self.authorizations = []
        self.service = self.construct(authorizer=self.authorizations.append)
        self.bundle = self.service.provision(self.sponsor, '5000000000', '2026-10-10T13:00:00Z')
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def construct(self, *, authorizer=None, issuer=None, store=None):
        store = store or self.store
        def authorize(*args):
            self.assertEqual(store.db.execute('SELECT state FROM coupons WHERE digest=?', (args[0],)).fetchone()[0], 'issuing')
            authorizer(args)
        return DsmackCouponServiceV4(store, self.provider, self.key,
            sponsor_subject=self.sponsor.subject, observer_subject='operator:observer',
            issuer_peer_id=self.issuer['peer_id'], provider_binding={'mode': 'synthetic'},
            issuer_binding=issuer or self.issuer, issuance_authorizer=authorize if authorizer else None,
            clock=lambda: self.now)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def request(self, op='claim', peer='PeerA', service=None, **fields):
        frame = {'id': 'r', 'op': op, 'coupon': self.bundle['coupon'], **fields}
        if op == 'claim':
            frame.setdefault('recipient_key', base64.b64encode(self.public).decode())
            frame.setdefault('offer_hash', self.bundle['offer_hash'])
        return json.loads((service or self.service).dispatch(json.dumps(frame).encode(),
            Principal('guest', frozenset()), local_peer=self.issuer['peer_id'], remote_peer=peer))

    def test_shared_offer_and_aad_vector(self):
        vector = json.loads((Path(__file__).parent / 'fixtures' / 'offer-v4.json').read_text())
        self.assertEqual(offer_hash_v4(vector['offer']), vector['offer_hash'])
        self.assertEqual(peer_hash(vector['recipient_peer']), vector['recipient_peer_sha256'])
        self.assertEqual(delivery_aad_v4(vector['offer']['coupon_digest'], vector['provider_key_id'],
            base64.b64decode(vector['recipient_public_key']), vector['offer_hash'], vector['recipient_peer']).decode(), vector['aad_utf8'])

    def test_policy_hash_alone_never_authorizes_provider_creation(self):
        denied = self.construct()
        self.assertFalse(self.request(service=denied)['ok'])
        self.assertEqual(self.provider.creates, 0)
        self.assertEqual(self.request('status')['result']['state'], 'reconciliation_required')
        self.assertFalse(self.request()['ok'])
        self.assertEqual(self.authorizations, [])

    def test_delivery_binds_exact_policies_key_and_actual_winner(self):
        first = self.request()
        self.assertTrue(first['ok'])
        self.assertEqual(len(self.authorizations), 1)
        self.assertEqual(self.authorizations[0][4], self.issuer)
        aad = delivery_aad_v4(Store.digest(self.bundle['coupon']), first['result']['key_id'], self.public,
                              self.bundle['offer_hash'], 'PeerA')
        self.assertEqual(decrypt_secret(first['result']['envelope'], self.private, aad), 'synthetic-secret')
        self.assertEqual(json.loads(aad)['recipient_peer_sha256'], peer_hash('PeerA'))
        self.now = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
        self.assertEqual(self.request(service=self.construct()), first)
        self.assertEqual(self.provider.creates, 1)
        self.assertFalse(self.request(peer='PeerB')['ok'])
        self.assertFalse(self.request('offer', peer='PeerB')['ok'])

    def test_each_issuer_offer_tamper_changes_hash_before_effects(self):
        for field in ('identity_policy_sha256', 'issuance_policy_sha256', 'issuer_public_key_sha256', 'peer_id'):
            offer = copy.deepcopy(self.bundle['offer'])
            offer['issuer'][field] = 'OtherIssuer000001' if field == 'peer_id' else 'ab' * 32
            altered = offer_hash_v4(offer)
            self.assertNotEqual(altered, self.bundle['offer_hash'])
            self.assertFalse(self.request(offer_hash=altered)['ok'])
        for field in ('extra', 'policy'):
            offer = copy.deepcopy(self.bundle['offer'])
            offer['issuer'][field] = 'unreviewed'
            with self.assertRaises(RedemptionError):
                offer_hash_v4(offer)
        self.assertEqual(self.provider.creates, 0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM service_v4_claims').fetchone()[0], 0)

    def test_two_store_connections_race_with_only_one_authorization_and_create(self):
        barrier = threading.Barrier(2)
        def compete(peer):
            store = Store(Path(self.directory.name) / 'state.sqlite')
            try:
                service = self.construct(store=store, authorizer=self.authorizations.append)
                barrier.wait(5)
                return peer, self.request(peer=peer, service=service)
            finally:
                store.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(compete, ('PeerA', 'PeerB')))
        self.assertEqual(sum(result['ok'] for peer, result in results), 1)
        self.assertEqual(len(self.authorizations), 1)
        self.assertEqual(self.provider.creates, 1)
        winner = next(peer for peer, result in results if result['ok'])
        self.assertEqual(self.authorizations[0][1], winner)
        self.assertEqual(self.store.db.execute('SELECT peer FROM service_v4_claims').fetchone()[0], winner)

    def test_initial_expiry_and_wrong_local_peer_are_denied_before_authority(self):
        frame = {'id': 'a', 'op': 'claim', 'coupon': self.bundle['coupon'],
                 'recipient_key': base64.b64encode(self.public).decode(), 'offer_hash': self.bundle['offer_hash']}
        rejected = self.service.dispatch(json.dumps(frame).encode(), Principal('guest', frozenset()),
                                         local_peer='OtherIssuer000001', remote_peer='PeerA')
        self.assertFalse(json.loads(rejected)['ok'])
        self.now = datetime(2026, 10, 10, 13, tzinfo=timezone.utc)
        self.assertFalse(self.request()['ok'])
        self.assertEqual(self.store.db.execute('SELECT state FROM coupons').fetchone()[0], 'ready')
        self.assertEqual(self.authorizations, [])
        self.assertEqual(self.provider.creates, 0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM service_v4_claims').fetchone()[0], 0)

    def test_signer_policy_and_protocol_replacement_cannot_reinterpret_state(self):
        altered = {**self.issuer, 'issuance_policy_sha256': 'ab' * 32}
        with self.assertRaises(RedemptionError):
            self.construct(issuer=altered)
        with self.assertRaises(RedemptionError):
            self.construct(issuer={**self.issuer, 'issuer_public_key_sha256': 'ab' * 32})
        old = DsmackCouponServiceV3(self.store, self.provider, self.key,
            sponsor_subject=self.sponsor.subject, observer_subject='operator:observer',
            issuer_peer_id=self.issuer['peer_id'], provider_binding={'mode': 'synthetic'})
        self.assertFalse(self.request(service=old)['ok'])
        coupon = old.provision(self.sponsor, '1', '2026-10-10T13:00:00Z')['coupon']
        self.assertFalse(self.request(coupon=coupon)['ok'])

    def test_v4_observation_is_bound_but_cannot_release_deposit(self):
        self.request()
        observer = Principal('operator:observer', frozenset({'observer'}))
        frame = {'id': 'r', 'op': 'observe', 'coupon': self.bundle['coupon'],
                 'start': '2026-10-10T00:00:00Z', 'end': '2026-10-11T00:00:00Z', 'challenge': 'ab' * 32}
        result = json.loads(self.service.dispatch(json.dumps(frame).encode(), observer,
            local_peer=self.issuer['peer_id'], remote_peer='ObserverPeer'))['result']
        self.assertEqual(result['payload']['version'], 4)
        self.assertEqual(result['payload']['environment'], 'local-unattested')
        self.assertEqual(result['payload']['recipient_peer_sha256'], peer_hash('PeerA'))
        self.assertEqual(result['payload']['offer_hash'], self.bundle['offer_hash'])
        with self.assertRaises(RedemptionError):
            authorize_deposit_release(result)


if __name__ == '__main__':
    unittest.main()
