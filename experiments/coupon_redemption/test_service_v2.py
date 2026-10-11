import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .evidence import canonical as evidence_canonical, authorize_deposit_release
from .offer_v2 import OFFER_DOMAIN, amount, canonical, delivery_aad, offer_hash, validate_offer
from .service import DsmackCouponService, Principal
from .service_v2 import DsmackCouponServiceV2
from .spike import Store, RedemptionError, decrypt_secret, IssuedKey, MAX_PROVIDER_SECRET_BYTES
from .test_service import Provider


class ServiceV2Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'state.sqlite'
        self.store = Store(self.path)
        self.provider = Provider()
        self.signing = Ed25519PrivateKey.generate()
        self.sponsor = Principal('peer:sponsor', frozenset({'sponsor'}))
        self.recipient = Principal('peer:recipient', frozenset({'recipient'}))
        self.observer = Principal('peer:observer', frozenset({'observer'}))
        self.now = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
        self.construct()
        self.bundle = self.service.provision(self.sponsor, '5000000000', self.recipient.subject, '2026-10-10T13:00:00Z')
        self.coupon = self.bundle['coupon']
        self.private = X25519PrivateKey.generate()
        self.public_bytes = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = base64.b64encode(self.public_bytes).decode()

    def construct(self):
        self.service = DsmackCouponServiceV2(self.store, self.provider, self.signing,
            sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject,
            issuer_peer_id='Issuer1', provider_binding={'mode': 'synthetic'}, clock=lambda: self.now)
        self.v1 = DsmackCouponService(self.store, self.provider, self.signing,
            sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def request(self, op, principal=None, local_peer='Issuer1', **fields):
        request = {'id': 'a', 'op': op, 'coupon': self.coupon, **fields}
        return json.loads(self.service.dispatch(json.dumps(request).encode(),
            self.recipient if principal is None else principal, local_peer=local_peer))

    def claim(self, **fields):
        return self.request('claim', recipient_key=self.public,
                            offer_hash=self.bundle['offer_hash'], **fields)

    def test_exact_schema_ascii_decimal_and_canonical_hash(self):
        offer = self.bundle['offer']
        self.assertEqual(offer_hash(offer), self.bundle['offer_hash'])
        reordered = dict(reversed(list(offer.items())))
        self.assertEqual(offer_hash(reordered), offer_hash(offer))
        self.assertEqual(amount('9223372036854775807'), 2**63 - 1)
        for value in ['0', '01', '-1', '1.0', '1e3', '9223372036854775808', '9' * 20, 5, True]:
            with self.assertRaises(RedemptionError):
                amount(value)
        for changed in ({**offer, 'extra': True}, {k: v for k, v in offer.items() if k != 'version'},
                        {**offer, 'version': True}, {**offer, 'recipient_subject': 'peer:récipient'},
                        {**offer, 'claim_expires_at': '２０２６-10-10T13:00:00Z'},
                        {**offer, 'provider_expires_at': '2026-10-10T13:00:00Z'}):
            with self.assertRaises((RedemptionError, ValueError)):
                validate_offer(changed)

    def test_shared_synthetic_hash_and_delivery_aad_vector(self):
        vector = json.loads((Path(__file__).parent / 'fixtures' / 'offer-v2.json').read_text())
        self.assertEqual(vector['mode'], 'synthetic-contract-vector')
        self.assertEqual(offer_hash(vector['offer']), vector['offer_hash'])
        self.assertEqual(delivery_aad(Store.digest(vector['coupon']), vector['provider_key_id'],
            base64.b64decode(vector['recipient_public_key']), vector['offer_hash']).decode(), vector['aad_utf8'])

    def test_offer_semantic_tampering_changes_hash_and_fails_before_creation(self):
        mutations = [('budget_nano_usd', '6000000000'), ('issuer.peer_id', 'OtherIssuer1'),
            ('issuer.policy', 'claimed-attested'), ('provider.id', 'near'),
            ('provider.scope_commitment', 'cd' * 32), ('recipient_subject', 'peer:other'),
            ('cap_semantics', 'guaranteed-credit'), ('claim_expires_at', '2026-10-11T13:00:00Z'),
            ('sponsor_powers', []), ('delivery_profile', 'persistent-plaintext')]
        for field, value in mutations:
            changed = copy.deepcopy(self.bundle['offer'])
            parts = field.split('.')
            target = changed if len(parts) == 1 else changed[parts[0]]
            target[parts[-1]] = value
            forged_hash = hashlib.sha256(OFFER_DOMAIN + canonical(changed)).hexdigest()
            self.assertNotEqual(forged_hash, self.bundle['offer_hash'])
            self.assertFalse(self.request('claim', recipient_key=self.public, offer_hash=forged_hash)['ok'])
        self.assertEqual(self.provider.creates, 0)
        self.assertEqual(self.request('status')['result']['state'], 'ready')

    def test_delivery_aad_binds_offer_coupon_key_and_recipient(self):
        response = self.claim()
        self.assertTrue(response['ok'])
        result = response['result']
        aad = delivery_aad(Store.digest(self.coupon), result['key_id'], self.public_bytes, self.bundle['offer_hash'])
        self.assertEqual(decrypt_secret(result['envelope'], self.private, aad), 'synthetic-secret')
        for wrong in [delivery_aad('ef' * 32, result['key_id'], self.public_bytes, self.bundle['offer_hash']),
            delivery_aad(Store.digest(self.coupon), 'wrongkey', self.public_bytes, self.bundle['offer_hash']),
            delivery_aad(Store.digest(self.coupon), result['key_id'], b'x' * 32, self.bundle['offer_hash']),
            delivery_aad(Store.digest(self.coupon), result['key_id'], self.public_bytes, 'aa' * 32)]:
            with self.assertRaises(RedemptionError):
                decrypt_secret(result['envelope'], self.private, wrong)
        self.assertEqual(json.loads(result['envelope'])['version'], 1)
        self.assertEqual(json.loads(aad)['version'], 2)

    def test_expiry_blocks_only_new_creation_and_delivered_replay_survives_restart(self):
        first = self.claim()
        salt = self.store.db.execute('SELECT salt FROM service_v2_identity').fetchone()[0]
        self.now += timedelta(days=1)
        self.store.close()
        self.store = Store(self.path)
        self.construct()
        self.assertEqual(self.claim(), first)
        self.assertEqual(self.request('offer')['result']['offer_hash'], self.bundle['offer_hash'])
        self.assertEqual(self.store.db.execute('SELECT salt FROM service_v2_identity').fetchone()[0], salt)
        self.assertTrue(self.request('status')['result']['claim_expired'])
        different = base64.b64encode(b'\x09' * 32).decode()
        self.assertFalse(self.request('claim', recipient_key=different, offer_hash=self.bundle['offer_hash'])['ok'])
        expired = self.service.provision(self.sponsor, '1', self.recipient.subject, '2026-10-10T13:00:00Z')
        self.assertFalse(self.request('claim', coupon=expired['coupon'], recipient_key=self.public,
                                      offer_hash=expired['offer_hash'])['ok'])
        self.assertEqual(self.provider.creates, 1)

    def test_expiry_boundary_precedes_durable_intent(self):
        self.now = datetime(2026, 10, 10, 13, tzinfo=timezone.utc)
        self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.provider.creates, 0)
        self.assertEqual(self.store.db.execute('SELECT state FROM coupons').fetchone()[0], 'ready')

    def test_protocol_isolation_prevents_v1_bypass(self):
        request = {'id': 'a', 'op': 'claim', 'coupon': self.coupon, 'recipient_key': self.public}
        self.assertFalse(json.loads(self.v1.dispatch(json.dumps(request).encode(), self.recipient))['ok'])
        old = self.v1.provision(self.sponsor, 1, self.recipient.subject)
        self.assertFalse(self.request('claim', coupon=old, recipient_key=self.public, offer_hash=self.bundle['offer_hash'])['ok'])
        self.assertEqual(self.provider.creates, 0)
        self.assertTrue(json.loads(self.v1.dispatch(json.dumps({**request, 'coupon': old}).encode(), self.recipient))['ok'])

    def test_scoped_offer_status_and_forbidden_wire_authority(self):
        wrong = Principal('peer:other', frozenset({'sponsor', 'recipient', 'observer'}))
        for op in ('offer', 'status'):
            denied = self.request(op, wrong)
            unknown = self.request(op, coupon='A' * 43)
            self.assertEqual(denied, unknown)
            self.assertFalse(self.request(op, local_peer='OtherIssuer1')['ok'])
            self.assertFalse(self.request(op, principal=self.recipient, principal_context={})['ok'])
            for principal in (self.sponsor, self.recipient, self.observer):
                self.assertTrue(self.request(op, principal)['ok'])
        for field in ('offer', 'issuer', 'provider', 'rows', 'roles', 'claim_expires_at'):
            self.assertFalse(self.claim(**{field: 'caller-controlled'})['ok'])
        self.assertEqual((self.provider.creates, self.provider.reads), (0, 0))

    def test_reconciliation_and_accounting_status_do_not_authorize_retry_or_release(self):
        for persisted in ('issuing', 'quarantined'):
            self.store.db.execute('UPDATE coupons SET state=?', (persisted,))
            status = self.request('status')['result']
            self.assertEqual(status['state'], 'reconciliation_required')
            self.assertFalse(status['automatic_retry_allowed'])
            self.assertFalse(status['deposit_release_authorized'])
            self.assertFalse(self.claim()['ok'])
        self.assertEqual(self.provider.creates, 0)

    def test_oversized_provider_secret_quarantines_before_delivery_commit(self):
        secret = 'synthetic-oversized-' + 'x' * MAX_PROVIDER_SECRET_BYTES
        def oversized(name, budget):
            self.provider.creates += 1
            return IssuedKey('key1', secret)
        self.provider.create_key = oversized
        self.assertFalse(self.claim()['ok'])
        self.assertFalse(self.claim()['ok'])
        row = self.store.db.execute('SELECT state,key_id,envelope FROM coupons').fetchone()
        self.assertEqual(dict(row), {'state': 'quarantined', 'key_id': None, 'envelope': None})
        self.assertEqual(self.provider.creates, 1)
        self.assertNotIn('synthetic-oversized-', '\n'.join(self.store.db.iterdump()))

    def test_observation_binds_stored_offer_and_cannot_accept_rows(self):
        delivered = self.claim()['result']
        fields = {'start': '2026-10-10T00:00:00Z', 'end': '2026-10-11T00:00:00Z', 'challenge': 'ab' * 32}
        self.assertFalse(self.request('observe', self.observer, **fields, rows=[])['ok'])
        observed = self.request('observe', self.observer, **fields)['result']
        payload = observed['payload']
        self.signing.public_key().verify(base64.b64decode(observed['signature']), evidence_canonical(payload))
        self.assertEqual(payload['domain'], 'dsmack-coupon-observation-v2')
        self.assertEqual(payload['version'], 2)
        self.assertEqual(payload['offer_hash'], self.bundle['offer_hash'])
        self.assertEqual(payload['threshold_nano_usd'], '5000000000')
        self.assertEqual(payload['provider_reported_nano_usd'], '5000000000')
        self.assertEqual(payload['delivery_sha256'], hashlib.sha256(delivered['envelope'].encode()).hexdigest())
        self.assertEqual(payload['environment'], 'local-unattested')
        with self.assertRaises(RedemptionError):
            authorize_deposit_release(observed)
        self.assertEqual(self.provider.reads, 1)

    def test_provider_correction_blocks_v2_observation_across_restart(self):
        self.claim()
        fields = {'start': '2026-10-10T00:00:00Z', 'end': '2026-10-11T00:00:00Z', 'challenge': 'ab' * 32}
        self.assertTrue(self.request('observe', self.observer, **fields)['ok'])
        self.provider.usage_rows = lambda key_id, start, end: [{'source': 'inference', 'id': 'row1',
            'api_key_id': key_id, 'total_cost_nano_usd': -1}]
        self.assertFalse(self.request('observe', self.observer, **fields)['ok'])
        status = self.request('status')['result']
        self.assertEqual(status['state'], 'delivered')
        self.assertTrue(status['accounting_blocked'])
        self.store.close()
        self.store = Store(self.path)
        self.construct()
        self.provider.usage_rows = lambda key_id, start, end: []
        self.assertFalse(self.request('observe', self.observer, **fields)['ok'])
        self.assertTrue(self.request('status')['result']['accounting_blocked'])

    def test_issuer_and_scope_identity_are_persisted(self):
        for peer, binding in [('OtherIssuer1', {'mode': 'synthetic'}), ('Issuer1', {'mode': 'near'})]:
            with self.assertRaises(RedemptionError):
                DsmackCouponServiceV2(self.store, self.provider, self.signing, sponsor_subject=self.sponsor.subject,
                    observer_subject=self.observer.subject, issuer_peer_id=peer, provider_binding=binding)


if __name__ == '__main__':
    unittest.main()
