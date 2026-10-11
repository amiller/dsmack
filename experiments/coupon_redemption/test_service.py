import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .service import DsmackCouponService, Principal, MAX_FRAME
from .spike import Store, IssuedKey, RedemptionError, decrypt_secret


class Provider:
    def __init__(self):
        self.creates, self.reads = 0, 0
        self.fail = False
    def create_key(self, name, budget):
        self.creates += 1
        if self.fail:
            raise RuntimeError('private-provider-response')
        return IssuedKey('key1', 'synthetic-secret')
    def usage_rows(self, key_id, start, end):
        self.reads += 1
        return [{'source': 'inference', 'id': 'row1', 'api_key_id': key_id,
                 'total_cost_nano_usd': 5_000_000_000}]


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'state.sqlite')
        self.provider = Provider()
        self.sponsor = Principal('peer:sponsor', frozenset({'sponsor'}))
        self.recipient = Principal('peer:recipient', frozenset({'recipient'}))
        self.observer = Principal('peer:observer', frozenset({'observer'}))
        self.service = DsmackCouponService(self.store, self.provider, Ed25519PrivateKey.generate(),
                                         sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject)
        self.coupon = self.service.provision(self.sponsor, 5_000_000_000, self.recipient.subject)
        self.private = X25519PrivateKey.generate()
        self.public = base64.b64encode(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def request(self, op, authenticated, **fields):
        request = {'id': 'request1', 'op': op, 'coupon': self.coupon, **fields}
        return json.loads(self.service.dispatch(json.dumps(request).encode(), authenticated))

    def observe(self, principal):
        return self.request('observe', principal, start='2026-10-10T00:00:00Z',
                            end='2026-10-11T00:00:00Z', challenge='ab' * 32)

    def test_claim_observe_and_scoped_status(self):
        first = self.request('claim', self.recipient, recipient_key=self.public)
        again = self.request('claim', self.recipient, recipient_key=self.public)
        self.assertEqual(first, again)
        self.assertEqual(self.provider.creates, 1)
        envelope = first['result']['envelope']
        aad = (Store.digest(self.coupon) + ':key1').encode()
        self.assertEqual(decrypt_secret(envelope, self.private, aad), 'synthetic-secret')
        self.assertNotIn('synthetic-secret', json.dumps(first))
        observation = self.observe(self.observer)
        self.assertTrue(observation['ok'])
        self.assertEqual(observation['result']['payload']['environment'], 'local-unattested')
        for principal in (self.sponsor, self.recipient, self.observer):
            status = self.request('status', principal)
            self.assertTrue(status['ok'])
            self.assertFalse(status['result']['deposit_release_authorized'])
            self.assertNotIn('envelope', status['result'])

    def test_authentication_and_role_fail_before_provider_effects(self):
        for principal in [None, {'subject': self.recipient.subject, 'roles': ['recipient']},
                          self.sponsor, self.observer,
                          Principal('peer:other', frozenset({'recipient'})),
                          Principal(self.recipient.subject, frozenset())]:
            self.assertFalse(self.request('claim', principal, recipient_key=self.public)['ok'])
        self.assertEqual(self.provider.creates, 0)
        self.assertFalse(self.observe(self.recipient)['ok'])
        self.assertFalse(self.observe(self.sponsor)['ok'])
        self.assertEqual(self.provider.reads, 0)
        with self.assertRaises(RedemptionError):
            self.service.provision(self.recipient, 1, self.recipient.subject)

    def test_coupon_capability_is_scoped_to_granted_subject(self):
        self.assertFalse(self.request('status', Principal('peer:other', frozenset({'sponsor', 'recipient', 'observer'})))['ok'])
        other_coupon = self.service.provision(self.sponsor, 1, 'peer:other')
        self.assertFalse(self.request('claim', self.recipient, coupon=other_coupon, recipient_key=self.public)['ok'])
        self.assertEqual(self.provider.creates, 0)

    def test_accounting_credentials_and_roles_cannot_be_supplied_on_wire(self):
        for field in ('rows', 'provider', 'bearer', 'principal', 'roles', 'budget'):
            self.assertFalse(self.request('claim', self.recipient, recipient_key=self.public,
                                          **{field: 'untrusted'})['ok'])
        self.assertFalse(self.request('observe', self.observer, start='2026-10-10T00:00:00Z',
                                     end='2026-10-11T00:00:00Z', challenge='ab' * 32, rows=[])['ok'])
        self.assertEqual((self.provider.creates, self.provider.reads), (0, 0))

    def test_frame_bounds_duplicate_json_and_bad_challenge(self):
        for frame in (b'x' * (MAX_FRAME + 1), b'{"id":"a","id":"b"}', b'{', b'[]'):
            self.assertFalse(json.loads(self.service.dispatch(frame, self.recipient))['ok'])
        self.assertFalse(self.request('observe', self.observer, start='2026-10-10T00:00:00Z',
                                     end='2026-10-11T00:00:00Z', challenge='bad')['ok'])
        self.assertEqual((self.provider.creates, self.provider.reads), (0, 0))

    def test_ambiguous_failure_redacted_and_never_reissued(self):
        self.provider.fail = True
        for _ in range(2):
            result = self.request('claim', self.recipient, recipient_key=self.public)
            self.assertFalse(result['ok'])
            self.assertNotIn('private-provider-response', str(result))
        self.assertEqual(self.provider.creates, 1)

    def test_scope_survives_restart(self):
        self.request('claim', self.recipient, recipient_key=self.public)
        self.store.close()
        self.store = Store(Path(self.directory.name) / 'state.sqlite')
        self.service = DsmackCouponService(self.store, self.provider, Ed25519PrivateKey.generate(),
                                         sponsor_subject=self.sponsor.subject, observer_subject=self.observer.subject)
        self.assertTrue(self.request('claim', self.recipient, recipient_key=self.public)['ok'])
        self.assertEqual(self.provider.creates, 1)


if __name__ == '__main__':
    unittest.main()
