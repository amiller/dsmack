import copy
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .dstack_issuer_identity import DstackIssuerIdentity
from .issuer_service import IssuerEvidenceService, MAX_ISSUER_FRAME
from .spike import RedemptionError


class SyntheticGuest:
    def __init__(self):
        self.calls = []

    def get_quote(self, data):
        self.calls.append(data)
        return type('SyntheticQuote', (), {'quote': '00', 'event_log': '[]'})()


class IssuerServiceTests(unittest.TestCase):
    def setUp(self):
        self.guest = SyntheticGuest()
        self.key = Ed25519PrivateKey.generate()
        self.collector = DstackIssuerIdentity(self.guest, self.key)
        self.service = IssuerEvidenceService(issuer_peer='IssuerPeer00000001', signing_key=self.key,
            identity_policy_sha256='11' * 32, issuance_policy_sha256='22' * 32,
            collector=self.collector, app_compose='synthetic-only-not-hardware')
        self.binding = {'version': 2, 'peer_id': self.service.issuer_peer,
            'public_key_hex': self.service.public_key_hex, 'challenge_hex': 'ab' * 32,
            'policy_sha256': '11' * 32}

    def dispatch(self, frame, local_peer='IssuerPeer00000001'):
        return json.loads(self.service.dispatch(frame, local_peer=local_peer, remote_peer='UnknownPeer'))

    def test_public_discovery_has_no_bearer_and_evidence_binds_actual_signer(self):
        response = self.dispatch(b'{"id":"a","op":"info"}')
        self.assertEqual(set(response['result']), {'version', 'issuer_public_key_hex', 'identity_policy_sha256', 'issuance_policy_sha256'})
        self.assertNotIn('qualified', json.dumps(response))
        frame = json.dumps({'id': 'a', 'op': 'evidence', 'binding': self.binding}).encode()
        result = self.dispatch(frame)['result']
        self.assertEqual(result['binding'], self.binding)
        self.assertEqual(len(self.guest.calls), 1)
        self.assertEqual(self.guest.calls[0].hex(), __import__('hashlib').sha512(
            b'dsmack-coupon-issuer-identity-v2\0' + json.dumps(self.binding, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_wrong_context_key_policy_and_wire_authority_never_touch_guest(self):
        for field in ('peer_id', 'public_key_hex', 'policy_sha256'):
            binding = copy.deepcopy(self.binding)
            binding[field] = 'OtherPeer00000001' if field == 'peer_id' else 'ff' * 32
            self.assertFalse(self.dispatch(json.dumps({'id': 'a', 'op': 'evidence', 'binding': binding}).encode())['ok'])
        for field in ('coupon', 'principal', 'roles', 'local_peer'):
            frame = {'id': 'a', 'op': 'evidence', 'binding': self.binding, field: 'forged'}
            self.assertFalse(self.dispatch(json.dumps(frame).encode())['ok'])
        self.assertFalse(self.dispatch(b'{"id":"a","op":"info"}', local_peer='WrongPeer')['ok'])
        self.assertEqual(self.guest.calls, [])

    def test_duplicate_malformed_and_oversized_frames_are_generic(self):
        for frame in (b'{"id":"a","op":"info","op":"evidence"}', b'{', b'[]', b'X' * (MAX_ISSUER_FRAME + 1)):
            response = self.dispatch(frame)
            self.assertFalse(response['ok'])
            self.assertEqual(response['error'], 'request_failed')
        self.assertEqual(self.guest.calls, [])

    def test_wrong_collector_key_rejected_before_mount(self):
        with self.assertRaises(RedemptionError):
            IssuerEvidenceService(issuer_peer='IssuerPeer00000001', signing_key=self.key,
                identity_policy_sha256='11' * 32, issuance_policy_sha256='22' * 32,
                collector=DstackIssuerIdentity(self.guest, Ed25519PrivateKey.generate()), app_compose='fixture')

    def test_large_evidence_never_overruns_outer_wire_bound(self):
        self.collector.collect = lambda binding, compose: {'binding': binding, 'event_log': '\\' * (1024 * 1024)}
        response = self.dispatch(json.dumps({'id': 'a', 'op': 'evidence', 'binding': self.binding}).encode())
        self.assertFalse(response['ok'])


if __name__ == '__main__':
    unittest.main()
