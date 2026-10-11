import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('coupon_testnet_status', Path(__file__).with_name('coupon_testnet_status.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublicStatusTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.manifest = {'version': 1, 'network': 'dsmack-public-testnet-v1',
            'environment': 'public-testnet', 'trust_profile': 'operator-readable-debug',
            'peer': '/dns4/issuer.example/tcp/443/wss/p2p/' + 'a' * 32,
            'bundle_url': 'https://example.org/immutable/bundle.json', 'bundle_sha256': '1' * 64,
            'source_revision': '2' * 40, 'image_digest': 'sha256:' + '3' * 64,
            'app_id': '4' * 40, 'compose_sha256': '5' * 64,
            'chain_id': 8453, 'guard_address': '0x' + '6' * 40,
            'confirmation_profile': 'base-mainnet-rpc-safe-debug-v1',
            'approval_expires_at': '2030-01-02T00:00:00Z',
            'claiming_available_until': '2030-01-01T00:40:00Z'}
        self.probe = {'publicPeerRouteVerified': True,
            'issuerIdentityVerified': 'verified-intel-tdx-identity',
            'authenticatedPeer': 'a' * 32, 'compose': '5' * 64, 'appId': '4' * 40,
            'approvalMatchesFreshIssuer': True, 'privateIssuanceQualified': False,
            'rollbackQualified': False, 'providerAdmission': False,
            'providerPolicy': 'UpToDate-or-OutOfDate-with-warning',
            'providerReadiness': 'Fresh recipient admission required',
            'giftRead': False, 'bearerSent': False, 'providerEffects': 0}

    def export(self, observed='2030-01-01T00:00:00Z'):
        return module.status(self.manifest, self.probe, observed_at=observed, now=self.now)

    def test_fresh_is_issuer_only_not_provider_or_membership_claim(self):
        result = self.export()
        self.assertEqual(result['issuer_status'], 'issuer-reachable')
        self.assertEqual(result['provider_model_status'], 'unknown-requires-fresh-recipient-admission')
        self.assertIsNone(result['independent_participant_count'])
        self.assertFalse(result['private_issuance_qualified'])
        self.assertFalse(result['l1_finality_verified'])

    def test_stale_and_expired_not_healthy(self):
        self.assertEqual(self.export('2029-12-31T23:54:59Z')['issuer_status'], 'stale')
        self.manifest['approval_expires_at'] = '2029-12-31T23:59:59Z'
        self.manifest['claiming_available_until'] = '2029-12-31T23:59:59Z'
        self.assertEqual(self.export()['issuer_status'], 'expired')

    def test_named_refusal_exports_no_raw_error(self):
        self.probe = {'publicPeerOrIssuerRefused': True, 'code': 'issuer_identity_or_route_refused',
                      'giftRead': False, 'bearerSent': False, 'providerEffects': 0}
        self.assertEqual(self.export()['issuer_status'], 'refused')

    def test_private_unknown_fields_and_effectful_probe_refused(self):
        for target, key, value in ((self.manifest, 'session_jwt', 'private'),
                                   (self.probe, 'raw_error', 'private')):
            target[key] = value
            with self.assertRaises(ValueError): self.export()
            del target[key]
        self.probe['bearerSent'] = True
        with self.assertRaises(ValueError): self.export()

    def test_substituted_peer_compose_profile_and_qualifications_refused(self):
        for target, key, value in ((self.probe, 'authenticatedPeer', 'b' * 32),
                (self.probe, 'compose', '6' * 64), (self.probe, 'providerAdmission', True),
                (self.probe, 'rollbackQualified', True),
                (self.manifest, 'confirmation_profile', 'latest'),
                (self.manifest, 'environment', 'production')):
            old = target[key]; target[key] = value
            with self.assertRaises(ValueError): self.export()
            target[key] = old

    def test_credential_urls_future_and_invalid_expiry_refused(self):
        for url in ('https://user:secret@example.org/x', 'https://example.org/x?token=secret', 'http://example.org/x'):
            self.manifest['bundle_url'] = url
            with self.assertRaises(ValueError): self.export()
        self.manifest['bundle_url'] = 'https://example.org/x'
        with self.assertRaises(ValueError): self.export('2030-01-01T00:01:00Z')
        self.manifest['claiming_available_until'] = '2030-01-03T00:00:00Z'
        with self.assertRaises(ValueError): self.export()

    def test_duplicate_fields_and_size_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public.json'
            for raw in (b'{"version":1,"version":2}', b'x' * 65537):
                path.write_bytes(raw)
                with self.assertRaises(ValueError): module.read_json(path)


if __name__ == '__main__': unittest.main()
