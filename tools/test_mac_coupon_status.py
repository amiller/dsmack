import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tools.mac_coupon_status import status, FALSE_FIELDS


class MacCouponStatusTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.manifest = {'schema': 'dsmack-mac-issuer-deployment-v1',
            'network': 'dsmack-public-testnet-v1', 'peer': '/dns4/issuer.example/tcp/443/wss/p2p/' + 'a' * 32,
            'source_revision': '2' * 40, 'trust_profile': 'operator-readable-debug',
            'bundle_url': 'https://example.org/epoch/bundle.json', 'bundle_sha256': '1' * 64,
            'approval_expires_at': '2030-01-01T02:00:00Z', 'claiming_available_until': '2030-01-01T01:00:00Z',
            'identity_policy_sha256': '3' * 64, 'issuance_policy_sha256': '4' * 64,
            'approval_sha256': '5' * 64, 'apple_app_id': 'DC9JH5DRMY.dev.dsmack.provider',
            'cdhash': '6' * 64, 'compose_sha256': '7' * 64, 'runtime_app': 'synthetic:runner/v1'}
        self.probe = {'version': 1, 'observed_at_unix': int(self.now.timestamp()),
            'profile': 'mac-appattest-coupon-v1', 'evidenceStatus': 'verified-apple-appattest-issuer-identity',
            'peer': 'a' * 32, 'appleAppId': self.manifest['apple_app_id'],
            'cdhash': '6' * 64, 'composeSha256': '7' * 64, 'runtimeAppAttested': True,
            'runtimeApp': 'synthetic:runner/v1', 'identityPolicySha256': '3' * 64,
            'issuancePolicySha256': '4' * 64, 'approvalSha256': '5' * 64,
            'custody': 'operator-kms-readable', **dict.fromkeys(FALSE_FIELDS, False)}

    def export(self, now=None):
        return status(self.manifest, self.probe, now=now or self.now)

    def test_genuine_profile_bound_report_is_only_reachability(self):
        result = self.export()
        self.assertEqual(result['issuer_status'], 'issuer-reachable')
        self.assertEqual(result['identity_profile'], 'mac-appattest-coupon-v1')
        self.assertNotIn('claiming_available', result)
        self.assertNotIn('runtimeApp', result)
        self.assertNotIn('providerEffects', result)
        self.assertNotIn('participants', result)

    def test_fresh_stale_expired_and_future(self):
        self.assertEqual(self.export(self.now + timedelta(seconds=300))['issuer_status'], 'issuer-reachable')
        self.assertEqual(self.export(self.now + timedelta(seconds=301))['issuer_status'], 'stale')
        self.manifest['approval_expires_at'] = '2029-12-31T23:59:59Z'
        self.manifest['claiming_available_until'] = '2029-12-31T23:59:59Z'
        self.assertEqual(self.export()['issuer_status'], 'expired')
        with self.assertRaises(ValueError): self.export(self.now - timedelta(seconds=31))

    def test_all_mismatched_pins_and_effects_refuse(self):
        for key in ('peer', 'appleAppId', 'cdhash', 'composeSha256', 'identityPolicySha256',
                    'issuancePolicySha256', 'approvalSha256', 'runtimeApp'):
            with self.subTest(key=key):
                old = self.probe[key]; self.probe[key] = 'mismatch'
                with self.assertRaises(ValueError): self.export()
                self.probe[key] = old
        for key in FALSE_FIELDS:
            for value in (True, 0, 'false'):
                self.probe[key] = value
                with self.assertRaises(ValueError): self.export()
            self.probe[key] = False

    def test_synthetic_evidence_unqualified_profile_or_hidden_fields_refuse(self):
        for key, value in (('version', True), ('evidenceStatus', 'synthetic-only-not-hardware'),
                           ('profile', 'tdx'), ('custody', 'private'),
                           ('observed_at_unix', True), ('observed_at_unix', 1e15),
                           ('runtimeAppAttested', False), ('secret', 'canary')):
            candidate = {**self.probe, key: value}
            with self.assertRaises(ValueError): status(self.manifest, candidate, now=self.now)
        with self.assertRaises(ValueError): status({**self.manifest, 'secret': 'canary'}, self.probe, now=self.now)

    def test_runtime_absence_must_be_explicit_in_both_pins_and_probe(self):
        self.manifest['runtime_app'] = None
        self.probe['runtimeAppAttested'] = False
        with self.assertRaises(ValueError): self.export()
        del self.probe['runtimeApp']
        self.assertEqual(self.export()['issuer_status'], 'issuer-reachable')
        self.probe['runtimeAppAttested'] = True
        with self.assertRaises(ValueError): self.export()

    def test_manifest_url_and_window_refuse(self):
        for key, value in (('bundle_url', 'https://user:secret@example.org'),
                           ('bundle_url', 'https://example.org/?token=secret'),
                           ('bundle_sha256', 'bad'), ('source_revision', 'main'),
                           ('runtime_app', '<script>'), ('apple_app_id', 'other'),
                           ('claiming_available_until', '2030-01-02T00:00:00Z')):
            with self.assertRaises(ValueError): status({**self.manifest, key: value}, self.probe, now=self.now)

    def test_cli_refuses_without_echoing_input(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, probe = Path(folder)/'manifest.json', Path(folder)/'probe.json'
            manifest.write_text(json.dumps(self.manifest)); probe.write_text('{"secret":"PRIVATE-CANARY"}')
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('mac_coupon_status.py')),
                '--manifest', str(manifest), '--probe', str(probe)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('PRIVATE-CANARY', result.stderr)


if __name__ == '__main__': unittest.main()
