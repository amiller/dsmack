import contextlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('mac_preview_status',
                                              Path(__file__).with_name('mac_preview_status.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

OBSERVED = '2026-01-15T12:00:00Z'
OBSERVED_DT = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
OUTPUT_FIELDS = {'version', 'observation_source', 'observed_at_utc', 'observation_age_seconds',
                 'observation_max_age_seconds', 'observation_max_future_seconds',
                 'observation_status', 'inventory_observation_fresh', 'issuer_environment',
                 'issuer_compose_sha256', 'issuer_peer', 'claim_window_open',
                 'claiming_available', 'claiming_requirements', 'claiming_blockers',
                 'automatic_reboot_recovery_qualified', 'retirement_candidates',
                 'retirement_authorized', 'environments', 'independent_participant_count'}


def inventory():
    """Synthetic operator inventory with the exact allowlisted shape and the
    supplied claim/credential window offsets; no real host or credential state."""
    return {'observed_at_utc': OBSERVED,
            'qualified_preview': {'environment': 'public-testnet-preview',
                                  'runner_pid': 7341, 'holder_pid': 7342, 'kms_pid': 7343,
                                  'compose': 'a' * 64, 'peer': '1' * 52,
                                  'claim_deadline_utc': '2026-01-15T12:25:12Z',
                                  'credential_expiry_utc': '2026-01-15T12:36:02Z',
                                  'automatic_reboot_recovery_qualified': False},
            'relay': {'pid': 7344, 'loopback_tcp': 4002, 'loopback_ws': 4003,
                      'cloudflare_pid': 7345, 'temporary_tunnel': True},
            'private_dev_reference': {'native_dev_node_pid': 7346, 'runner_pid': 7347,
                                      'current_independent_qualification': False},
            'historical_pilot': {'runner_pid': 7348, 'broker_pid': 7349, 'kms_pid': 7350,
                                 'managed_staging_qualified': False},
            'superseded_unused': {'runner_pid': 7351, 'kms_pid': 7352, 'holder_pid': 7353},
            'idle_old_holder_pid': 7354, 'private_staging_qualified': False,
            'production_deployed': False, 'project_cvms_allowed': False,
            'runtime_mutations_authorized_by_task': False}


class MacPreviewStatusTests(unittest.TestCase):
    def setUp(self):
        self.data = inventory()
        self.now = OBSERVED_DT + timedelta(seconds=30)

    def export(self, now=None):
        return module.status(self.data, now=now or self.now)

    def aged(self, seconds):
        """Caller time exactly `seconds` after the recorded observation."""
        return OBSERVED_DT + timedelta(seconds=seconds)

    def test_fresh_inventory_does_not_qualify_reachability_or_claiming(self):
        result = self.export()
        self.assertEqual(result['observation_status'], 'fresh')
        self.assertTrue(result['inventory_observation_fresh'])
        self.assertFalse(result['claiming_available'])
        self.assertEqual(sorted(result['claiming_blockers']),
                         ['gas_and_provider_readiness_observed', 'maintenance_absence_observed'])
        self.assertTrue(result['claiming_requirements']['inventory_observation_fresh'])
        self.assertTrue(result['claiming_requirements']['owner_authorization_remaining_over_650s'])
        self.assertTrue(result['claim_window_open'])
        self.assertEqual(result['issuer_environment'], 'public-testnet-preview')
        self.assertEqual(set(result), OUTPUT_FIELDS)
        self.assertEqual(result['environments'],
                         {'public_testnet_preview': 'historically-qualified-issuer-admission-redemption-paused',
                          'managed_private_staging': 'not-qualified',
                          'private_dev_reference': 'historically-observed-not-qualified',
                          'production': 'not-deployed'})
        self.assertEqual(result['retirement_candidates'],
                         ['historical_pilot', 'superseded_unused', 'idle_old_holder'])
        self.assertFalse(result['retirement_authorized'])
        self.assertFalse(result['automatic_reboot_recovery_qualified'])
        self.assertIsNone(result['independent_participant_count'])

    def test_output_carries_no_process_or_credential_field(self):
        result = self.export()
        rendered = json.dumps(result)
        for pid in (7341, 7342, 7343, 7344, 7345, 7346, 7347, 7348, 7349, 7350, 7351, 7352, 7353, 7354):
            self.assertNotIn(str(pid), rendered)
        for key in result:
            for banned in ('jwt', 'path', 'secret', 'account', 'bearer', 'ssh', 'token', 'pid'):
                self.assertNotIn(banned, key)

    def test_observation_age_bounds_fresh_stale_and_unknown(self):
        self.assertEqual(self.export(self.aged(90))['observation_status'], 'fresh')
        self.assertEqual(self.export(self.aged(91))['observation_status'], 'stale')
        stale = self.export(self.aged(9000))
        self.assertFalse(stale['inventory_observation_fresh'])
        self.assertFalse(stale['claim_window_open'])
        self.assertIn('inventory_observation_fresh', stale['claiming_blockers'])
        self.assertEqual(self.export(self.aged(-30))['observation_status'], 'fresh')
        unknown = self.export(self.aged(-31))
        self.assertEqual(unknown['observation_status'], 'unknown')
        self.assertFalse(unknown['inventory_observation_fresh'])
        self.assertFalse(unknown['claiming_available'])

    def test_owner_authorization_window_and_policy_gate_claiming(self):
        self.data['qualified_preview']['credential_expiry_utc'] = '2026-01-15T12:11:20Z'
        self.data['qualified_preview']['claim_deadline_utc'] = '2026-01-15T12:11:20Z'
        self.assertFalse(
            self.export()['claiming_requirements']['owner_authorization_remaining_over_650s'])
        self.assertIn('owner_authorization_remaining_over_650s', self.export()['claiming_blockers'])
        self.data['qualified_preview']['credential_expiry_utc'] = '2026-01-15T12:11:21Z'
        self.assertTrue(
            self.export()['claiming_requirements']['owner_authorization_remaining_over_650s'])
        self.data['qualified_preview']['claim_deadline_utc'] = '2026-01-15T12:00:29Z'
        self.assertFalse(self.export()['claim_window_open'])
        self.assertIn('policy_claim_window_open', self.export()['claiming_blockers'])

    def test_exact_allowlist_refuses_private_and_unknown_fields(self):
        for target, key in ((self.data, 'owner_dir'), (self.data, 'session_jwt'),
                            (self.data, 'ssh_config'), (self.data, 'private_key_path'),
                            (self.data, 'account_id'), (self.data, 'bearer_token'),
                            (self.data, 'participant_count'), (self.data, 'version'),
                            (self.data['qualified_preview'], 'owner_session_jwt'),
                            (self.data['qualified_preview'], 'config_path'),
                            (self.data['relay'], 'tunnel_url')):
            target[key] = 'private'
            with self.assertRaises(ValueError):
                module.validate(self.data)
            del target[key]

    def test_missing_malformed_oversized_and_duplicate_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            missing = inventory()
            del missing['relay']
            variants = (b'', b'not json', b'{"observed_at_utc":NaN}',
                        b'{"observed_at_utc":"2026-10-11T20:18:00Z",'
                        b'"observed_at_utc":"2026-10-11T20:18:00Z"}',
                        json.dumps(missing).encode(), b'x' * 65537)
            for raw in variants:
                path.write_bytes(raw)
                with self.assertRaises(ValueError, msg=raw[:24]):
                    module.read_inventory(path)

    def test_unqualified_claims_and_environment_flags_are_refused(self):
        flips = ((self.data, 'production_deployed'), (self.data, 'private_staging_qualified'),
                 (self.data, 'project_cvms_allowed'),
                 (self.data, 'runtime_mutations_authorized_by_task'),
                 (self.data['qualified_preview'], 'automatic_reboot_recovery_qualified'),
                 (self.data['private_dev_reference'], 'current_independent_qualification'),
                 (self.data['historical_pilot'], 'managed_staging_qualified'))
        for target, key in flips:
            target[key] = True
            with self.assertRaises(ValueError, msg=key):
                module.validate(self.data)
            target[key] = False
        self.data['relay']['temporary_tunnel'] = False
        with self.assertRaises(ValueError):
            module.validate(self.data)

    def test_malformed_values_and_inconsistent_windows_are_refused(self):
        swaps = ((self.data['qualified_preview'], 'environment', 'production'),
                 (self.data['qualified_preview'], 'environment', 'private-staging'),
                 (self.data['qualified_preview'], 'compose', 'A' * 64),
                 (self.data['qualified_preview'], 'compose', 'a' * 63),
                 (self.data['qualified_preview'], 'peer', 'short'),
                 (self.data['qualified_preview'], 'runner_pid', 0),
                 (self.data['qualified_preview'], 'runner_pid', '1448'),
                 (self.data['qualified_preview'], 'kms_pid', 4194305),
                 (self.data['relay'], 'loopback_tcp', 70000),
                 (self.data['relay'], 'pid', -1),
                 (self.data, 'idle_old_holder_pid', 1.0),
                 (self.data, 'observed_at_utc', '2026-10-11 20:18:00Z'),
                 (self.data, 'observed_at_utc', '2026-10-11T20:18:00+00:00'),
                 (self.data, 'observed_at_utc', None))
        for target, key, value in swaps:
            old = target[key]
            target[key] = value
            with self.assertRaises(ValueError, msg=key):
                module.validate(self.data)
            target[key] = old
        self.data['qualified_preview']['claim_deadline_utc'] = '2026-10-11T20:54:03Z'
        with self.assertRaises(ValueError):
            module.validate(self.data)

    def test_malformed_section_types_are_refused(self):
        for name in ('qualified_preview', 'relay', 'private_dev_reference',
                     'historical_pilot', 'superseded_unused'):
            old = self.data[name]
            self.data[name] = ['not', 'a', 'dict']
            with self.assertRaises(ValueError, msg=name):
                module.validate(self.data)
            self.data[name] = old

    def test_caller_time_is_required_and_validated(self):
        with self.assertRaises(ValueError):
            module.status(self.data, now='2026-10-11T20:18:30Z')
        with self.assertRaises(ValueError):
            module.status(self.data, now=datetime(2026, 10, 11, 20, 18, 30))
        module.status(self.data, now=self.now.astimezone(timezone(timedelta(hours=-1))))

    def test_cli_exports_status_and_fails_closed_without_input_content(self):
        tool = Path(__file__).with_name('mac_preview_status.py')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            path.write_text(json.dumps(inventory()))
            good = subprocess.run([sys.executable, str(tool), '--inventory', str(path),
                                   '--now', '2026-01-15T12:00:30Z'],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0, good.stderr)
            result = json.loads(good.stdout)
            self.assertEqual(result['observation_status'], 'fresh')
            self.assertTrue(result['inventory_observation_fresh'])
            self.assertFalse(result['claiming_available'])
            path.write_bytes(b'{')
            bad = subprocess.run([sys.executable, str(tool), '--inventory', str(path),
                                  '--now', '2026-01-15T12:00:30Z'],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, '')
            self.assertNotIn('{', bad.stderr)
            missing_now = subprocess.run([sys.executable, str(tool), '--inventory', str(path)],
                                         capture_output=True, text=True, check=False)
            self.assertEqual(missing_now.returncode, 2)


if __name__ == '__main__':
    unittest.main()
