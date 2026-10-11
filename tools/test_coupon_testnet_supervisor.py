import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import coupon_owner_session as owner
import coupon_testnet_supervisor as supervisor


def token(exp):
    body = base64.urlsafe_b64encode(json.dumps({'exp': exp}).encode()).decode().rstrip('=')
    return 'synthetic.' + body + '.signature'


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.old = {'session_jwt': token(1200), 'refresh_user_agent': 'fixture-original-UA',
                    'owner_profile': {'id': 'owner'}, 'discovered_account': {'organization_id': 'org'}}
        owner.atomic_json(self.root / 'owner-session.json', self.old)
        owner.atomic_json(self.root / 'owner-refresh.json', {'refresh_token': 'rt_fixture_old', 'refresh_user_agent': 'fixture-original-UA'})
        self.calls = []

    def call(self, route, **kwargs):
        self.calls.append((route, kwargs))
        if kwargs.get('post'):
            return {'access_token': token(4600), 'refresh_token': 'rt_fixture_rotated', 'refresh_token_expiration': '2030-01-01T00:00:00Z'}
        return {'id': 'owner', 'is_active': True, 'organizations': [{'id': 'org', 'is_active': True}]}

    def test_exact_original_ua_rotation_before_identity_and_success(self):
        def call(route, **kwargs):
            if not kwargs.get('post'):
                self.assertEqual(owner.private_json(self.root / 'owner-refresh.json')['refresh_token'], 'rt_fixture_rotated')
            return self.call(route, **kwargs)
        result = owner.renew(self.root, call=call, clock=lambda: 1000)
        self.assertTrue(result['renewed']); self.assertEqual(result['seconds_remaining'], 3600)
        self.assertEqual([r for r, _ in self.calls], ['/v1/users/me/access-tokens', '/v1/users/me'])
        self.assertTrue(all(k['user_agent'] == 'fixture-original-UA' for _, k in self.calls))
        self.assertEqual(owner.private_json(self.root / 'owner-session.json')['session_jwt'], token(4600))

    def test_identity_refusal_preserves_rotated_refresh_and_old_session(self):
        def call(route, **kwargs):
            result = self.call(route, **kwargs)
            if not kwargs.get('post'): result['id'] = 'wrong-owner'
            return result
        with self.assertRaises(owner.Refused): owner.renew(self.root, call=call, clock=lambda: 1000)
        self.assertEqual(owner.private_json(self.root / 'owner-refresh.json')['refresh_token'], 'rt_fixture_rotated')
        self.assertEqual(owner.private_json(self.root / 'owner-session.json'), self.old)

    def test_malformed_access_still_preserves_rotated_refresh(self):
        def call(route, **kwargs):
            result = self.call(route, **kwargs); result['access_token'] = 'malformed'; return result
        with self.assertRaises(owner.Refused): owner.renew(self.root, call=call, clock=lambda: 1000)
        self.assertEqual(owner.private_json(self.root / 'owner-refresh.json')['refresh_token'], 'rt_fixture_rotated')
        self.assertEqual(owner.private_json(self.root / 'owner-session.json'), self.old)

    def test_wrong_user_agent_private_modes_links_refused_before_post(self):
        refresh = self.root / 'owner-refresh.json'
        owner.atomic_json(refresh, {'refresh_token': 'rt_fixture_old', 'refresh_user_agent': 'wrong'})
        with self.assertRaises(owner.Refused): owner.renew(self.root, call=self.call, clock=lambda: 1000)
        self.assertEqual(self.calls, [])
        refresh.chmod(0o644)
        with self.assertRaises(owner.Refused): owner.private_json(refresh)
        refresh.chmod(0o600)
        link = self.root / 'linked.json'; os.link(refresh, link)
        with self.assertRaises(owner.Refused): owner.private_json(refresh)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.plan = {'state_dir': str(self.root), 'owner_dir': str(self.root)}
        self.before = {'ready': True, 'issuing_jobs': 0, 'owner_expires_at_unix': 2600,
            'approval_expires_at_unix': 20000, 'obligation_fingerprint': 'a' * 64,
            'one_claim_reserve_ready': True}
        self.calls = []; self.renew_count = 0

    def adapter(self, plan, operation):
        self.calls.append(operation)
        if operation == 'rotate': return {'rotated': True, 'before_fingerprint': 'a' * 64, 'after_fingerprint': 'a' * 64}
        value = dict(self.before)
        if operation == 'verify': value['owner_expires_at_unix'] = 4600
        return value

    def renew(self, directory):
        self.renew_count += 1
        return {'renewed': True, 'same_owner_and_organization': True, 'seconds_remaining': 3600}

    def run_cycle(self, adapter=None, renew=None):
        return supervisor.cycle(self.plan, adapter=adapter or self.adapter, renew_owner=renew or self.renew, clock=lambda: 1000)

    def test_unattended_success_preserves_full_obligation_and_verifies_after_rotation(self):
        self.assertEqual(self.run_cycle(), 'renewed')
        self.assertEqual(self.calls, ['inspect', 'rotate', 'verify']); self.assertEqual(self.renew_count, 1)
        self.assertEqual(owner.private_json(self.root / 'rotation.json')['stage'], 'complete')
        self.assertTrue(owner.private_json(self.root / 'health.json')['claiming_available'])
        self.assertEqual((self.root / 'rotation.json').stat().st_mode & 0o777, 0o600)

    def test_busy_does_not_renew_stop_or_reissue(self):
        self.before['issuing_jobs'] = 1
        self.assertEqual(self.run_cycle(), 'busy'); self.assertEqual(self.calls, ['inspect']); self.assertEqual(self.renew_count, 0)
        self.assertFalse((self.root / 'rotation.json').exists())

    def test_failure_after_post_durably_blocks_retry_on_next_process_cycle(self):
        def renewal(directory): self.renew_count += 1; raise TimeoutError('synthetic-private-error')
        self.assertEqual(self.run_cycle(renew=renewal), 'blocked')
        self.assertEqual(self.run_cycle(), 'blocked'); self.assertEqual(self.renew_count, 1)
        public_health = (self.root / 'health.json').read_text()
        self.assertNotIn('synthetic-private-error', public_health)
        self.assertFalse(owner.private_json(self.root / 'health.json')['claiming_available'])

    def test_state_mismatch_approval_change_and_freshness_failure_fail_closed(self):
        for broken in ('fingerprint', 'approval', 'expiry'):
            with self.subTest(broken=broken):
                if (self.root / 'rotation.json').exists(): (self.root / 'rotation.json').unlink()
                def adapter(plan, op):
                    result = self.adapter(plan, op)
                    if op == 'verify':
                        key, value = {'fingerprint': ('obligation_fingerprint', 'b' * 64),
                                      'approval': ('approval_expires_at_unix', 30000),
                                      'expiry': ('owner_expires_at_unix', 1300)}[broken]
                        result[key] = value
                    return result
                self.assertEqual(self.run_cycle(adapter=adapter), 'blocked')
                self.assertFalse(owner.private_json(self.root / 'health.json')['claiming_available'])

    def test_approval_expiry_and_insufficient_reserve_never_trigger_mutation(self):
        self.before['approval_expires_at_unix'] = 1800
        self.assertEqual(self.run_cycle(), 'approval-renewal-required'); self.assertEqual(self.renew_count, 0)
        self.before['approval_expires_at_unix'] = 20000; self.before['one_claim_reserve_ready'] = False
        self.assertEqual(self.run_cycle(), 'unavailable'); self.assertEqual(self.renew_count, 0)

    def test_unknown_inspection_does_not_print_raw_failure(self):
        def adapter(plan, operation): raise ValueError('secret-fixture')
        self.assertEqual(self.run_cycle(adapter=adapter), 'unknown')
        self.assertNotIn('secret-fixture', (self.root / 'health.json').read_text())


if __name__ == '__main__': unittest.main()
