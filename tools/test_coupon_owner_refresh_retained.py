import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import coupon_owner_refresh_retained as r


class Retention(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = Path(self.tmp.name)
        self.calls = []
        self.jwt = 'x.' + base64.urlsafe_b64encode(json.dumps({'exp': 5000}).encode()).decode() + '.x'
        r.owner.atomic_json(self.p / 'owner-session.json', {
            'refresh_user_agent': 'recorded', 'owner_profile': {'id': 'owner'},
            'discovered_account': {'organization_id': 'org'}, 'session_jwt': 'old'})
        r.owner.atomic_json(self.p / 'owner-refresh.json', {
            'refresh_user_agent': 'recorded', 'refresh_token': 'rt_old'})

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, path, **kw):
        self.calls.append((path, kw.get('post', False)))
        if kw.get('post'):
            self.assertTrue((self.p / 'refresh-started.json').exists())
            self.assertEqual((self.p / 'rotation-response.json').stat().st_size, r.RESERVATION)
            return {'access_token': self.jwt, 'refresh_token': 'rt_new', 'refresh_token_expiration': 9000}
        return {'id': 'owner', 'is_active': True,
                'organizations': [{'id': 'org', 'is_active': True}]}

    def run_renew(self, **kw):
        return r.renew(self.p, call=self.call, clock=lambda: 1000, **kw)

    def retained(self):
        return json.loads((self.p / 'rotation-response.json').read_bytes())

    def test_success_retained_and_no_replay(self):
        self.assertTrue(self.run_renew()['renewed'])
        self.assertEqual(self.retained()['refresh_token'], 'rt_new')
        self.assertEqual((self.p / 'rotation-response.json').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(r.owner.Refused):
            self.run_renew()
        self.assertEqual(len(self.calls), 2)

    def test_low_space_precedes_post(self):
        with self.assertRaises(r.owner.Refused):
            self.run_renew(free_bytes=lambda _: 0)
        self.assertEqual(self.calls, [])

    def test_allocation_failure_precedes_post(self):
        def fail(*args):
            raise OSError('fixture disk full')
        with self.assertRaises(OSError):
            self.run_renew(allocate=fail)
        self.assertEqual(self.calls, [])

    def test_later_disk_failure_retains_rotation(self):
        with patch.object(r.owner, 'atomic_json', side_effect=OSError('fixture disk full')):
            with self.assertRaises(OSError):
                self.run_renew()
        self.assertEqual(self.retained()['refresh_token'], 'rt_new')
        self.assertEqual(len(self.calls), 1)

    def test_scope_failure_retains_rotation(self):
        original = self.call
        def wrong(path, **kw):
            v = original(path, **kw)
            if not kw.get('post'):
                v['id'] = 'different'
            return v
        with self.assertRaises(r.owner.Refused):
            r.renew(self.p, call=wrong, clock=lambda: 1000)
        self.assertEqual(self.retained()['refresh_token'], 'rt_new')
        self.assertEqual(r.owner.private_json(self.p / 'owner-refresh.json')['refresh_token'], 'rt_new')

    def test_ambiguous_post_never_repeated(self):
        def fail(*args, **kw):
            self.calls.append(('post', True))
            raise TimeoutError()
        with self.assertRaises(TimeoutError):
            r.renew(self.p, call=fail)
        with self.assertRaises(r.owner.Refused):
            self.run_renew()
        self.assertEqual(len(self.calls), 1)


if __name__ == '__main__':
    unittest.main()
