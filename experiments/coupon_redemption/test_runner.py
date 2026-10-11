import argparse
import contextlib
import io
import unittest
from unittest.mock import patch

from .runner import run, main
from .spike import RedemptionError

WS = '22222222-2222-4222-8222-222222222222'
ORG = '33333333-3333-4333-8333-333333333333'
KEY = '11111111-1111-4111-8111-111111111111'


class RunnerTests(unittest.TestCase):
    def args(self):
        return argparse.Namespace(command='usage', workspace=WS, organization=ORG, key=KEY,
                                  start='2026-10-10T00:00:00Z', end='2026-10-11T00:00:00Z')

    def test_preflight_emits_only_validated_scope_ids(self):
        calls = []
        def transport(*args):
            calls.append(args)
            return {'token': 'do-not-print', 'organizations': [{'id': ORG}],
                    'workspaces': [{'id': WS, 'organization_id': ORG, 'secret': 'do-not-print'}]}
        with patch.dict('os.environ', {'NEAR_SESSION_JWT': 'secret'}):
            result = run(argparse.Namespace(command='preflight'), transport)
        self.assertNotIn('do-not-print', str(result))
        self.assertEqual(calls[0][0], 'GET')
        self.assertEqual(calls[0][2], 'secret')

    def test_usage_read_only_unsigned_and_duplicate_rejection(self):
        row = {'id': 'row1', 'source': 'inference', 'api_key_id': KEY,
               'workspace_id': WS, 'total_cost_nano_usd': 5_000_000_000}
        def transport(method, url, bearer, body):
            self.assertEqual(method, 'GET')
            self.assertEqual(bearer, 'reporting-secret')
            return {'data': [row], 'next_cursor': None}
        with patch.dict('os.environ', {'NEAR_REPORTING_TOKEN': 'reporting-secret'}):
            result = run(self.args(), transport)
            self.assertEqual(result['provider_reported_nano_usd'], 5_000_000_000)
            self.assertFalse(result['deposit_release_authorized'])
            with self.assertRaises(RedemptionError):
                run(self.args(), lambda *args: {'data': [row, row], 'next_cursor': None})

    def test_failures_never_print_provider_or_environment_secrets(self):
        stderr, stdout = io.StringIO(), io.StringIO()
        with patch('experiments.coupon_redemption.runner.NearHTTPS') as factory:
            factory.return_value.side_effect = RuntimeError('private-response Bearer secret')
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                code = main(['health'])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn('secret', stderr.getvalue())
        self.assertNotIn('private-response', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
