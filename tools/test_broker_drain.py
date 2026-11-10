import unittest
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from broker_drain import drained


class DrainTest(unittest.TestCase):
    def fixture(self, busy=lambda reads: 0, streams=lambda reads: 0):
        calls = []
        def call(path, method='GET', headers={}):
            calls.append((path, method, headers.get('Authorization')))
            reads = sum(1 for c in calls if c[0] == '/network')
            if path == '/drain':
                return {'draining': method == 'POST'}
            return {'totals': {'busy_slots': busy(reads)}} if path == '/network' else {'inFlightStreams': streams(reads)}
        return calls, call

    def test_drains_waits_then_runs_the_deploy_without_resuming(self):
        calls, call = self.fixture(lambda r: int(r < 2), lambda r: int(r < 3))
        with drained('unused', 'relay-broker', 'operator-fixture', call=call, sleep=lambda s: None):
            calls.append(('deploy',))
        self.assertEqual(calls[0], ('/drain', 'POST', 'Bearer operator-fixture'))
        self.assertEqual([c[0] for c in calls[1:]], ['/network', '/inference/status'] * 3 + ['deploy'])

    def test_failed_deploy_resumes_new_stays(self):
        calls, call = self.fixture()
        with self.assertRaisesRegex(ValueError, 'upload rejected'):
            with drained('unused', 'relay-broker', 'operator-fixture', call=call, sleep=lambda s: None):
                raise ValueError('upload rejected')
        self.assertEqual(calls[-1], ('/drain', 'DELETE', 'Bearer operator-fixture'))

    def test_stuck_busy_times_out_loudly_and_resumes(self):
        at = [0]
        calls, call = self.fixture(lambda r: 1)
        with self.assertRaisesRegex(RuntimeError, 'timed out after 65 minutes with 1 busy'):
            with drained('unused', 'relay-broker', 'x', call=call, clock=lambda: at[0],
                         sleep=lambda s: at.__setitem__(0, at[0] + s)):
                self.fail('deploy must not run')
        self.assertEqual(calls[-1][:2], ('/drain', 'DELETE'))
        self.assertGreaterEqual(at[0], 65 * 60)

    def test_failed_resume_is_reported(self):
        def call(path, method='GET', headers={}):
            if method == 'DELETE':
                raise OSError('broker gone')
            return {'draining': True} if path == '/drain' else {'totals': {'busy_slots': 0}} if path == '/network' else {'inFlightStreams': 0}
        with self.assertRaisesRegex(RuntimeError, 'may still refuse new stays'):
            with drained('unused', 'relay-broker', 'x', call=call):
                raise ValueError('upload rejected')

    def test_refused_drain_does_not_resume(self):
        calls = []
        def call(path, method='GET', headers={}):
            calls.append(method)
            raise HTTPError('https://broker/drain', 403, 'operator required', {}, None)
        with self.assertRaises(HTTPError):
            with drained('unused', 'relay-broker', 'x', call=call):
                self.fail('deploy must not run')
        self.assertEqual(calls, ['POST'])

    def test_drain_post_timeout_still_resumes(self):
        calls = []
        def call(path, method='GET', headers={}):
            calls.append(method)
            if method == 'POST':
                raise TimeoutError()
            return {'draining': False}
        with self.assertRaises(TimeoutError):
            with drained('unused', 'relay-broker', 'x', call=call):
                self.fail('deploy must not run')
        self.assertEqual(calls, ['POST', 'DELETE'])

    def test_unconfirmed_drain_stops_the_deploy(self):
        with self.assertRaisesRegex(RuntimeError, 'confirm draining'):
            with drained("unused", "relay-broker", "x", call=lambda *a: {} if a[1:2] != ("DELETE",) else {"draining": False}):
                self.fail('deploy must not run')

    def test_missing_activity_is_not_idle(self):
        def call(path, method='GET', headers={}):
            return {'draining': method == 'POST'} if path == '/drain' else {'totals': {'busy_slots': 0}} if path == '/network' else {}
        with self.assertRaises(KeyError):
            with drained('unused', 'relay-broker', 'x', call=call):
                self.fail('deploy must not run')


class BrokerPromotionTest(unittest.TestCase):
    def test_broker_drains_before_upload_and_promotes(self):
        source = Path(__file__).resolve().parents[1] / 'applications/relay-broker/deploy-inference.py'
        spec = importlib.util.spec_from_file_location('broker_deploy_test', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        uploaded, promoted = False, False
        def api(path, **kwargs):
            nonlocal uploaded, promoted
            if path == '/_api/projects':
                guard.return_value.__enter__.assert_called_once()
                guard.return_value.__exit__.assert_not_called()
                uploaded = True
                return {'runtime': 'deno', 'isolation': 'container', 'mode': 'dev'}
            if path.endswith('/promote'):
                promoted = True
                return {'mode':'attested'}
            if path == '/relay-broker/key':
                self.assertTrue(promoted)
                return {}
            raise AssertionError(path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'relay-broker.manifest.json').write_text(json.dumps({
                'name':'relay-broker', 'runtime':'deno', 'entry':'applications/relay-broker/server.ts',
                'isolation':'container', 'mode':'attested', 'source':'tarball://relay-broker', 'env':{'DSTACK_SOCKET':'/run/broker/dstack.sock'}, 'ref':'test-ref'}))
            with tarfile.open(root / 'relay-broker.tgz', 'w:gz') as archive:
                body = b'{"payments":{},"inference":{}}'
                info = tarfile.TarInfo('applications/relay-broker/config.json')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            with patch.object(module, 'source_ref', return_value='test-ref'), patch.object(module, 'token', return_value='test-only'), patch.object(module, 'client', return_value=api), patch.object(module, 'drained') as guard:
                (root/'operator').write_text('operator-fixture\n')
                module.deploy(SimpleNamespace(target='production', prepared=root, evidence=root/'evidence', apply=True, url='unused', operator_token=root/'operator'))
            guard.assert_called_once_with('unused', 'relay-broker', 'operator-fixture')
            self.assertTrue(promoted)


if __name__ == '__main__':
    unittest.main()
