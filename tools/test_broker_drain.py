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
from broker_drain import drain


class DrainTest(unittest.TestCase):
    def test_drains_then_waits_for_guests_and_streams(self):
        calls = []
        def call(path, method='GET', headers={}):
            calls.append((path, method, headers.get('Authorization')))
            reads = sum(1 for c in calls if c[0] == '/network')
            if path == '/drain':
                return {'draining': True}
            return {'totals': {'busy_slots': int(reads < 2)}} if path == '/network' else {'inFlightStreams': int(reads < 3)}
        drain('unused', 'relay-broker', 'operator-fixture', call=call, sleep=lambda s: None)
        self.assertEqual(calls[0], ('/drain', 'POST', 'Bearer operator-fixture'))
        self.assertEqual([c[0] for c in calls[1:]], ['/network', '/inference/status'] * 3)

    def test_unconfirmed_drain_stops_the_deploy(self):
        with self.assertRaisesRegex(RuntimeError, 'confirm draining'):
            drain('unused', 'relay-broker', 'x', call=lambda *a: {})

    def test_missing_activity_is_not_idle(self):
        def call(path, method='GET', headers={}):
            return {'draining': True} if path == '/drain' else {'totals': {'busy_slots': 0}} if path == '/network' else {}
        with self.assertRaises(KeyError):
            drain('unused', 'relay-broker', 'x', call=call)


class BrokerPromotionTest(unittest.TestCase):
    def test_broker_drains_before_upload_and_promotes(self):
        source = Path(__file__).resolve().parents[1] / 'applications/relay-broker/deploy-inference.py'
        spec = importlib.util.spec_from_file_location('broker_deploy_test', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        uploaded, promoted = False, False
        def activity(*args):
            if uploaded:
                raise RuntimeError('CVM-only provider key unavailable before promotion')
        def api(path, **kwargs):
            nonlocal uploaded, promoted
            if path == '/_api/projects':
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
                'isolation':'container', 'mode':'attested', 'source':'tarball://relay-broker', 'env':{}, 'ref':'test-ref'}))
            with tarfile.open(root / 'relay-broker.tgz', 'w:gz') as archive:
                body = b'{"payments":{},"inference":{}}'
                info = tarfile.TarInfo('applications/relay-broker/config.json')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            with patch.object(module, 'source_ref', return_value='test-ref'), patch.object(module, 'token', return_value='test-only'), patch.object(module, 'client', return_value=api), patch.object(module, 'drain', side_effect=activity) as guard:
                (root/'operator').write_text('operator-fixture\n')
                module.deploy(SimpleNamespace(target='production', prepared=root, evidence=root/'evidence', apply=True, url='unused', operator_token=root/'operator'))
            guard.assert_called_once_with('unused', 'relay-broker', 'operator-fixture')
            self.assertTrue(promoted)


if __name__ == '__main__':
    unittest.main()
