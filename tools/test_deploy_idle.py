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
from deploy_idle import wait_for_idle


class IdleGuardTest(unittest.TestCase):
    def test_waits_for_both_guest_and_stream(self):
        at = [0]
        reads = []
        def read(path):
            reads.append(path)
            return {'totals': {'busy_slots': int(at[0] < 2)}} if path == '/network' else {'inFlightStreams': int(at[0] < 4)}
        wait_for_idle('unused', read=read, clock=lambda: at[0], sleep=lambda seconds: at.__setitem__(0, at[0] + seconds))
        self.assertEqual(at[0], 4)
        self.assertEqual(len(reads), 6)

    def test_busy_timeout_prevents_deploy(self):
        def read(path):
            return {'totals': {'busy_slots': 0}} if path == '/network' else {'inFlightStreams': 1}
        with self.assertRaisesRegex(RuntimeError, 'activity must reach idle'):
            wait_for_idle('unused', 0, read=read)

    def test_restart_between_upload_and_promotion_waits_for_activity_report(self):
        at = [0]
        def read(path):
            if at[0] < 2:
                raise HTTPError('https://broker/network', 500, 'restarting', {}, None)
            return {'totals': {'busy_slots': 0}} if path == '/network' else {'inFlightStreams': 0}
        wait_for_idle('unused', read=read, clock=lambda: at[0], sleep=lambda seconds: at.__setitem__(0, at[0] + seconds))
        self.assertEqual(at[0], 2)

    def test_missing_activity_is_not_idle(self):
        with self.assertRaisesRegex(RuntimeError, 'must report'):
            wait_for_idle('unused', read=lambda path: {'totals': {'busy_slots': 0}} if path == '/network' else {})


class BrokerPromotionTest(unittest.TestCase):
    def test_uploaded_dev_broker_must_promote_before_cvm_only_activity_can_load(self):
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
                return {'runtime': 'deno', 'isolation': 'shared'}
            if path.endswith('/promote'):
                promoted = True
                return {}
            if path == '/relay-broker/key':
                self.assertTrue(promoted)
                return {}
            raise AssertionError(path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'relay-broker.manifest.json').write_text(json.dumps({
                'name':'relay-broker', 'runtime':'deno', 'entry':'applications/relay-broker/server.ts',
                'isolation':'shared', 'source':'tarball://relay-broker', 'env':{}, 'ref':'test-ref'}))
            with tarfile.open(root / 'relay-broker.tgz', 'w:gz') as archive:
                body = b'{"payments":{},"inference":{}}'
                info = tarfile.TarInfo('applications/relay-broker/config.json')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            with patch.object(module, 'token', return_value='test-only'), patch.object(module, 'client', return_value=api), patch.object(module, 'wait_for_idle', side_effect=activity) as guard:
                module.deploy(SimpleNamespace(prepared=root, evidence=root/'evidence', apply=True, url='unused', wait_idle_minutes=1))
            guard.assert_called_once()
            self.assertTrue(promoted)


if __name__ == '__main__':
    unittest.main()
