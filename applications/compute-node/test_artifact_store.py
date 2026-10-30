import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('artifact_store', Path(__file__).with_name('artifact-store.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ArtifactStoreTests(unittest.TestCase):
    def host(self, root, url):
        address = urlsplit(url)
        def pinned(cid):
            request = Request(url + '/api/v0/pin/ls?' + urlencode({'arg': cid}), data=b'', method='POST')
            with urlopen(request, timeout=20) as response:
                return cid in json.load(response)['Keys']
        path = root / 'state.json'
        state = json.loads(path.read_text()) if path.exists() else {'ownedPins': {}}
        host = SimpleNamespace(lock=threading.RLock(), state=state,
            kubo=SimpleNamespace(url=url, host=address.hostname, port=address.port, pinned=pinned))
        host.save = lambda: path.write_text(json.dumps(host.state))
        return host

    @unittest.skipUnless(os.environ.get('KUBO_API_URL'), 'real Kubo API required')
    def test_actual_pin_reload_public_read_and_idempotent_quota(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = module.ArtifactStore(root / 'artifacts', module.Kubo(os.environ['KUBO_API_URL']), '0x' + '2' * 40)
            data = os.urandom(73)
            cid = module.cid_for(data)
            body = {'cid': cid, 'ciphertext': base64.urlsafe_b64encode(data).decode().rstrip('=')}
            self.assertEqual(module.artifact_call(host, 'raw-put', body), {'cid': cid, 'pinned': True})
            self.assertTrue(host.kubo.pinned(cid))
            self.assertNotIn(cid, host.state.get('ownedPins', {}))
            if os.environ.get('WORKSPACE_STORE_SOURCE'):
                source = importlib.util.spec_from_file_location('workspace_store', os.environ['WORKSPACE_STORE_SOURCE'])
                workspace = importlib.util.module_from_spec(source);source.loader.exec_module(workspace)
                other = workspace.WorkspaceStore(root / 'workspaces', '0x' + '1' * 40, '0x' + '2' * 40, workspace.Kubo(os.environ['KUBO_API_URL']))
                other.prune()
                self.assertTrue(host.kubo.pinned(cid))
            self.assertEqual(module.artifact_call(host, 'raw-put', body), {'cid': cid, 'pinned': True})
            restored = module.ArtifactStore(root / 'artifacts', module.Kubo(os.environ['KUBO_API_URL']), '0x' + '2' * 40)
            self.assertEqual(module.artifact_call(restored, 'raw-get', {'cid': cid}), body)
            self.assertEqual(sum(pin['size'] for pin in restored.state['artifactPins'].values()), len(data))

    def test_quota_and_unpublished_cid_fail_before_kubo_io(self):
        with tempfile.TemporaryDirectory() as directory:
            host = self.host(Path(directory), 'http://127.0.0.1:1')
            host.state['artifactPins'] = {'existing': {'size': module.MAX_PIN_BYTES, 'published': True}}
            data = b'bounded private encrypted block bytes'
            body = {'cid': module.cid_for(data), 'ciphertext': base64.urlsafe_b64encode(data).decode().rstrip('=')}
            with self.assertRaisesRegex(module.ArtifactStoreError, 'storage is full') as caught:
                module.artifact_call(host, 'raw-put', body)
            self.assertEqual(caught.exception.status, 507)
            with self.assertRaisesRegex(module.ArtifactStoreError, 'not been published'):
                module.artifact_call(host, 'raw-get', {'cid': body['cid']})
            self.assertEqual(len(host.state['artifactPins']), 1)


    def test_broker_signature_and_replay_are_checked_before_pin_authority(self):
        from eth_account import Account
        from eth_account.messages import encode_defunct
        import time
        key = Account.create()
        with tempfile.TemporaryDirectory() as directory:
            store = module.ArtifactStore(directory, None, key.address)
            unsigned = {'action': 'raw-get', 'issuedAt': int(time.time()), 'nonce': 'a' * 32,
                        'wallet': '0x' + '0' * 40, 'cid': module.cid_for(b'ciphertext')}
            message = 'dsmack-workspace-store/1\n' + json.dumps(unsigned, sort_keys=True, separators=(',', ':'))
            body = dict(unsigned, sig=key.sign_message(encode_defunct(text=message)).signature.hex())
            store.authorize('raw-get', body)
            with self.assertRaisesRegex(module.ArtifactStoreError, 'replayed'):
                store.authorize('raw-get', body)
            body['nonce'] = 'b' * 32
            with self.assertRaisesRegex(module.ArtifactStoreError, 'signature'):
                store.authorize('raw-get', body)

if __name__ == '__main__':
    unittest.main()
