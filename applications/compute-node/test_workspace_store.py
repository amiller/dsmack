"""Encrypted snapshot boundaries: ownership, complete hashes, replay and retention."""
import base64
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('workspace_store', Path(__file__).with_name('workspace-store.py'))
ws = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ws)
MAC, WALLET = '0x' + '12' * 20, '0x' + '34' * 20


def cid_for(data):
    return 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(data).digest()).decode().lower().rstrip('=')


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.blobs, self.pins = {}, set()
        test = self
        class KuboHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                route = urlsplit(self.path)
                arg = parse_qs(route.query).get('arg', [None])[0]
                status = 200
                if route.path == '/api/v0/add':
                    body = self.rfile.read(int(self.headers['Content-Length']))
                    data = body.split(b'\r\n\r\n', 1)[1].rsplit(b'\r\n--', 1)[0]
                    cid = cid_for(data)
                    test.blobs[cid] = data
                    raw = json.dumps({'Hash': cid}).encode()
                elif route.path.endswith('/pin/ls'):
                    status = 200 if arg in test.pins else 500
                    raw = json.dumps({'Keys': {arg: {}}} if arg in test.pins else {'Message': 'path is not pinned'}).encode()
                elif route.path.endswith('/pin/add'):
                    test.pins.add(arg)
                    raw = b'{}'
                elif route.path.endswith('/pin/rm'):
                    test.pins.discard(arg)
                    raw = b'{}'
                elif route.path.endswith('/cat'):
                    raw = test.blobs[arg]
                else:
                    raw, status = b'{}', 404
                self.send_response(status)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_):
                pass
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), KuboHandler)
        self.thread = threading.Thread(target=lambda: self.http.serve_forever(poll_interval=.01), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_http)
        self.now = 2000000000
        self.store = ws.WorkspaceStore(self.root / 'store', MAC, WALLET,
                                       ws.Kubo('http://127.0.0.1:' + str(self.http.server_port)), now=lambda: self.now)

    def close_http(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=2)

    def head(self, data, version=1, previous='0' * 64):
        return dict(workspaceId='conversation-one', version=version, previousHash=previous,
                    hash=hashlib.sha256(data).hexdigest(), size=len(data), cid=None, mac=MAC)

    def upload(self, data, upload_id='ab' * 16):
        head = self.head(data)
        self.store.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})
        for offset in range(0, len(data), ws.CHUNK_BYTES):
            self.store.call('chunk', {'wallet': WALLET, 'uploadId': upload_id, 'offset': offset,
                                     'data': base64.b64encode(data[offset:offset + ws.CHUNK_BYTES]).decode()})
        return self.store.call('commit', {'wallet': WALLET, 'uploadId': upload_id})['head']

    def test_chunk_replay_hash_pin_and_cross_process_cache_or_ipfs_restore(self):
        data = bytes(range(256)) * 2400
        head = self.head(data)
        upload_id = 'ab' * 16
        self.store.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})
        body = {'wallet': WALLET, 'uploadId': upload_id, 'offset': 0,
                'data': base64.b64encode(data[:ws.CHUNK_BYTES]).decode()}
        self.assertEqual(self.store.call('chunk', body)['offset'], ws.CHUNK_BYTES)
        self.assertEqual(self.store.call('chunk', body)['offset'], ws.CHUNK_BYTES)
        with self.assertRaisesRegex(ws.StoreError, 'replayed ciphertext chunk differs'):
            self.store.call('chunk', dict(body, data=base64.b64encode(b'x' * ws.CHUNK_BYTES).decode()))
        with self.assertRaisesRegex(ws.StoreError, 'does not belong'):
            self.store.call('chunk', dict(body, wallet='0x' + '56' * 20))
        self.store.call('chunk', {'wallet': WALLET, 'uploadId': upload_id, 'offset': ws.CHUNK_BYTES,
                                 'data': base64.b64encode(data[ws.CHUNK_BYTES:]).decode()})
        saved = self.store.call('commit', {'wallet': WALLET, 'uploadId': upload_id})['head']
        self.assertEqual(saved['cid'], cid_for(data))
        self.assertIn(saved['cid'], self.pins)
        self.assertTrue(self.store.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})['committed'])
        restarted = ws.WorkspaceStore(self.store.root, MAC, WALLET, self.store.kubo, now=lambda: self.now)
        body = {'wallet': WALLET, 'head': saved, 'offset': 0, 'length': ws.CHUNK_BYTES}
        local = restarted.call('read', body)
        self.assertEqual(base64.b64decode(local['data']), data[:ws.CHUNK_BYTES])
        self.assertEqual((local['source'], local['ipfsFetched']), ('mac', False))
        restarted.remove(restarted.blob(saved['hash']))
        remote = restarted.call('read', body)
        self.assertEqual((remote['source'], remote['ipfsFetched']), ('ipfs', True))
        self.assertEqual(base64.b64decode(remote['data']), data[:ws.CHUNK_BYTES])

    def test_commit_recovers_if_ciphertext_rename_precedes_metadata_save(self):
        data = b'ciphertext for interrupted commit' * 10
        head, upload_id = self.head(data), 'ab' * 16
        self.store.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})
        self.store.call('chunk', {'wallet': WALLET, 'uploadId': upload_id, 'offset': 0,
                                 'data': base64.b64encode(data).decode()})
        self.store.part(upload_id).rename(self.store.blob(head['hash']))
        restarted = ws.WorkspaceStore(self.store.root, MAC, WALLET, self.store.kubo, now=lambda: self.now)
        recovered = restarted.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})
        self.assertTrue(recovered['committed'])
        self.assertEqual(recovered['head']['cid'], cid_for(data))

    def test_incomplete_or_wrong_ciphertext_never_reaches_ipfs(self):
        data = b'encrypted archive' * 10
        head = self.head(data)
        upload_id = 'cd' * 16
        self.store.call('begin', {'wallet': WALLET, 'uploadId': upload_id, 'head': head})
        with self.assertRaisesRegex(ws.StoreError, 'hash/size mismatch'):
            self.store.call('commit', {'wallet': WALLET, 'uploadId': upload_id})
        self.store.call('chunk', {'wallet': WALLET, 'uploadId': upload_id, 'offset': 0,
                                 'data': base64.b64encode(b'x' * len(data)).decode()})
        with self.assertRaisesRegex(ws.StoreError, 'hash/size mismatch'):
            self.store.call('commit', {'wallet': WALLET, 'uploadId': upload_id})
        self.assertEqual(self.blobs, {})
        self.assertEqual(self.pins, set())
        with self.assertRaises(ws.StoreError):
            self.store.call('begin', {'wallet': WALLET, 'uploadId': 'ef' * 16,
                                     'head': dict(head, size=ws.MAX_BYTES + 1)})

    def test_retention_extends_on_read_and_never_unpins_an_existing_shared_pin(self):
        data = b'ciphertext-only' * 10
        self.pins.add(cid_for(data))
        head = self.upload(data)
        self.assertNotIn(head['cid'], self.store.state['ownedPins'])
        self.now += 29 * 86400
        self.store.call('read', {'wallet': WALLET, 'head': head, 'offset': 0, 'length': 10})
        self.now += 2 * 86400
        self.store.prune()
        self.assertTrue(self.store.blob(head['hash']).exists())
        self.now += 31 * 86400
        self.assertEqual(self.store.prune()['snapshotsRemoved'], 1)
        self.assertFalse(self.store.blob(head['hash']).exists())
        self.assertIn(head['cid'], self.pins)
        own = self.upload(b'another-ciphertext' * 10, 'cd' * 16)
        self.assertIn(own['cid'], self.store.state['ownedPins'])
        self.now += 31 * 86400
        self.store.prune()
        self.assertNotIn(own['cid'], self.pins)
        self.assertIn(head['cid'], self.pins)

    def test_http_rejects_a_non_broker_signature_and_accepts_canonical_signed_metadata(self):
        from eth_account import Account
        from eth_account.messages import encode_defunct
        broker, outsider = Account.create(), Account.create()
        self.store.broker_signer = broker.address.lower()
        server = ws.Server(('127.0.0.1', 0), ws.Handler)
        server.store = self.store
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
        thread.start()
        try:
            body = {'action': 'begin', 'issuedAt': self.now, 'nonce': '12' * 16, 'wallet': WALLET,
                    'uploadId': '34' * 16, 'head': self.head(b'ciphertext' * 10)}
            def post(signer):
                message = encode_defunct(text=ws.PREFIX + ws.canonical(body))
                signed = dict(body, sig='0x' + signer.sign_message(message).signature.hex())
                request = Request('http://127.0.0.1:' + str(server.server_port) + '/begin',
                                  data=json.dumps(signed).encode(), headers={'Content-Type': 'application/json'})
                return urlopen(request, timeout=5)
            with self.assertRaises(HTTPError) as error:
                post(outsider)
            self.assertEqual(error.exception.code, 403)
            with post(broker) as response:
                self.assertEqual(json.load(response), {'offset': 0})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
