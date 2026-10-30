"""Broker-authorized permanent ciphertext pins on the existing loopback Kubo API."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import threading
import time
import re
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MAX_BLOCK_BYTES = 512 * 1024
MAX_PIN_BYTES = 64 * 1024 * 1024
MAX_PIN_RECORDS = 4096

class ArtifactStoreError(Exception):
    def __init__(self, message, status=400, code='ARTIFACT_STORE_REQUEST'):
        super().__init__(message)
        self.status, self.code = status, code

def need(ok, message, status=400):
    if not ok:
        raise ArtifactStoreError(message, status)

def cid_for(data):
    return 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(data).digest()).decode().lower().rstrip('=')

def put_block(kubo, data):
    boundary = 'dsmack-artifact-' + secrets.token_hex(16)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="artifact.sealed"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
    connection = http.client.HTTPConnection(kubo.host, kubo.port, timeout=120)
    try:
        connection.request('POST', '/api/v0/block/put?format=raw&mhtype=sha2-256&pin=true', body,
                           {'Content-Type': 'multipart/form-data; boundary=' + boundary})
        response = connection.getresponse()
        raw = response.read(65536)
        need(response.status == 200, 'Kubo artifact block put failed', 502)
        need(json.loads(raw)['Key'] == cid_for(data), 'Kubo returned a different artifact CID', 502)
    finally:
        connection.close()

def artifact_call(store, action, body):
    """Call only after the existing handler verifies its broker signature."""
    need(action in ('raw-put', 'raw-get'), 'unknown artifact store action', 404)
    cid = body.get('cid')
    need(isinstance(cid, str) and re.fullmatch(r'bafkre[a-z2-7]{53}', cid), 'raw SHA256 artifact CID required')
    with store.lock:
        pins = store.state.setdefault('artifactPins', {})
        if action == 'raw-put':
            text = body.get('ciphertext')
            need(isinstance(text, str) and len(text) <= (MAX_BLOCK_BYTES * 4 + 2) // 3 and
                 re.fullmatch(r'[A-Za-z0-9_-]+', text), 'artifact ciphertext exceeds 512 KiB or is not base64url')
            data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
            need(29 <= len(data) <= MAX_BLOCK_BYTES and cid_for(data) == cid, 'artifact ciphertext size/CID mismatch')
            if cid not in pins:
                need(len(pins) < MAX_PIN_RECORDS and
                     sum(pin['size'] for pin in pins.values()) + len(data) <= MAX_PIN_BYTES,
                     'artifact pin storage is full; no published artifacts were removed', 507)
                pins[cid] = {'size': len(data), 'published': False}
                store.save()
            need(pins[cid]['size'] == len(data), 'artifact stored size mismatch', 502)
            put_block(store.kubo, data)
            need(store.kubo.pinned(cid), 'Kubo artifact pin was not confirmed', 502)
            pins[cid]['published'] = True
            store.save()
            return {'cid': cid, 'pinned': True}
        need(pins.get(cid, {}).get('published'), 'artifact CID has not been published', 404)
        request = Request(store.kubo.url + '/api/v0/block/get?' + urlencode({'arg': cid}), data=b'', method='POST')
        with urlopen(request, timeout=120) as response:
            data = response.read(MAX_BLOCK_BYTES + 1)
        need(len(data) == pins[cid]['size'] and len(data) <= MAX_BLOCK_BYTES and cid_for(data) == cid,
             'Kubo artifact ciphertext size/CID mismatch', 502)
        return {'cid': cid, 'ciphertext': base64.urlsafe_b64encode(data).decode().rstrip('=')}


class ArtifactStore:
    def __init__(self, root, kubo, broker_signer, now=time.time):
        self.root, self.kubo, self.broker_signer, self.now = Path(root), kubo, broker_signer.lower(), now
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / 'state.json'
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {'artifactPins': {}}
        self.lock, self.nonces = threading.RLock(), {}

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        with temporary.open('w') as output:
            os.chmod(temporary, 0o600)
            json.dump(self.state, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)
        descriptor = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def authorize(self, action, body):
        from eth_account import Account
        from eth_account.messages import encode_defunct
        need(action in ('raw-put', 'raw-get') and body.get('action') == action and
             type(body.get('issuedAt')) is int and abs(self.now() - body['issuedAt']) <= 120 and
             re.fullmatch(r'[0-9a-f]{32}', str(body.get('nonce', ''))) and
             re.fullmatch(r'0x[0-9a-f]{40}', str(body.get('wallet', ''))), 'fresh broker-signed request required', 403)
        allowed = {'action', 'issuedAt', 'nonce', 'wallet', 'sig', 'cid'} | ({'ciphertext'} if action == 'raw-put' else set())
        need(set(body) <= allowed, 'only encrypted artifact fields are accepted')
        unsigned = {k: v for k, v in body.items() if k != 'sig'}
        try:
            message = 'dsmack-workspace-store/1\n' + json.dumps(unsigned, sort_keys=True, separators=(',', ':'))
            signer = Account.recover_message(encode_defunct(text=message), signature=body.get('sig')).lower()
        except Exception:
            signer = None
        need(signer == self.broker_signer, 'broker artifact signature does not verify', 403)
        with self.lock:
            self.nonces = {k: expiry for k, expiry in self.nonces.items() if expiry >= self.now()}
            need(body['nonce'] not in self.nonces, 'broker artifact request was replayed', 403)
            need(len(self.nonces) < 10000, 'artifact request window is full', 429)
            self.nonces[body['nonce']] = self.now() + 120

class Kubo:
    def __init__(self, url):
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        need(parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost') and
             not parsed.username and not parsed.password and parsed.path in ('', '/'), 'Kubo API must be a loopback HTTP origin')
        self.url, self.host, self.port = url.rstrip('/'), parsed.hostname, parsed.port or 80

    def pinned(self, cid):
        request = Request(self.url + '/api/v0/pin/ls?' + urlencode({'arg': cid}), data=b'', method='POST')
        with urlopen(request, timeout=120) as response:
            return cid in json.loads(response.read(65536)).get('Keys', {})

def main():
    import argparse
    import http.server
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--broker-signer', required=True)
    parser.add_argument('--ipfs-api', default='http://127.0.0.1:15092')
    parser.add_argument('--port', type=int, default=15094)
    args = parser.parse_args()
    store = ArtifactStore(args.state, Kubo(args.ipfs_api), args.broker_signer)
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                need(0 < size <= 720 * 1024, 'artifact request exceeds its limit')
                self.connection.settimeout(15)
                body = json.loads(self.rfile.read(size))
                need(isinstance(body, dict), 'artifact request object required')
                action = self.path.lstrip('/')
                store.authorize(action, body)
                result, status = artifact_call(store, action, body), 200
            except ArtifactStoreError as error:
                result, status = {'error': {'code': error.code, 'message': str(error)}}, error.status
            except (ValueError, KeyError, TypeError):
                result, status = {'error': {'code': 'ARTIFACT_STORE_REQUEST', 'message': 'invalid artifact request'}}, 400
            except OSError:
                result, status = {'error': {'code': 'ARTIFACT_STORE_UNAVAILABLE', 'message': 'artifact pin storage is unavailable'}}, 503
            raw = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *_):
            pass
    http.server.ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()

if __name__ == '__main__':
    main()
