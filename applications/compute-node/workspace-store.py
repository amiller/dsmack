#!/usr/bin/env python3
"""Store encrypted workspace archives locally and pin them through a running Kubo API."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

CHUNK_BYTES = 512 * 1024
MAX_BYTES = 272 * 1024 * 1024
RETENTION_SECONDS = 30 * 86400
PREFIX = 'dsmack-workspace-store/1\n'
HEX = re.compile(r'^[0-9a-f]{64}$')
CID = re.compile(r'^b[a-z2-7]{20,120}$')


class StoreError(Exception):
    def __init__(self, message, status=400, code='WORKSPACE_STORE_REQUEST'):
        super().__init__(message)
        self.status, self.code = status, code


def need(ok, message, status=400):
    if not ok:
        raise StoreError(message, status)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        os.chmod(temporary, 0o600)
        output.write(canonical(value) + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


class Kubo:
    def __init__(self, url='http://127.0.0.1:15092'):
        self.url = url.rstrip('/')
        parsed = urlsplit(self.url)
        need(parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost') and
             not parsed.username and not parsed.password and not parsed.path,
             'Kubo API must be a loopback HTTP origin')
        self.host, self.port = parsed.hostname, parsed.port or 80

    def json(self, op, **params):
        request = Request(self.url + '/api/v0/' + op + '?' + urlencode(params), data=b'', method='POST')
        try:
            with urlopen(request, timeout=120) as response:
                raw = response.read(1 << 20)
        except HTTPError as error:
            raw = error.read(65536)
            error.close()
            try:
                message = json.loads(raw).get('Message', 'Kubo API refused request')
            except ValueError:
                message = 'Kubo API refused request'
            raise StoreError(message, 502, 'WORKSPACE_IPFS') from None
        return json.loads(raw)

    def add_file(self, path):
        boundary = 'dsmack-workspace-' + os.urandom(16).hex()
        header = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="workspace.sealed"\r\n'
                  'Content-Type: application/octet-stream\r\n\r\n').encode()
        ending = ('\r\n--' + boundary + '--\r\n').encode()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=120)
        try:
            connection.putrequest('POST', '/api/v0/add?pin=false&cid-version=1&raw-leaves=true')
            connection.putheader('Content-Type', 'multipart/form-data; boundary=' + boundary)
            connection.putheader('Content-Length', str(len(header) + path.stat().st_size + len(ending)))
            connection.endheaders()
            connection.send(header)
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(1 << 20), b''):
                    connection.send(chunk)
            connection.send(ending)
            response = connection.getresponse()
            raw = response.read(65536)
            need(response.status == 200, 'Kubo add failed', 502)
            cid = json.loads(raw.splitlines()[-1])['Hash']
            need(isinstance(cid, str) and CID.fullmatch(cid), 'Kubo returned invalid CID', 502)
            return cid
        finally:
            connection.close()

    def pinned(self, cid):
        try:
            return cid in self.json('pin/ls', arg=cid).get('Keys', {})
        except StoreError as error:
            if 'not pinned' in str(error).lower():
                return False
            raise

    def pin(self, cid):
        self.json('pin/add', arg=cid)

    def unpin(self, cid):
        try:
            self.json('pin/rm', arg=cid)
        except StoreError as error:
            if 'not pinned' not in str(error).lower():
                raise

    def fetch(self, cid, destination, size, expected_hash):
        digest, count = hashlib.sha256(), 0
        request = Request(self.url + '/api/v0/cat?' + urlencode({'arg': cid}), data=b'', method='POST')
        try:
            with urlopen(request, timeout=120) as response, destination.open('xb') as output:
                os.chmod(destination, 0o600)
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    count += len(chunk)
                    need(count <= size and count <= MAX_BYTES, 'IPFS ciphertext exceeds snapshot size', 502)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            need(count == size and digest.hexdigest() == expected_hash, 'IPFS ciphertext hash/size mismatch', 502)
        except Exception:
            if destination.exists():
                destination.unlink()
            raise


class WorkspaceStore:
    def __init__(self, root, publisher, broker_signer, kubo=None, now=time.time):
        self.root, self.publisher, self.broker_signer = Path(root), publisher.lower(), broker_signer.lower()
        self.kubo, self.now = kubo or Kubo(), now
        self.lock = threading.RLock()
        self.checked = {}
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ('uploads', 'blobs'):
            (self.root / name).mkdir(exist_ok=True, mode=0o700)
        self.path = self.root / 'state.json'
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {'uploads': {}, 'snapshots': {}, 'ownedPins': {}}

    def save(self):
        atomic_json(self.path, self.state)

    def authorize(self, action, body):
        from eth_account import Account
        from eth_account.messages import encode_defunct
        need(body.get('action') == action and type(body.get('issuedAt')) is int and
             abs(self.now() - body['issuedAt']) <= 120 and re.fullmatch(r'[0-9a-f]{32}', str(body.get('nonce', ''))),
             'fresh broker-signed request required', 403)
        unsigned = {key: value for key, value in body.items() if key != 'sig'}
        try:
            signer = Account.recover_message(encode_defunct(text=PREFIX + canonical(unsigned)), signature=body.get('sig')).lower()
        except Exception:
            signer = None
        need(signer == self.broker_signer, 'broker workspace signature does not verify', 403)
        need(re.fullmatch(r'0x[0-9a-f]{40}', str(body.get('wallet', ''))), 'workspace wallet required')
        return unsigned

    def head(self, value):
        need(isinstance(value, dict) and set(value) == {'workspaceId', 'version', 'previousHash', 'hash', 'size', 'cid', 'mac'},
             'snapshot head fields required')
        need(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', str(value['workspaceId'])) and type(value['version']) is int and value['version'] > 0 and
             isinstance(value['hash'], str) and HEX.fullmatch(value['hash']) and isinstance(value['previousHash'], str) and
             HEX.fullmatch(value['previousHash']) and type(value['size']) is int and 29 <= value['size'] <= MAX_BYTES,
             'bounded snapshot metadata required')
        need(value['cid'] is None or isinstance(value['cid'], str) and CID.fullmatch(value['cid']), 'snapshot CID required')
        return dict(value)

    def key(self, wallet, head):
        return wallet + ':' + head['workspaceId'] + ':' + str(head['version'])

    def part(self, upload_id):
        need(isinstance(upload_id, str) and re.fullmatch(r'[0-9a-f]{32}', upload_id), 'upload ID required')
        return self.root / 'uploads' / (upload_id + '.part')

    def blob(self, digest):
        need(isinstance(digest, str) and HEX.fullmatch(digest), 'ciphertext hash required')
        return self.root / 'blobs' / (digest + '.sealed')

    def remove(self, path):
        if not path.exists():
            return
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
             'retention target is not an exact owned regular file', 500)
        path.unlink()

    def prune(self):
        cutoff = self.now() - RETENTION_SECONDS
        expired = [key for key, value in self.state['snapshots'].items() if value['usedAt'] < cutoff]
        old_uploads = [key for key, value in self.state['uploads'].items() if value['usedAt'] < cutoff]
        old_hashes = {self.state['snapshots'][key]['head']['hash'] for key in expired}
        for key in expired:
            del self.state['snapshots'][key]
        for key in old_uploads:
            self.remove(self.part(key))
            del self.state['uploads'][key]
        active = list(self.state['snapshots'].values())
        for digest in old_hashes - {value['head']['hash'] for value in active}:
            self.remove(self.blob(digest))
            self.checked.pop(digest, None)
        active_cids = {value['head']['cid'] for value in active}
        removed_pins = 0
        for cid in list(self.state['ownedPins']):
            if cid not in active_cids and not any(value['head'].get('cid') == cid and value['usedAt'] >= cutoff
                                                 for value in self.state['uploads'].values()):
                self.kubo.unpin(cid)
                del self.state['ownedPins'][cid]
                removed_pins += 1
        if expired or old_uploads or removed_pins:
            self.save()
        return {'snapshotsRemoved': len(expired), 'uploadsRemoved': len(old_uploads)}

    def pin(self, cid):
        if not self.kubo.pinned(cid):
            # Record only a pin this store creates. Existing unrelated recursive
            # pins are never removed by workspace retention.
            self.state['ownedPins'][cid] = True
            self.save()
            self.kubo.pin(cid)

    def call(self, action, body):
        with self.lock:
            self.prune()
            wallet = body['wallet']
            if action == 'begin':
                head = self.head(body['head'])
                need(head['mac'] == self.publisher, 'snapshot targets another Mac', 409)
                path = self.part(body['uploadId'])
                saved = self.state['snapshots'].get(self.key(wallet, head))
                if saved:
                    need(all(saved['head'][key] == head[key] for key in ('workspaceId', 'version', 'previousHash', 'hash', 'size')),
                         'snapshot version already has different ciphertext', 409)
                    saved['usedAt'] = self.now()
                    self.save()
                    return {'committed': True, 'head': saved['head'], 'offset': head['size']}
                upload = self.state['uploads'].get(body['uploadId'])
                if upload:
                    need(upload['wallet'] == wallet and upload['head'] == head, 'upload ID changed owner or snapshot', 409)
                else:
                    with path.open('xb'):
                        os.chmod(path, 0o600)
                    upload = {'wallet': wallet, 'head': head, 'usedAt': self.now()}
                    self.state['uploads'][body['uploadId']] = upload
                upload['usedAt'] = self.now()
                if not path.exists() and self.blob(head['hash']).exists():
                    # The immutable ciphertext rename may precede the metadata
                    # commit when this service is interrupted. Finish that commit.
                    result = self.call('commit', {'wallet': wallet, 'uploadId': body['uploadId']})
                    return {'committed': True, 'head': result['head'], 'offset': head['size']}
                self.save()
                return {'offset': path.stat().st_size}
            if action == 'read':
                head = self.head(body['head'])
                need(head['cid'], 'committed snapshot CID required')
                offset, length = body['offset'], body['length']
                need(type(offset) is int and 0 <= offset <= head['size'] and type(length) is int and 0 < length <= CHUNK_BYTES,
                     'bounded ciphertext range required')
                path = self.blob(head['hash'])
                fetched = not path.exists()
                if fetched:
                    temporary = self.root / 'uploads' / (os.urandom(16).hex() + '.part')
                    self.kubo.fetch(head['cid'], temporary, head['size'], head['hash'])
                    os.replace(temporary, path)
                    self.pin(head['cid'])
                info = path.stat()
                if self.checked.get(head['hash']) != (info.st_size, info.st_mtime_ns):
                    need(info.st_size == head['size'] and sha(path) == head['hash'], 'cached ciphertext hash/size mismatch', 502)
                    self.checked[head['hash']] = (info.st_size, info.st_mtime_ns)
                with path.open('rb') as source:
                    source.seek(offset)
                    data = source.read(min(length, head['size'] - offset))
                local_head = dict(head, mac=self.publisher)
                self.state['snapshots'][self.key(wallet, head)] = {'head': local_head, 'usedAt': self.now()}
                self.save()
                return {'head': local_head, 'data': base64.b64encode(data).decode(), 'offset': offset,
                        'nextOffset': offset + len(data), 'source': 'ipfs' if fetched else 'mac', 'ipfsFetched': fetched}
            need(action in ('chunk', 'commit'), 'workspace store route not found', 404)
            path = self.part(body['uploadId'])
            upload = self.state['uploads'].get(body['uploadId'])
            need(upload and upload['wallet'] == wallet, 'workspace upload does not belong to wallet', 403)
            if action == 'chunk':
                need(isinstance(body['data'], str) and len(body['data']) <= 4 * ((CHUNK_BYTES + 2) // 3), 'ciphertext chunk too large')
                try:
                    data = base64.b64decode(body['data'], validate=True)
                except ValueError:
                    raise StoreError('standard base64 ciphertext required') from None
                offset = body['offset']
                need(type(offset) is int and offset >= 0 and 0 < len(data) <= CHUNK_BYTES and offset + len(data) <= upload['head']['size'],
                     'ciphertext chunk outside snapshot size')
                need(path.exists(), 'upload already committed', 409)
                size = path.stat().st_size
                need(offset <= size, 'ciphertext upload has a gap', 409)
                with path.open('r+b') as output:
                    output.seek(offset)
                    if offset < size:
                        need(offset + len(data) <= size and output.read(len(data)) == data, 'replayed ciphertext chunk differs', 409)
                    else:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                upload['usedAt'] = self.now()
                self.save()
                return {'offset': path.stat().st_size}
            head = upload['head']
            saved = self.state['snapshots'].get(self.key(wallet, head))
            if saved:
                need(saved['head']['hash'] == head['hash'], 'snapshot version ciphertext differs', 409)
                return {'head': saved['head']}
            source = path if path.exists() else self.blob(head['hash'])
            need(source.exists() and source.stat().st_size == head['size'] and sha(source) == head['hash'],
                 'uploaded ciphertext hash/size mismatch', 409)
            cid = self.kubo.add_file(source)
            self.pin(cid)
            final_head = dict(head, cid=cid)
            destination = self.blob(head['hash'])
            if path.exists():
                if destination.exists():
                    need(sha(destination) == head['hash'], 'existing ciphertext cache differs', 502)
                    self.remove(path)
                else:
                    os.replace(path, destination)
            upload.update(head=final_head, usedAt=self.now())
            self.state['snapshots'][self.key(wallet, head)] = {'head': final_head, 'usedAt': self.now()}
            self.save()
            return {'head': final_head}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            need(0 < size <= 1024 * 1024, 'workspace request exceeds 1 MiB')
            self.connection.settimeout(15)
            body = json.loads(self.rfile.read(size))
            need(isinstance(body, dict), 'workspace request object required')
            action = self.path.lstrip('/')
            self.server.store.authorize(action, body)
            result = self.server.store.call(action, body)
            status = 200
        except StoreError as error:
            result, status = {'error': {'code': error.code, 'message': str(error)}}, error.status
        except (ValueError, KeyError, TypeError):
            result, status = {'error': {'code': 'WORKSPACE_STORE_REQUEST', 'message': 'invalid workspace request'}}, 400
        except (OSError, http.client.HTTPException):
            result, status = {'error': {'code': 'WORKSPACE_STORE_IO', 'message': 'workspace storage or IPFS unavailable'}}, 503
        raw = canonical(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    next_prune = 0

    def service_actions(self):
        if time.monotonic() >= self.next_prune:
            self.next_prune = time.monotonic() + 3600
            try:
                with self.store.lock:
                    result = self.store.prune()
                if any(result.values()):
                    print(canonical({'event': 'workspace-retention', **result}), flush=True)
            except (StoreError, OSError, http.client.HTTPException) as error:
                print(canonical({'event': 'workspace-retention-retry', 'error': type(error).__name__}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--publisher', required=True)
    parser.add_argument('--broker-signer', required=True)
    parser.add_argument('--port', type=int, default=15093)
    parser.add_argument('--ipfs-api', default='http://127.0.0.1:15092')
    args = parser.parse_args()
    store = WorkspaceStore(args.state, args.publisher, args.broker_signer, Kubo(args.ipfs_api))
    with Server(('127.0.0.1', args.port), Handler) as server:
        server.store = store
        server.serve_forever()


if __name__ == '__main__':
    main()
