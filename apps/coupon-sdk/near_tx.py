"""Minimal NEAR Transfer signer over JSON-RPC (borsh by hand; stdlib + cryptography). Keys stay in memory."""
import base64, hashlib, http.client, json, os, socket, ssl, urllib.parse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(b):
    n, out = int.from_bytes(b, 'big'), ''
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + out


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return b'\0' * (len(s) - len(s.lstrip('1'))) + body


class EgressHTTPS(http.client.HTTPSConnection):
    """TLS from the guest through the runner's CONNECT tunnel on /run/egress.sock (an egress.tcp entry)."""
    def connect(self):
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        raw.connect('/run/egress.sock')
        raw.sendall(f'CONNECT {self.host}:443 HTTP/1.1\r\nHost: {self.host}:443\r\n\r\n'.encode())
        header = b''
        while not header.endswith(b'\r\n\r\n'):
            header += raw.recv(1)
        if header.split(b' ', 2)[1] != b'200':
            raise ConnectionError(f'CONNECT {self.host} refused: {header[:64]!r}')
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


TRANSPORTS = {'egress': EgressHTTPS, 'direct': http.client.HTTPSConnection}


def rpc(url, method, params):
    u = urllib.parse.urlsplit(url)
    conn = TRANSPORTS[os.environ['NEAR_TRANSPORT']](u.hostname, timeout=60, context=ssl.create_default_context())
    conn.request('POST', u.path or '/', json.dumps({'jsonrpc': '2.0', 'id': 'x', 'method': method, 'params': params}),
                 {'content-type': 'application/json'})
    res = conn.getresponse()
    if res.status != 200:
        raise RuntimeError(f'NEAR RPC {method}: HTTP {res.status}')
    reply = json.loads(res.read())
    if 'error' in reply:
        raise RuntimeError(json.dumps(reply['error']))
    return reply['result']


def public(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def implicit_account(seed):
    return public(seed).hex()


def string(x):
    b = x.encode()
    return len(b).to_bytes(4, 'little') + b


def transfer(url, seed, signer_id, receiver_id, yocto):
    """Signs and submits one Transfer; returns the final RPC result (status, transaction.hash)."""
    pub = public(seed)
    key = rpc(url, 'query', {'request_type': 'view_access_key', 'finality': 'final', 'account_id': signer_id,
                             'public_key': 'ed25519:' + b58encode(pub)})
    tx = (string(signer_id) + b'\0' + pub + (key['nonce'] + 1).to_bytes(8, 'little') + string(receiver_id)
          + b58decode(key['block_hash']) + (1).to_bytes(4, 'little') + b'\x03' + yocto.to_bytes(16, 'little'))
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(hashlib.sha256(tx).digest())
    return rpc(url, 'broadcast_tx_commit', [base64.b64encode(tx + b'\0' + sig).decode()])


def balance(url, account_id):
    return int(rpc(url, 'query', {'request_type': 'view_account', 'finality': 'final', 'account_id': account_id})['amount'])
