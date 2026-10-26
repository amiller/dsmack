"""One agent turn inside the mac-compose runner: fetch the state blob, decrypt it with
/key, increment the counter, re-encrypt for the next turn, assert the transition with
/attest and commit it to the coordinator (applications/coordinator)."""
import base64, hashlib, json, os, socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STATE_IN, TURN, PORT = os.environ['STATE_IN'], int(os.environ['TURN']), int(os.environ['KEEPER_PORT'])
canonical = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':')).encode()


def http(sock, method, host, path, body=b''):
    sock.sendall(f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n'
                 f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
    # Read by Content-Length: the runner's CONNECT relay does not pass the server's close through.
    raw = b''
    while b'\r\n\r\n' not in raw:
        raw += sock.recv(65536)
    head, _, data = raw.partition(b'\r\n\r\n')
    length = int(next(l.split(b':', 1)[1] for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')))
    while len(data) < length:
        data += sock.recv(65536)
    status = int(head.split(b' ')[1])
    assert status == 200, (method, host, path, status, data[:500])
    return data


def egress():
    s = socket.socket(socket.AF_UNIX)
    s.connect('/run/egress.sock')
    return s


def runner(path, obj):
    return json.loads(http(egress(), 'POST', 'runner.local', path, canonical(obj)))


def coordinator(method, path, body=b''):
    s = egress()
    s.sendall(f'CONNECT 127.0.0.1:{PORT} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n'.encode())
    head = b''
    while b'\r\n\r\n' not in head:
        head += s.recv(1)
    assert b' 200' in head.split(b'\r\n')[0], head
    return http(s, method, '127.0.0.1', path, body)


key = lambda turn: bytes.fromhex(runner('/key', {'path': f'agent-state/{turn}'})['key'])
blob = coordinator('GET', f'/turn/state/{STATE_IN}')
assert hashlib.sha256(blob).hexdigest() == STATE_IN, 'state blob does not match STATE_IN'
state = json.loads(AESGCM(key(TURN)).decrypt(blob[:12], blob[12:], b'agent-state'))
state = {'counter': state['counter'] + 1, 'log': state['log'] + [f'turn {TURN} ran on the mini']}
nonce = os.urandom(12)
out = nonce + AESGCM(key(TURN + 1)).encrypt(nonce, canonical(state), b'agent-state')
transition = {'state_in': STATE_IN, 'state_out': hashlib.sha256(out).hexdigest(), 'turn': TURN}
evidence = runner('/attest', {'data': canonical(transition).decode()})
reply = coordinator('POST', '/turn/commit', canonical({'ciphertext': base64.b64encode(out).decode(), 'evidence': evidence, **transition}))
print(json.dumps({'transition': transition, 'counter': state['counter'], 'coordinator': json.loads(reply)}))
