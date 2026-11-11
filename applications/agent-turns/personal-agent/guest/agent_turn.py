"""One personal-agent turn in a dsmack guest.

The agent's root secret comes from the secret-release policy: /v1/Attest with report_data binding the
request, POST {task_id, attestation} to $POLICY/release, /v1/GetSecret on the reply. The head and its state
blob come from $STATE, which is untrusted: the turn signs (turn, state_in, state_out) for TurnHeads with a
key derived from the secret, and the contract moves the head only from its current value. Writes the new
state ciphertext and the signed commit to /workspace/artifacts.

`python3 agent_turn.py address` prints the agent's address for the secret hex on stdin, at provisioning.
"""
import hashlib, hmac, http.client, json, os, socket, sys, urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dsmack_dstack import G, _mul, derive, keccak256, sign

OUT = '/workspace/artifacts/'
GENESIS = {'counter': 0, 'log': []}


class Dstack(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect('/var/run/dstack.sock')


def request(conn, method, path, body=None):
    conn.request(method, path, body and json.dumps(body), {'Content-Type': 'application/json'})
    r = conn.getresponse()
    data = r.read()
    assert r.status == 200, (path, r.status, data[:500])
    return data


def url(base, method, path, body=None):
    u = urllib.parse.urlsplit(base)
    return request((http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection)(u.netloc, timeout=60),
                   method, u.path + path, body)


def release(task, policy):
    rd = hashlib.sha256(b'dsmack.secret-request/1' + task.encode()).digest() + bytes(32)
    att = json.loads(request(Dstack('localhost'), 'POST', '/v1/Attest', {'report_data': rd.hex()}))['attestation']
    sealed = json.loads(url(policy, 'POST', '/release', {'task_id': task, 'attestation': att}))
    return bytes.fromhex(json.loads(request(Dstack('localhost'), 'POST', '/v1/GetSecret', dict(task_id=task, **sealed)))['secret'])


def state_key(secret, turn):
    return hmac.new(secret, b'agent-state/%d' % turn, hashlib.sha256).digest()


def agent_key(secret):
    key = derive(secret, 'agent-commit/1', 'secp256k1')[0]
    x, y = _mul(int.from_bytes(key, 'big'), G)
    return key, '0x' + keccak256(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[12:].hex()


def digest(chain_id, heads, turn, state_in, state_out):
    """TurnHeads.digest: keccak256(abi.encode(chainid, heads, turn, stateIn, stateOut))."""
    return keccak256(int(chain_id).to_bytes(32, 'big') + bytes(12) + bytes.fromhex(heads[2:])
                     + turn.to_bytes(32, 'big') + bytes.fromhex(state_in) + bytes.fromhex(state_out))


def step(secret, chain_id, heads, turn, state_in, blob):
    """The turn proper: (head, blob) -> (new blob, commit) for TurnHeads at heads on chain_id."""
    if turn:
        assert hashlib.sha256(blob).hexdigest() == state_in, 'state blob does not match the head'
        state = json.loads(AESGCM(state_key(secret, turn)).decrypt(blob[:12], blob[12:], b'agent-state'))
    else:
        assert state_in == '00' * 32, 'a new agent starts at state 0'
        state = GENESIS
    state = {'counter': state['counter'] + 1, 'log': state['log'] + [f'turn {turn} ran in a dsmack guest']}
    nonce = os.urandom(12)
    out = nonce + AESGCM(state_key(secret, turn + 1)).encrypt(nonce, json.dumps(state, sort_keys=True).encode(), b'agent-state')
    state_out = hashlib.sha256(out).hexdigest()
    key, agent = agent_key(secret)
    sig = sign(key, digest(chain_id, heads, turn, state_in, state_out))
    return out, {'agent': agent, 'turn': turn, 'state_in': state_in, 'state_out': state_out,
                 'v': 27 + sig[64], 'r': sig[:32].hex(), 's': sig[32:64].hex()}


if __name__ == '__main__' and sys.argv[1:] == ['address']:
    print(agent_key(bytes.fromhex(sys.stdin.read().strip()))[1])
elif __name__ == '__main__':
    e = os.environ
    head = json.loads(url(e['STATE'], 'GET', '/head.json'))
    blob = url(e['STATE'], 'GET', '/' + head['state']) if head['turn'] else b''
    out, commit = step(release(e['TASK'], e['POLICY']), e['CHAIN_ID'], e['HEADS'], head['turn'], head['state'], blob)
    open(OUT + 'state', 'wb').write(out)
    open(OUT + 'commit', 'w').write(json.dumps(commit))
    print(json.dumps(commit))
