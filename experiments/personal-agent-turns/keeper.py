"""Head-keeping KMS for agent turns on the mac-compose runner.

The installed runner (built 9 October) predates app ids: its clientData has no app and its
parcel is {api_key, app_key}. The keeper's own app_key, constant across turns, plays the app role.
It speaks the runner's KMS protocol (GET /nonce, POST /release; private-code runner/kms/kms.py)
but admits only the compose for the current head: the turn's STATE_IN is in the compose
environment, so a turn started from any other state has a different compose_hash and gets
no app_key. A guest commits its turn with POST /commit; the keeper checks the App Attest
evidence over {state_in, state_out, turn} and advances the head. GET /state/<sha256> serves
stored ciphertext.

usage: keeper.py --state DIR --cdhash HEX --app APP --image REF@sha256:... --port N [--genesis]
"""
import argparse, base64, hashlib, json, os, secrets, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from verifier.core import Reject, require, unb64, unique_json, verify_assertion, verify_attestation
from verifier.macos_policy import policy, root
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p = argparse.ArgumentParser()
p.add_argument('--state', type=Path, required=True)
p.add_argument('--cdhash', required=True)
p.add_argument('--app', required=True)
p.add_argument('--image', required=True)
p.add_argument('--port', type=int, required=True)
p.add_argument('--genesis', action='store_true')
args = p.parse_args()

canonical = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':')).encode()
hkdf = lambda ikm, info: HKDF(hashes.SHA256(), 32, None, info.encode()).derive(ikm)
blobs = args.state / 'blobs'
if args.genesis:
    args.state.mkdir()
    blobs.mkdir()
    (args.state / 'master.key').write_bytes(os.urandom(32))
MASTER = (args.state / 'master.key').read_bytes()
APP_KEY = hkdf(MASTER, f'mac-compose-app-key/1|{args.app}')
state_key = lambda turn: hkdf(APP_KEY, f'mac-compose-get-key/1|agent-state/{turn}')


def compose(head, turn):
    service = {'image': args.image, 'command': ['python3', '/turn.py'],
               'environment': {'STATE_IN': head, 'TURN': str(turn), 'KEEPER_PORT': str(args.port)}}
    return canonical({'docker_compose_file': canonical({'services': {'turn': service}}).decode(),
                      'egress': {'allow': [], 'max_requests': 16, 'max_tokens': 0, 'tcp': [{'host': '127.0.0.1', 'port': args.port}]},
                      'kms_enabled': True, 'manifest_version': 2, 'name': 'personal-agent-turns', 'runner': 'docker-compose'})


def store(blob):
    h = hashlib.sha256(blob).hexdigest()
    (blobs / h).write_bytes(blob)
    return h


def set_head(head, turn):
    c = compose(head, turn)
    (args.state / f'compose-turn-{turn}.json').write_bytes(c)
    (args.state / 'head.json').write_bytes(canonical({'head': head, 'turn': turn, 'compose_hash': hashlib.sha256(c).hexdigest()}))


if args.genesis:
    nonce = os.urandom(12)
    set_head(store(nonce + AESGCM(state_key(1)).encrypt(nonce, canonical({'counter': 0, 'log': []}), b'agent-state')), 1)
HEAD = json.loads((args.state / 'head.json').read_bytes())
POLICY = policy(bytes.fromhex(args.cdhash))
NONCES = {}


def log(event):
    with (args.state / 'events.jsonl').open('a') as f:
        f.write(json.dumps({'at': time.time(), **event}, sort_keys=True) + '\n')


def release(req):
    client_data = unb64(req['client_data'])
    client = unique_json(client_data)
    require(req['mode'] == 'attested' and client['attested'] is True, 'attested_request_required')
    info = verify_attestation(unb64(req['attestation']), req['key_id'], client_data, POLICY, root())
    require(info['signals']['cdhash'] == args.cdhash, 'build_not_allowed')
    require(client['domain'] == 'mac-compose-boot/1', 'wrong_client_data_domain')
    issued = NONCES.pop(client['nonce'], None)
    require(issued is not None and time.time() - issued < 60, 'unknown_or_stale_nonce')
    require(client['compose_hash'] == HEAD['compose_hash'], 'stale_head: compose is not the current head')
    kms_key = ec.generate_private_key(ec.SECP256R1())
    shared = kms_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client['eph_pub'])))
    nonce = os.urandom(12)
    parcel = canonical({'api_key': 'synthetic-not-a-credential', 'app_key': APP_KEY.hex()})
    sealed = nonce + AESGCM(hkdf(shared, 'mac-compose-key-release/1')).encrypt(nonce, parcel, hashlib.sha256(client_data).digest())
    return {'epk': base64.b64encode(kms_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode(),
            'sealed': base64.b64encode(sealed).decode()}


def commit(req):
    global HEAD
    ev, ct = req['evidence'], base64.b64decode(req['ciphertext'])
    transition = {k: req[k] for k in ('state_in', 'state_out', 'turn')}
    require(ev['type'] == 'macrunner', 'not_macrunner_evidence')
    enroll_bytes, assert_bytes = unb64(ev['bootClientData']), unb64(ev['assertClientData'])
    att = verify_attestation(unb64(ev['attestation']), ev['keyId'], enroll_bytes, POLICY, root())
    sig = verify_assertion(unb64(ev['assertion']), assert_bytes, att['public_key'], 0, POLICY)
    enroll, assertion = unique_json(enroll_bytes), unique_json(assert_bytes)
    require(assertion['domain'] == 'mac-compose-assert/1', 'wrong_assert_domain')
    require(enroll['compose_hash'] == assertion['compose_hash'] == HEAD['compose_hash'], 'stale_head: evidence is not for the current head')
    require(assertion['data'] == canonical(transition).decode(), 'assertion_does_not_cover_transition')
    require(transition['state_in'] == HEAD['head'] and transition['turn'] == HEAD['turn'], 'stale_head: state_in is not the current head')
    require(hashlib.sha256(ct).hexdigest() == transition['state_out'], 'ciphertext_does_not_match_state_out')
    store(ct)
    receipt = {**transition, 'compose_hash': HEAD['compose_hash'], 'cdhash': sig['signals']['cdhash'],
               'key_id': ev['keyId'], 'evidence_sha256': hashlib.sha256(canonical(ev)).hexdigest()}
    (args.state / f'evidence-turn-{HEAD["turn"]}.json').write_bytes(canonical(ev))
    with (args.state / 'receipts.jsonl').open('a') as f:
        f.write(json.dumps(receipt, sort_keys=True) + '\n')
    set_head(transition['state_out'], HEAD['turn'] + 1)
    HEAD = json.loads((args.state / 'head.json').read_bytes())
    return {'ok': True, 'head': HEAD}


class H(BaseHTTPRequestHandler):
    def reply(self, code, body, kind='application/json'):
        self.send_response(code)
        self.send_header('content-type', kind)
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/nonce':
            nonce = secrets.token_hex(32)
            NONCES[nonce] = time.time()
            return self.reply(200, canonical({'nonce': nonce}))
        if self.path == '/head':
            return self.reply(200, canonical(HEAD))
        h = self.path.removeprefix('/state/')
        require(len(h) == 64 and all(c in '0123456789abcdef' for c in h), 'not_found')
        self.reply(200, (blobs / h).read_bytes(), 'application/octet-stream')

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        op = {'/release': release, '/commit': commit}[self.path]
        try:
            out = op(req)
            log({'op': self.path, 'ok': True, 'head': HEAD})
            self.reply(200, canonical(out))
        except Reject as e:
            log({'op': self.path, 'ok': False, 'error': str(e), 'head': HEAD})
            self.reply(403, canonical({'error': str(e)}))


ThreadingHTTPServer(('127.0.0.1', args.port), H).serve_forever()
