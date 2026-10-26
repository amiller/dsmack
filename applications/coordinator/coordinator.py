"""dsmack coordinator, a dstack app: it holds the keys and the agent heads; Macs run turns.

Keys come from the app's own dstack GetKey on /var/run/dstack.sock: the release authority
(ed25519, signs releases and per-attempt workload admissions), one app key per agent, and the
per-(turn, Mac) worker grants of dstack-compat/grant.py. State lives in /state, the app's
encrypted volume.

Turns speak the mac-compose runner's KMS protocol (run it with --kms http://<host>/turn).
A turn's STATE_IN is in its compose environment, so a compose hash names one (agent, head).
/turn/release gives the turn key only to an App Attest launch of a CDRegistry-admitted build
whose compose is an agent's current head; /turn/commit advances that head once.

env: OPERATOR_TOKEN, API_KEY, RPC_URL, CDREGISTRY
"""
import base64, datetime, hashlib, hmac, json, os, re, secrets, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / 'dstack-compat')]
from verifier.core import Policy, Reject, require, unb64, unique_json, verify_assertion, verify_attestation
from verifier.macos_policy import APP_ID, MACOS_VALIDATION_CATEGORY, root
from grant import call, mint
from dsmack_dstack import keccak256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SOCK, STATE = '/var/run/dstack.sock', Path('/state')
TOKEN, API_KEY, RPC_URL, CDREGISTRY = (os.environ[k] for k in ('OPERATOR_TOKEN', 'API_KEY', 'RPC_URL', 'CDREGISTRY'))
HEX64, HEX32, NAME = re.compile('[0-9a-f]{64}'), re.compile('[0-9a-f]{32}'), re.compile('[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
POLICY = Policy(APP_ID, environment='production', categories=(MACOS_VALIDATION_CATEGORY,), require_macos_acl=True)
RP_ID_HASH = hashlib.sha256(APP_ID.encode()).digest()
LOCK = threading.Lock()

canonical = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
sha = lambda b: hashlib.sha256(b).hexdigest()
hkdf = lambda ikm, info: HKDF(hashes.SHA256(), 32, None, info.encode()).derive(ikm)
get_key = lambda domain, alg: call(SOCK, 'GetKey', {'domain': domain, 'algorithm': alg})
stamp = lambda t: t.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

RELEASE = get_key('dsmack-release-authority/1', 'ed25519')
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RELEASE['key']))
KEY_ID = 'dsmack-coordinator-' + RELEASE['public_key'][:16]
KEYS = canonical({'key_id': KEY_ID, 'public_key': RELEASE['public_key'], 'signature_chain': RELEASE['signature_chain'],
                  'public_pem': SIGNER.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                  'app_id': call(SOCK, 'Info', {})['app_id']})
for d in ('agents', 'heads', 'blobs', 'nonces', 'releases', 'attempts'):
    (STATE / d).mkdir(parents=True, exist_ok=True)


def log(event):
    with (STATE / 'events.jsonl').open('a') as f:
        f.write(json.dumps({'at': time.time(), **event}, sort_keys=True) + '\n')


def registry_rp(cdhash):
    data = '0x' + keccak256(b'rpIdHash(bytes32)')[:4].hex() + cdhash
    body = canonical({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': CDREGISTRY, 'data': data}, 'latest']})
    reply = json.loads(urllib.request.urlopen(urllib.request.Request(RPC_URL, body, {'content-type': 'application/json'}), timeout=10).read())
    return bytes.fromhex(reply['result'][2:])


def launch(attestation, key_id, client_data):
    """App Attest chain to Apple's root under the macOS policy; the attested CDHash must resolve in CDRegistry to our RP ID."""
    info = verify_attestation(unb64(attestation), key_id, client_data, POLICY, root())
    cdhash = info['signals']['cdhash']
    require(cdhash is not None and HEX64.fullmatch(cdhash), 'missing_cdhash')
    require(registry_rp(cdhash) == RP_ID_HASH, 'build_not_in_cdregistry')
    return info


def compose(agent, head, turn):
    cfg = json.loads((STATE / 'agents' / agent / 'config.json').read_bytes())
    service = {'image': cfg['image'], 'command': ['python3', '/turn.py'],
               'environment': {'STATE_IN': head, 'TURN': str(turn), 'KEEPER_PORT': str(cfg['port'])}}
    return canonical({'docker_compose_file': canonical({'services': {'turn': service}}).decode(),
                      'egress': {'allow': [], 'max_requests': 16, 'max_tokens': 0, 'tcp': [{'host': '127.0.0.1', 'port': cfg['port']}]},
                      'kms_enabled': True, 'manifest_version': 2, 'name': 'personal-agent-turns', 'runner': 'docker-compose'})


def store(blob):
    (STATE / 'blobs' / sha(blob)).write_bytes(blob)
    return sha(blob)


def set_head(agent, head, turn, old=None):
    c = compose(agent, head, turn)
    d = STATE / 'agents' / agent
    (d / f'compose-turn-{turn}.json').write_bytes(c)
    (d / 'head.json').write_bytes(canonical({'head': head, 'turn': turn, 'compose_hash': sha(c)}))
    (STATE / 'heads' / sha(c)).write_text(agent)
    if old:
        (STATE / 'heads' / old).unlink()
    return json.loads((d / 'head.json').read_bytes())


def head_of(compose_hash, reason):
    require(isinstance(compose_hash, str) and HEX64.fullmatch(compose_hash), 'bad_compose_hash')
    index = STATE / 'heads' / compose_hash
    require(index.exists(), reason)
    agent = index.read_text()
    return agent, json.loads((STATE / 'agents' / agent / 'head.json').read_bytes())


def take_nonce(nonce):
    require(isinstance(nonce, str) and HEX64.fullmatch(nonce) and (STATE / 'nonces' / nonce).exists(), 'unknown_or_stale_nonce')
    issued = float((STATE / 'nonces' / nonce).read_text())
    (STATE / 'nonces' / nonce).unlink()
    require(time.time() - issued < 60, 'unknown_or_stale_nonce')


def genesis(req):
    agent = req['agent']
    require(isinstance(agent, str) and NAME.fullmatch(agent), 'bad_agent_name')
    d = STATE / 'agents' / agent
    require(not d.exists(), 'agent_exists')
    d.mkdir()
    (d / 'config.json').write_bytes(canonical({'image': req['image'], 'port': int(req['port'])}))
    return set_head(agent, store(base64.b64decode(req['ciphertext'])), 1)


def release(req):
    client_data = unb64(req['client_data'])
    client = unique_json(client_data)
    require(req['mode'] == 'attested' and client['attested'] is True, 'attested_request_required')
    require(client['domain'] == 'mac-compose-boot/1', 'wrong_client_data_domain')
    launch(req['attestation'], req['key_id'], client_data)
    agent, head = head_of(client['compose_hash'], 'stale_head: compose is not the current head')
    if 'app' in client:
        require(client['app'] == agent, 'wrong_app')
    take_nonce(client['nonce'])
    parcel = {'api_key': API_KEY, 'app_key': get_key(f'agent-app-key/1/{agent}', 'ed25519')['key'],
              **({'app': agent} if 'app' in client else {})}
    grant = mint(SOCK, f'{agent}:{head["turn"]}', req['key_id'], head['compose_hash'], 600)
    kms_key = ec.generate_private_key(ec.SECP256R1())
    shared = kms_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client['eph_pub'])))
    aad = hashlib.sha256(client_data).digest()

    def seal(info, obj):
        n = os.urandom(12)
        return base64.b64encode(n + AESGCM(hkdf(shared, info)).encrypt(n, canonical(obj), aad)).decode()
    return {'epk': base64.b64encode(kms_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode(),
            'sealed': seal('mac-compose-key-release/1', parcel), 'grant': seal('dsmack-coordinator-grant/1', grant)}


def commit(req):
    ev, ct = req['evidence'], base64.b64decode(req['ciphertext'])
    transition = {k: req[k] for k in ('state_in', 'state_out', 'turn')}
    require(ev['type'] == 'macrunner', 'not_macrunner_evidence')
    enroll_bytes, assert_bytes = unb64(ev['bootClientData']), unb64(ev['assertClientData'])
    att = launch(ev['attestation'], ev['keyId'], enroll_bytes)
    sig = verify_assertion(unb64(ev['assertion']), assert_bytes, att['public_key'], 0, POLICY)
    enroll, assertion = unique_json(enroll_bytes), unique_json(assert_bytes)
    require(assertion['domain'] == 'mac-compose-assert/1', 'wrong_assert_domain')
    require(enroll['compose_hash'] == assertion['compose_hash'], 'assertion_not_for_launched_compose')
    agent, head = head_of(assertion['compose_hash'], 'stale_head: evidence is not for the current head')
    require(assertion['data'] == canonical(transition).decode(), 'assertion_does_not_cover_transition')
    require(transition['state_in'] == head['head'] and transition['turn'] == head['turn'], 'stale_head: state_in is not the current head')
    require(sha(ct) == transition['state_out'], 'ciphertext_does_not_match_state_out')
    store(ct)
    receipt = {**transition, 'agent': agent, 'compose_hash': head['compose_hash'], 'cdhash': sig['signals']['cdhash'],
               'key_id': ev['keyId'], 'evidence_sha256': sha(canonical(ev))}
    with (STATE / 'agents' / agent / 'receipts.jsonl').open('a') as f:
        f.write(json.dumps(receipt, sort_keys=True) + '\n')
    return {'ok': True, 'head': set_head(agent, transition['state_out'], head['turn'] + 1, head['compose_hash'])}


def sign(schema, raw):
    return base64.b64encode(SIGNER.sign(schema.encode() + b'\0' + raw)).decode()


def sign_release(req):
    inv = req['inventory']
    require(inv['key_id'] == KEY_ID, 'wrong_key_id')
    raw = canonical(inv)
    (STATE / 'releases' / (sha(raw) + '.json')).write_bytes(raw)
    return {'inventory': raw.decode(), 'inventory_sha256': sha(raw), 'signature': sign(inv['schema'], raw)}


def admit(req):
    """One workload admission per attempt, for a profile of a release this app signed."""
    h = req['release_inventory_sha256']
    require(isinstance(h, str) and HEX64.fullmatch(h) and (STATE / 'releases' / (h + '.json')).exists(), 'unknown_release')
    inv = json.loads((STATE / 'releases' / (h + '.json')).read_bytes())
    profile_raw = canonical(req['profile'])
    entry = next((p for p in inv['profiles'] if p['descriptor_sha256'] == sha(profile_raw)), None)
    require(entry is not None, 'profile_not_in_release')
    closure, disk = req['closure_context'], req['workload_disk']
    attempt = closure.get('attempt_id')
    require(isinstance(attempt, str) and HEX32.fullmatch(attempt) and closure == {
        'schema': 'dsmack-result-closure-context/1', 'attempt_id': attempt, 'selectors': [entry['profile_id']]}, 'bad_closure_context')
    require(set(disk) == {'bytes', 'sha256'} and type(disk['bytes']) is int and disk['bytes'] > 0
            and isinstance(disk['sha256'], str) and HEX64.fullmatch(disk['sha256']), 'bad_workload_disk')
    try:
        os.close(os.open(STATE / 'attempts' / attempt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        raise Reject('attempt_already_admitted') from None
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = min(now + datetime.timedelta(hours=2), datetime.datetime.fromisoformat(inv['expires_at'].replace('Z', '+00:00')))
    admission = {'schema': 'dsmack-alpha-workload-admission/1', 'key_id': KEY_ID, 'release_inventory_sha256': h,
                 'profile_id': entry['profile_id'],
                 'compose_manifest_sha256': req['profile']['execution_profile']['compose_manifest_sha256'],
                 'attempt_id': attempt, 'closure_context_sha256': sha(canonical(closure)), 'workload_disk': disk,
                 'issued_at': stamp(now), 'expires_at': stamp(expires)}
    raw = canonical(admission)
    return {'admission': raw.decode(), 'signature': sign(admission['schema'], raw)}


POSTS = {'/turn/release': (release, False), '/turn/commit': (commit, False),
         '/agent': (genesis, True), '/sign-release': (sign_release, True), '/admit': (admit, True)}


class H(BaseHTTPRequestHandler):
    def reply(self, code, body, kind='application/json'):
        self.send_response(code)
        self.send_header('content-type', kind)
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/turn/nonce':
            nonce = secrets.token_hex(32)
            (STATE / 'nonces' / nonce).write_text(str(time.time()))
            return self.reply(200, canonical({'nonce': nonce}))
        if self.path == '/keys':
            return self.reply(200, KEYS)
        kind, _, name = self.path.removeprefix('/').partition('/')
        if kind in ('head', 'compose') and NAME.fullmatch(name) and (STATE / 'agents' / name).exists():
            head = (STATE / 'agents' / name / 'head.json').read_bytes()
            return self.reply(200, head if kind == 'head' else (STATE / 'agents' / name / f'compose-turn-{json.loads(head)["turn"]}.json').read_bytes())
        if self.path.startswith('/turn/state/') and HEX64.fullmatch(h := self.path.removeprefix('/turn/state/')) and (STATE / 'blobs' / h).exists():
            return self.reply(200, (STATE / 'blobs' / h).read_bytes(), 'application/octet-stream')
        self.reply(404, canonical({'error': 'not_found'}))

    def do_POST(self):
        if self.path not in POSTS:
            return self.reply(404, canonical({'error': 'not_found'}))
        op, operator = POSTS[self.path]
        if operator and not hmac.compare_digest(self.headers.get('authorization', ''), 'Bearer ' + TOKEN):
            return self.reply(401, canonical({'error': 'operator_token_required'}))
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        try:
            with LOCK:
                out = op(req)
            log({'op': self.path, 'ok': True})
            self.reply(200, canonical(out))
        except Reject as e:
            log({'op': self.path, 'ok': False, 'error': str(e)})
            self.reply(403, canonical({'error': str(e)}))
        except (KeyError, TypeError, ValueError) as e:
            log({'op': self.path, 'ok': False, 'error': repr(e)})
            self.reply(400, canonical({'error': repr(e)}))


ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
