"""Stand-in KMS for the Mac compose runner. Holds one API key (env KMS_API_KEY, or --keys-file) in memory and
releases it on 127.0.0.1 to a runner presenting a fresh App Attest attestation whose clientData
binds a KMS nonce, the app, the compose_hash and the receipt public key, with (app, CDHash, compose_hash)
on the --allow list. The key never crosses the socket in plaintext: /release returns
{epk, sealed}, the key sealed to the eph_pub in clientData (ECDH P-256 with a one-time KMS key epk,
HKDF-SHA256 info "mac-compose-key-release/1", AES-256-GCM, nonce ‖ ciphertext ‖ tag, AAD sha256(clientData)). Attestation checks are verifier/core.py with the app/macos policy
(pinned Apple root, production AAGUID, category 3, Mac ACL).

--allow APP:CDHASH:COMPOSE_HASH admits one build (cdhash, compose_hash) to app APP; it is repeatable and a build belongs
to exactly one app. --allow CDHASH:COMPOSE_HASH is shorthand for the genesis app APP = "<cdhash>|<compose_hash>".

--dev-unattested is DEV-ONLY: it releases the key with NO attestation, for ad-hoc runner builds
(`runner run --no-attest`), to builds whose cdhash is "dev": --allow APP:dev:COMPOSE_HASH, or --allow-compose COMPOSE_HASH
as shorthand for APP = "dev|<compose_hash>". Never run it with a real key.

The API key comes from env KMS_API_KEY or from --keys-file PATH --provider ID [--label L], abalone's node key store
(lib/nodekeys.mjs: {"active": {provider: label}, "keys": [{kind, provider, label, key, added}]}); without --label
the label is active[provider]. Exactly one entry must match. The key is never printed or logged.

--state DIR holds master.key (32 random bytes, created mode 0600 on first run, never logged). Each release also carries
app_key = HKDF-SHA256(master, salt none, info "mac-compose-app-key/1|<APP>", 32 bytes), APP the app the --allow list
gives the build (cdhash from the verified attestation, or "dev" in --dev-unattested mode), which must equal clientData.app.
For a genesis app, APP = "<cdhash>|<compose_hash>" gives the same app_key the pre-app KMS derived from the build.
The sealed plaintext is the JSON {"api_key": <str>, "app": <APP>, "app_key": <64 hex>} (sorted keys, no spaces).

--record DIR writes every /release response body, byte for byte, to DIR/<sha256(clientData)[:16]>-<status>.json.

usage: KMS_API_KEY=... python3 kms.py --state DIR --allow [APP:]CDHASH:COMPOSE_HASH [--allow ...] [--port 8790] [--record DIR]
       KMS_API_KEY=... python3 kms.py --state DIR --dev-unattested (--allow APP:dev:COMPOSE_HASH | --allow-compose COMPOSE_HASH) ... [--port 8790] [--record DIR]
       (or --keys-file PATH --provider ID [--label L] in place of KMS_API_KEY)
"""
import argparse, base64, hashlib, json, os, secrets, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / 'app/macos')]
from verifier.core import Policy, Reject, require, unb64, unique_json, verify_attestation
from runner.kms.app_binding import app_binding_allowed, key_parcel
from check_evidence import APP_ID, MACOS_VALIDATION_CATEGORY, root
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p = argparse.ArgumentParser()
p.add_argument('--port', type=int, default=8790)
p.add_argument('--allow', action='append', default=[], help='[APP:]CDHASH:COMPOSE_HASH')
p.add_argument('--legacy-genesis', action='store_true', help='signed app-less Runner only; exact CDHash|compose key namespace, no attested app metadata')
p.add_argument('--dev-unattested', action='store_true', help='DEV-ONLY: release without attestation')
p.add_argument('--allow-compose', action='append', default=[], help='COMPOSE_HASH (dev mode, app "dev|COMPOSE_HASH")')
p.add_argument('--record', type=Path, help='write each /release response body to this directory')
p.add_argument('--state', type=Path, required=True, help='KMS state dir (master.key)')
p.add_argument('--keys-file', type=Path)
p.add_argument('--provider')
p.add_argument('--label')
p.add_argument('--dev-omit-app-key', action='store_true', help='DEV-ONLY test: seal a parcel without app_key')
args = p.parse_args()


def build(x):
    *app, cdhash, compose = x.rsplit(':', 2)
    cdhash, compose = cdhash.lower(), compose.lower()
    return (app[0] if app else f'{cdhash}|{compose}', cdhash, compose)
ALLOW = {}
for app, cdhash, compose in [build(x) for x in args.allow] + [build(f'dev:{h}') for h in args.allow_compose]:
    assert ALLOW.setdefault((cdhash, compose), app) == app, f'build {cdhash}:{compose} is in two apps: {ALLOW[cdhash, compose]!r}, {app!r}'
assert not args.legacy_genesis or not args.dev_unattested, 'legacy genesis requires genuine attestation'
assert not args.legacy_genesis or all(app == cdhash + '|' + compose for (cdhash, compose), app in ALLOW.items()), 'legacy genesis requires exact measured-build namespace'
assert ALLOW and all((c == 'dev') == args.dev_unattested for c, _ in ALLOW), \
    'configure exactly one mode: --allow [APP:]CDHASH:COMPOSE, or --dev-unattested with dev builds (--allow APP:dev:COMPOSE, --allow-compose COMPOSE)'
assert bool(args.keys_file) == bool(args.provider) and bool(args.keys_file) != ('KMS_API_KEY' in os.environ), \
    'give the API key by exactly one of: env KMS_API_KEY, or --keys-file PATH --provider ID'
assert not args.dev_omit_app_key or args.dev_unattested, '--dev-omit-app-key is DEV-ONLY (needs --dev-unattested)'
if args.keys_file:
    store = json.loads(args.keys_file.read_text())
    label = args.label or store['active'][args.provider]
    match = [k for k in store['keys'] if k['provider'] == args.provider and k['label'] == label]
    assert len(match) == 1, f'{args.keys_file}: {len(match)} keys for provider {args.provider} label {label}; need exactly 1'
    API_KEY = match[0]['key'].encode()
    print(f'kms: API key from {args.keys_file} provider {args.provider} label {label} ({len(API_KEY)} bytes)', file=sys.stderr)
else:
    API_KEY = os.environ['KMS_API_KEY'].encode()
args.state.mkdir(parents=True, exist_ok=True)
MASTER_PATH = args.state / 'master.key'
if not MASTER_PATH.exists():
    fd = os.open(MASTER_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, os.urandom(32))
    os.close(fd)
MASTER = MASTER_PATH.read_bytes()
assert len(MASTER) == 32, f'{MASTER_PATH} is {len(MASTER)} bytes, expected 32'


def app_key(app):
    return HKDF(hashes.SHA256(), 32, None, f'mac-compose-app-key/1|{app}'.encode()).derive(MASTER)
if args.record:
    args.record.mkdir(parents=True)
NONCES = {}


def release(req):
    client_data = unb64(req['client_data'])
    client = unique_json(client_data)
    if args.dev_unattested:
        require(req['mode'] == 'dev-unattested' and client['attested'] is False, 'dev_kms_accepts_only_dev_unattested')
        cdhash = 'dev'
        require((cdhash, client['compose_hash']) in ALLOW, 'compose_hash_not_allowed')
    else:
        require(req['mode'] == 'attested' and client['attested'] is True, 'attested_request_required')
        policy = Policy(APP_ID, environment='production', categories=(MACOS_VALIDATION_CATEGORY,),
                        cdhashes=tuple(bytes.fromhex(c) for c, _ in ALLOW), require_macos_acl=True)
        info = verify_attestation(unb64(req['attestation']), req['key_id'], client_data, policy, root())
        cdhash = info['signals']['cdhash']
        require((cdhash, client['compose_hash']) in ALLOW, 'cdhash_compose_pair_not_allowed')
    app = ALLOW[cdhash, client['compose_hash']]
    require(app_binding_allowed(client, app, cdhash, legacy_genesis=args.legacy_genesis), 'build_not_in_requested_app')
    require(client['domain'] == 'mac-compose-boot/1', 'wrong_client_data_domain')
    issued = NONCES.pop(client['nonce'], None)
    require(issued is not None and time.time() - issued < 60, 'unknown_or_stale_nonce')
    print(f"kms: released key to app {app!r} compose {client['compose_hash']} receipt_pub {client['receipt_pub'][:16]}... "
          f"{'DEV-UNATTESTED' if args.dev_unattested else 'attested'}", file=sys.stderr)
    kms_key = ec.generate_private_key(ec.SECP256R1())
    shared = kms_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client['eph_pub'])))
    aead = HKDF(hashes.SHA256(), 32, None, b'mac-compose-key-release/1').derive(shared)
    nonce = os.urandom(12)
    b64 = lambda b: base64.b64encode(b).decode()
    parcel = {'api_key': API_KEY.decode()} if args.dev_omit_app_key else \
        key_parcel(API_KEY.decode(), app, app_key(app).hex(), legacy_genesis=args.legacy_genesis)
    return {'epk': b64(kms_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)),
            'sealed': b64(nonce + AESGCM(aead).encrypt(nonce, json.dumps(parcel, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256(client_data).digest()))}


class H(BaseHTTPRequestHandler):
    def reply(self, code, obj, client_data=None):
        body = json.dumps(obj).encode()
        if args.record and client_data is not None:
            (args.record / f'{hashlib.sha256(client_data).hexdigest()[:16]}-{code}.json').write_bytes(body)
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        require(self.path == '/nonce', 'not_found')
        nonce = secrets.token_hex(32)
        NONCES[nonce] = time.time()
        self.reply(200, {'nonce': nonce})

    def do_POST(self):
        require(self.path == '/release', 'not_found')
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        client_data = unb64(req['client_data'])
        try:
            self.reply(200, release(req), client_data)
        except Reject as e:
            print(f'kms: refused: {e}', file=sys.stderr)
            self.reply(403, {'error': str(e)}, client_data)


if args.dev_unattested:
    print('kms: DEV-ONLY --dev-unattested mode: releasing without attestation', file=sys.stderr)
ThreadingHTTPServer(('127.0.0.1', args.port), H).serve_forever()
