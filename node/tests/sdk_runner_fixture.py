"""Test-only synthetic runner App Attest enrollments for the dsmack-sdk runner admission, in the schema of
sdk_runner_fixture.json (aa80468's Tests/ops/runner_fixture.py profile: production AAGUID, macOS ACL) with App Attest category 6, a Developer ID
runner; dev_signed is category 3, an Apple Development runner, which only test builds admit.
Runners are admitted by measurement M_runner, so each enrollment attests a real CodeDirectory from
contracts/fixtures/resign (`code`, the evidence's {cd, page0, ent, L, S}): honest (node-honest, team DC9JH5DRMY),
other_team (node-synthetic-team: TESTTEAM01's App ID and CDHash, same M), modified (node-modified, another M), and
resigned (node-resigned: same M, another CDHash, for a CodeDirectory that is not the attested one). The rpId is the App
ID each one's entitlements name. Nothing here is Apple evidence; a fresh synthetic root is made per run. The committed fixture pins now=1791762600 for SDKVectors; a live node checks enrollments against its
own clock (12 h), so live tests write a fresh one.
Usage: sdk_runner_fixture.py OUT.json [--now T] [--compose NAME=SHA256HEX ...]"""
import argparse, base64, datetime, hashlib, json, pathlib, sys, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts/release')]
from verifier.core import Policy, verify_attestation  # noqa: E402
from measure import app_identifier, measure  # noqa: E402

CODE = {}
for n, f in (('honest', 'node-honest'), ('other_team', 'node-synthetic-team'), ('modified', 'node-modified'), ('resigned', 'node-resigned')):
    d = json.loads((ROOT / f'contracts/fixtures/resign/{f}.json').read_text())
    x = {k: bytes.fromhex(d[k].removeprefix('0x')) for k in ('cd', 'page0', 'ent')}
    CODE[n] = {**x, 'L': d['linkeditCmd'], 'S': d['codeSigCmd']}
ACL = b'\x30\x46\xa3\x44\x04\x42' + base64.b64decode('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB')
sha = lambda d: hashlib.sha256(d).digest()
b64 = lambda d: base64.b64encode(d).decode()
Y = lambda y: datetime.datetime(y, 1, 1, tzinfo=datetime.timezone.utc)
name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
der = lambda c: c.public_bytes(serialization.Encoding.DER)


def cbor(v):
    head = lambda major, n: bytes([major << 5 | n]) if n < 24 else bytes([major << 5 | 24]) + bytes([n]) if n < 256 else bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(map(cbor, v))
    return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())


def cert(subject, issuer, key, signer, ca, start, end, extensions=()):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signer, hashes.SHA384() if isinstance(signer.curve, ec.SECP384R1) else hashes.SHA256())


p = argparse.ArgumentParser()
p.add_argument('out', type=pathlib.Path)
p.add_argument('--now', type=int, default=int(time.time()))
p.add_argument('--compose', action='append', default=[], help='NAME=SHA256HEX: enrollments NAME (honest), NAME@other_team, NAME@modified')
a = p.parse_args()
root_key, inter_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
root = cert(name('Synthetic Test App Attest Root'), name('Synthetic Test App Attest Root'), root_key, root_key, True, Y(2020), Y(2045))
inter = cert(name('Synthetic Test App Attest CA'), root.subject, inter_key, root_key, True, Y(2020), Y(2040))
COMPOSE = hashlib.sha256(b'synthetic coupon runner app-compose.json').hexdigest()


def ext(cdhash, category):
    return {'apple_cd_hash_type_01': b'\x02', 'apple_cd_hash_hash_01': cdhash, 'apple_validation_category_01': bytes([category, 0, 0, 0])}


def enrollment(code='honest', compose=COMPOSE, enrolled_at=a.now - 600, category=6):
    cdhash, app_id = sha(CODE[code]['cd']), app_identifier(CODE[code]['ent'])
    key = ec.generate_private_key(ec.SECP256R1())
    client = json.dumps({'app': 'coupon-runner', 'attested': True, 'compose_hash': compose, 'domain': 'mac-compose-boot/1',
                         'enrolled_at': enrolled_at, 'nonce': '11' * 32, 'receipt_pub': '04' + '22' * 64}, sort_keys=True, separators=(',', ':')).encode()
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    kid = sha(point)
    auth = (sha(app_id.encode()) + bytes([0xc0]) + bytes(4) + b'appattest' + bytes(7) + (32).to_bytes(2, 'big') + kid
            + cbor({1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}) + cbor({**ext(cdhash, category), 'apple_bundle_version_01': '1'}))
    leaf = cert(name('synthetic leaf'), inter.subject, key, inter_key, False, Y(2026), Y(2040),
                [x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.840.113635.100.8.2'), b'\x30\x24\xa1\x22\x04\x20' + sha(auth + sha(client))),
                 x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.840.113635.100.8.6'), ACL)])
    raw = cbor({'fmt': 'apple-appattest', 'attStmt': {'x5c': [der(leaf), der(inter)], 'receipt': b'synthetic-receipt'}, 'authData': auth})
    try:
        policy = Policy(app_id, environment='production', categories=(6,), cdhashes=(cdhash,), require_macos_acl=True)
        verify_attestation(raw, b64(kid), client, policy, root.public_bytes(serialization.Encoding.PEM), a.now)
        verdict = 'accept'
    except ValueError as e:
        verdict = str(e)
    return {'key_id': b64(kid), 'attestation': b64(raw), 'boot_client_data': b64(client), 'core_verdict': verdict,
            'leaf_scalar_synthetic': key.private_numbers().private_value.to_bytes(32, 'big').hex(), 'code': code, 'cdhash': cdhash.hex(),
            'assert_prefix': (sha(app_id.encode()) + bytes([0x80])).hex(), 'assert_ext': cbor(ext(cdhash, category)).hex()}


enrollments = {'good': enrollment(), 'other_team': enrollment('other_team'), 'modified': enrollment('modified'), 'wrong_compose': enrollment(compose='00' * 32),
               'stale': enrollment(enrolled_at=a.now - 13 * 3600), 'dev_signed': enrollment(category=3)}
for c in a.compose:
    n, h = c.split('=')
    enrollments[n] = enrollment(compose=h)
    enrollments[n + '@other_team'], enrollments[n + '@modified'] = enrollment('other_team', h), enrollment('modified', h)
code = {n: {'cd': b64(c['cd']), 'page0': b64(c['page0']), 'ent': b64(c['ent']), 'L': c['L'], 'S': c['S']} for n, c in CODE.items()}
out = {'synthetic_only': True, 'synthetic_root': b64(der(root)), 'now': a.now, 'compose_sha256': COMPOSE,
       'runner_m': measure(**CODE['honest']).hex(), 'modified_m': measure(**CODE['modified']).hex(), 'code': code, 'enrollments': enrollments}
a.out.write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
print(json.dumps({k: v['core_verdict'] for k, v in enrollments.items()}))
