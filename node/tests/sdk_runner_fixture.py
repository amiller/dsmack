"""Test-only synthetic runner App Attest enrollments for the dsmack-sdk runner admission, in the schema of
sdk_runner_fixture.json (aa80468's Tests/ops/runner_fixture.py profile: App ID DC9JH5DRMY.dev.dsmack.provider,
production AAGUID, category 3, macOS ACL, CDHash 5a..5a). Nothing here is Apple evidence; a fresh synthetic root is
made per run. The committed fixture pins now=1791762600 for SDKVectors; a live node checks enrollments against its
own clock (12 h), so live tests write a fresh one.
Usage: sdk_runner_fixture.py OUT.json [--now T] [--compose NAME=SHA256HEX ...]"""
import argparse, base64, datetime, hashlib, json, pathlib, sys, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from verifier.core import Policy, verify_attestation  # noqa: E402

APP_ID, CDHASH, OTHER_CDHASH = 'DC9JH5DRMY.dev.dsmack.provider', bytes([0x5a]) * 32, bytes([0x5b]) * 32
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
p.add_argument('--compose', action='append', default=[], help='NAME=SHA256HEX: one more good enrollment for that compose')
a = p.parse_args()
root_key, inter_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
root = cert(name('Synthetic Test App Attest Root'), name('Synthetic Test App Attest Root'), root_key, root_key, True, Y(2020), Y(2045))
inter = cert(name('Synthetic Test App Attest CA'), root.subject, inter_key, root_key, True, Y(2020), Y(2040))
POLICY = Policy(APP_ID, environment='production', categories=(3,), cdhashes=(CDHASH,), require_macos_acl=True)
COMPOSE = hashlib.sha256(b'synthetic coupon runner app-compose.json').hexdigest()


def ext(cdhash):
    return {'apple_cd_hash_type_01': b'\x02', 'apple_cd_hash_hash_01': cdhash, 'apple_validation_category_01': b'\x03\0\0\0'}


def enrollment(cdhash=CDHASH, compose=COMPOSE, enrolled_at=a.now - 600):
    key = ec.generate_private_key(ec.SECP256R1())
    client = json.dumps({'app': 'coupon-runner', 'attested': True, 'compose_hash': compose, 'domain': 'mac-compose-boot/1',
                         'enrolled_at': enrolled_at, 'nonce': '11' * 32, 'receipt_pub': '04' + '22' * 64}, sort_keys=True, separators=(',', ':')).encode()
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    kid = sha(point)
    auth = (sha(APP_ID.encode()) + bytes([0xc0]) + bytes(4) + b'appattest' + bytes(7) + (32).to_bytes(2, 'big') + kid
            + cbor({1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}) + cbor({**ext(cdhash), 'apple_bundle_version_01': '1'}))
    leaf = cert(name('synthetic leaf'), inter.subject, key, inter_key, False, Y(2026), Y(2040),
                [x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.840.113635.100.8.2'), b'\x30\x24\xa1\x22\x04\x20' + sha(auth + sha(client))),
                 x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.840.113635.100.8.6'), ACL)])
    raw = cbor({'fmt': 'apple-appattest', 'attStmt': {'x5c': [der(leaf), der(inter)], 'receipt': b'synthetic-receipt'}, 'authData': auth})
    try:
        verify_attestation(raw, b64(kid), client, POLICY, root.public_bytes(serialization.Encoding.PEM), a.now)
        verdict = 'accept'
    except ValueError as e:
        verdict = str(e)
    return {'key_id': b64(kid), 'attestation': b64(raw), 'boot_client_data': b64(client), 'core_verdict': verdict,
            'leaf_scalar_synthetic': key.private_numbers().private_value.to_bytes(32, 'big').hex()}


enrollments = {'good': enrollment(), 'wrong_cdhash': enrollment(cdhash=OTHER_CDHASH), 'wrong_compose': enrollment(compose='00' * 32),
               'stale': enrollment(enrolled_at=a.now - 13 * 3600)}
for c in a.compose:
    n, h = c.split('=')
    enrollments[n] = enrollment(compose=h)
out = {'synthetic_only': True, 'synthetic_root': b64(der(root)), 'now': a.now, 'cdhash': CDHASH.hex(), 'compose_sha256': COMPOSE,
       'assert_prefix': (sha(APP_ID.encode()) + bytes([0x80])).hex(), 'assert_ext': cbor(ext(CDHASH)).hex(),
       'assert_ext_wrong_cdhash': cbor(ext(OTHER_CDHASH)).hex(), 'enrollments': enrollments}
a.out.write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
print(json.dumps({k: v['core_verdict'] for k, v in enrollments.items()}))
