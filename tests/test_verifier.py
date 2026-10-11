"""Synthetic PKI fixtures are parser/protocol tests, never Apple-device evidence."""
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from verifier.core import Policy, Reject, authenticator, b64, decode, sha, unb64, verify_attestation
from verifier.server import create_app
from verifier.export import export


APP = 'TESTTEAM01.org.example.AppAttestLab'


def cert(name, key, issuer, issuer_key, ca, nonce=None, expired=False):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2))
               .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=10))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                   key_encipherment=False, data_encipherment=False, key_agreement=False,
                   key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
    if nonce is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.2.840.113635.100.8.2'), b'\x30\x24\xa1\x22\x04\x20' + nonce), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class Rig:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = cert('Synthetic test root', self.root_key, None, self.root_key, True)
        self.inter_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = cert('Synthetic intermediate', self.inter_key, self.root.subject, self.root_key, True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.point = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.key_id = b64(sha(self.point))
        self.root_pem = self.root.public_bytes(serialization.Encoding.PEM)

    def attestation(self, challenge, app_id=APP, aaguid=b'appattestdevelop', counter=0, expired=False,
                    extensions=None, wrong_nonce=False, cose_point=None):
        point = cose_point or self.point
        cose = {1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}
        auth = (sha(app_id.encode()) + bytes([0x40 | (0x80 if extensions is not None else 0)])
                + counter.to_bytes(4, 'big') + aaguid + b'\0\x20' + sha(self.point) + cbor2.dumps(cose))
        if extensions is not None:
            auth += cbor2.dumps(extensions)
        leaf = cert('Synthetic leaf', self.key, self.inter.subject, self.inter_key, False,
                    b'x' * 32 if wrong_nonce else sha(auth + sha(challenge)), expired)
        return cbor2.dumps({'fmt': 'apple-appattest', 'authData': auth,
            'attStmt': {'x5c': [leaf.public_bytes(serialization.Encoding.DER),
                                self.inter.public_bytes(serialization.Encoding.DER)], 'receipt': b'synthetic-unverified'}})

    def assertion(self, data, counter=1, app_id=APP, extensions=None):
        auth = sha(app_id.encode()) + bytes([0x80 if extensions is not None else 0]) + counter.to_bytes(4, 'big')
        if extensions is not None:
            auth += cbor2.dumps(extensions)
        signature = self.key.sign(sha(auth + sha(data)), ec.ECDSA(hashes.SHA256()))
        return cbor2.dumps({'authenticatorData': auth, 'signature': signature})


@pytest.fixture
def rig():
    return Rig()


def test_attestation_positive(rig):
    result = verify_attestation(rig.attestation(b'challenge'), rig.key_id, b'challenge', Policy(APP), rig.root_pem)
    assert result['public_key'] == b64(rig.point)
    assert result['receipt_status'] == 'retained_not_validated'


def test_developer_id_requires_explicit_category_policy(rig):
    raw = rig.attestation(b'challenge', extensions={'apple_validation_category_01': (6).to_bytes(4, 'little')})
    result = verify_attestation(raw, rig.key_id, b'challenge', Policy(APP, categories=(6,)), rig.root_pem)
    assert result['signals']['validation_category'] == 6
    with pytest.raises(Reject, match='category_policy_failed'):
        verify_attestation(raw, rig.key_id, b'challenge', Policy(APP, categories=(3,)), rig.root_pem)
    for invalid in (0, 1, 7, 8, 9, 10, True):
        with pytest.raises(Reject, match='invalid_validation_categories'):
            Policy(APP, categories=(invalid,))


@pytest.mark.parametrize('kwargs,reason', [
    ({'app_id': 'OTHERTEAM0.org.example.AppAttestLab'}, 'wrong_app_id'),
    ({'aaguid': b'appattest' + b'\0'*7}, 'wrong_environment_aaguid'),
    ({'counter': 1}, 'nonzero_initial_counter'),
    ({'expired': True}, 'certificate_chain_failed'),
    ({'wrong_nonce': True}, 'attestation_nonce_mismatch'),
    ({'cose_point': b'\x04' + b'\x01'*64}, 'cose_key_mismatch'),
])
def test_attestation_rejections(rig, kwargs, reason):
    with pytest.raises(Reject, match=reason):
        verify_attestation(rig.attestation(b'challenge', **kwargs), rig.key_id, b'challenge', Policy(APP), rig.root_pem)


def test_wrong_challenge_and_root(rig):
    raw = rig.attestation(b'challenge')
    with pytest.raises(Reject, match='nonce'):
        verify_attestation(raw, rig.key_id, b'other', Policy(APP), rig.root_pem)
    with pytest.raises(Reject, match='certificate_chain'):
        verify_attestation(raw, rig.key_id, b'challenge', Policy(APP), Rig().root_pem)


@pytest.mark.parametrize('raw', [b'\xa2\x61x\x01\x61x\x02', b'\xa0\x00', b'\x9f\xff', b'\x81', b'\xc0\xa0'])
def test_strict_cbor(raw):
    with pytest.raises(Reject):
        decode(raw)


def test_extension_policy(rig):
    extensions = {'apple_validation_category_01': (5).to_bytes(4, 'little'), 'apple_bundle_version_01': '1'}
    policy = Policy(APP, categories=(5,), versions=('1',))
    result = verify_attestation(rig.attestation(b'c', extensions=extensions), rig.key_id, b'c', policy, rig.root_pem)
    assert result['signals']['validation_category'] == 5
    with pytest.raises(Reject, match='category_policy_failed'):
        verify_attestation(rig.attestation(b'c'), rig.key_id, b'c', policy, rig.root_pem)


@pytest.fixture
def lab(tmp_path, rig):
    now = [1000.0]
    path = tmp_path / 'test.sqlite'
    app = create_app(Policy(APP), path, rig.root_pem, clock=lambda: now[0])
    app.testing = True
    return app, app.test_client(), now, path


def enroll(client, rig):
    ch = client.post('/challenge', json={'purpose': 'attestation', 'key_id': rig.key_id}).get_json()
    body = {'challenge_id': ch['challenge_id'], 'key_id': rig.key_id,
            'attestation': b64(rig.attestation(unb64(ch['challenge'])))}
    result = client.post('/attest', json=body)
    assert result.status_code == 200, result.get_json()
    return body


def assertion_body(client, rig, output=4, counter=1):
    ch = client.post('/challenge', json={'purpose': 'assertion', 'key_id': rig.key_id}).get_json()
    obj = {'protocol': 'ios-app-attest-sok/v1', 'challenge_id': ch['challenge_id'],
           'challenge': ch['challenge'], 'key_id': rig.key_id, 'operation': 'double', 'input': 2, 'output': output}
    data = json.dumps(obj).encode()
    return {'challenge_id': ch['challenge_id'], 'key_id': rig.key_id,
            'assertion': b64(rig.assertion(data, counter)), 'client_data': b64(data)}


@pytest.mark.parametrize('output,matches', [(4, True), (5, False)])
def test_identity_is_not_computation(lab, rig, output, matches):
    _, client, _, _ = lab
    enroll(client, rig)
    response = client.post('/assert', json=assertion_body(client, rig, output)).get_json()
    assert response['accepted'] is True
    assert response['computation_matches'] is matches
    assert response['fixed_code_verified'] is False
    assert response['evidence_origin'] == 'synthetic_test_root'


def test_challenge_and_counter_replay(lab, rig):
    _, client, _, _ = lab
    enrollment = enroll(client, rig)
    assert client.post('/attest', json=enrollment).get_json()['reason'] == 'challenge_replay'
    body = assertion_body(client, rig)
    assert client.post('/assert', json=body).status_code == 200
    assert client.post('/assert', json=body).get_json()['reason'] == 'challenge_replay'
    fresh = assertion_body(client, rig, counter=1)
    assert client.post('/assert', json=fresh).get_json()['reason'] == 'counter_replay'


def test_expired_challenge(lab, rig):
    _, client, now, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    now[0] += 121
    assert client.post('/assert', json=body).get_json()['reason'] == 'expired_challenge'


def test_payload_substitution(lab, rig):
    _, client, _, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    data = json.loads(unb64(body['client_data']))
    data['output'] = 5
    body['client_data'] = b64(json.dumps(data).encode())
    assert client.post('/assert', json=body).get_json()['reason'] == 'invalid_assertion_signature'
    assert client.post('/assert', json=body).get_json()['reason'] == 'challenge_replay'


def test_atomic_concurrent_replay(lab, rig):
    app, client, _, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(lambda _: app.test_client().post('/assert', json=body).status_code, range(2)))
    assert sorted(responses) == [200, 400]


def test_policy_pinned_across_restart(lab, rig):
    _, client, now, path = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    assert client.post('/assert', json=body).status_code == 200
    restarted = create_app(Policy(APP), path, rig.root_pem, clock=lambda: now[0]).test_client()
    assert restarted.post('/assert', json=body).get_json()['reason'] == 'challenge_replay'
    with pytest.raises(Reject, match='database_policy_mismatch'):
        create_app(Policy(APP, environment='production'), path, rig.root_pem)


@pytest.mark.parametrize('body', [b'{}', b'{"purpose":"attestation","purpose":"assertion"}',
                                b'{"purpose":"attestation","key_id":[]}', b'[]', b'not json'])
def test_bad_http_input(lab, body):
    assert lab[1].post('/challenge', data=body, content_type='application/json').status_code == 400


def test_challenge_bound_to_key(lab, rig):
    _, client, _, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    body['key_id'] = Rig().key_id
    assert client.post('/assert', json=body).get_json()['reason'] == 'challenge_binding_mismatch'


def test_signed_wrong_challenge_rejected(lab, rig):
    _, client, _, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    data = json.loads(unb64(body['client_data']))
    data['challenge'] = b64(b'x' * 32)
    raw = json.dumps(data).encode()
    body['client_data'], body['assertion'] = b64(raw), b64(rig.assertion(raw))
    assert client.post('/assert', json=body).get_json()['reason'] == 'client_challenge_mismatch'


def test_signature_from_another_key_rejected(lab, rig):
    _, client, _, _ = lab
    enroll(client, rig)
    body = assertion_body(client, rig)
    body['assertion'] = b64(Rig().assertion(unb64(body['client_data'])))
    assert client.post('/assert', json=body).get_json()['reason'] == 'invalid_assertion_signature'


def test_export_contains_raw_proofs_and_rejections(lab, rig):
    _, client, _, path = lab
    enroll(client, rig)
    body = assertion_body(client, rig, output=5)
    client.post('/assert', json=body)
    client.post('/assert', json=body)
    capture = export(path)
    assert capture['policy']['app_id'] == APP
    assert len(capture['entries']) == 3
    assert capture['entries'][1]['request'] == body
    assert capture['entries'][1]['challenge']['nonce'] == json.loads(unb64(body['client_data']))['challenge']
    assert capture['entries'][1]['response']['computation_matches'] is False
    assert capture['entries'][2]['response']['reason'] == 'challenge_replay'


def test_same_identity_new_key_synthetic_control(lab, rig):
    # Demonstrates the harness's intended scope, NOT an Apple second-certificate experiment.
    _, client, _, _ = lab
    enroll(client, rig)
    other = Rig()
    other.root_pem, other.inter, other.inter_key = rig.root_pem, rig.inter, rig.inter_key
    enroll(client, other)
    result = client.post('/assert', json=assertion_body(client, other, output=5)).get_json()
    assert result['accepted'] and not result['computation_matches']
    assert result['evidence_origin'] == 'synthetic_test_root'
