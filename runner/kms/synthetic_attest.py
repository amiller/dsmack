"""Test-only runner App Attest evidence from a synthetic fixture (node/tests/sdk_runner_fixture.json or one written
by node/tests/sdk_runner_fixture.py); never Apple evidence. Each enrollment carries its leaf scalar, so assertions
over any data can be signed the way the runner's /attest does: authenticatorData = assert_prefix ‖ counter ‖
assert_ext, signature = ECDSA-SHA256 over sha256(auth ‖ sha256(client_data)), CBOR {signature, authenticatorData}."""
import base64, hashlib, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def cbor_bytes(d):
    return bytes([0x40 + len(d)]) + d if len(d) < 24 else (bytes([0x58, len(d)]) if len(d) < 256 else bytes([0x59]) + len(d).to_bytes(2, 'big')) + d


class SyntheticRunner:
    def __init__(self, fixture, enrollment):
        self.fx = json.loads(open(fixture).read())
        assert self.fx['synthetic_only'] is True, 'fixture must be synthetic'
        self.e = self.fx['enrollments'][enrollment]
        self.key = ec.derive_private_key(int(self.e['leaf_scalar_synthetic'], 16), ec.SECP256R1())
        self.compose_hash = json.loads(base64.b64decode(self.e['boot_client_data']))['compose_hash']
        self.cdhash = self.fx['cdhash']

    def assertion(self, client, counter=1):
        auth = bytes.fromhex(self.fx['assert_prefix']) + counter.to_bytes(4, 'big') + bytes.fromhex(self.fx['assert_ext'])
        sig = self.key.sign(hashlib.sha256(auth + hashlib.sha256(client).digest()).digest(), ec.ECDSA(hashes.SHA256()))
        return b'\xa2\x69signature' + cbor_bytes(sig) + b'\x71authenticatorData' + cbor_bytes(auth)

    def attest(self, data, domain='mac-compose-assert/1'):
        client = json.dumps({'compose_hash': self.compose_hash, 'data': data, 'domain': domain}, sort_keys=True, separators=(',', ':')).encode()
        return {'type': 'macrunner', 'keyId': self.e['key_id'], 'attestation': self.e['attestation'], 'bootClientData': self.e['boot_client_data'],
                'assertion': base64.b64encode(self.assertion(client)).decode(), 'assertClientData': base64.b64encode(client).decode()}
