"""Runner side of the node channel (needs `cryptography`): JSON lines on the node's loopback sdkPort.

Runner admission (node/shared/SDK.swift SDKService): the first key op on a connection carries runner_evidence,
the runner's App Attest object over {"compose_hash", "data": runner_data(challenge, request), "domain":
"mac-compose-assert/1"}, for a challenge this connection asked for at most 60 s before. `attest(data)` returns
that object ({type: "macrunner", keyId, attestation, bootClientData, assertion, assertClientData}); the real
runner gets it from App Attest, tests from runner/kms/synthetic_attest.py. Every op names app_id, compose_hash and
the sponsor's allow record {scope, until, signature}. get_key returns the app root sealed to a one-time eph_pub
(ECDH P-256, HKDF-SHA256 empty salt info "dsmack-sdk/v1/release", AES-256-GCM nonce‖ct‖tag, AAD sha256(statement)).
"""
import hashlib, json, socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from . import DsmackError, app_signer, app_statement, b, runner_data
from .verify import p256_verify, require

pub = lambda k: k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()


class NodeSession:
    def __init__(self, address, app_id, compose_hash, allow, attest=None):
        host, port = address.rsplit(':', 1)
        self.sock = socket.create_connection((host, int(port)), timeout=30)
        self.lines = self.sock.makefile('rb')
        self.app_id, self.compose_hash, self.allow, self.attest = app_id, compose_hash, allow, attest
        self.admitted = False

    def call(self, q):
        self.sock.sendall(json.dumps(q).encode() + b'\n')
        reply = json.loads(self.lines.readline())
        if 'error' in reply:
            raise DsmackError(reply['error'])
        return reply

    def request(self, op, **fields):
        q = {'v': 1, 'op': op, 'app_id': self.app_id, 'compose_hash': self.compose_hash, 'allow': self.allow, **fields}
        if not self.admitted and self.attest:
            challenge = self.call({'v': 1, 'op': 'challenge'})['challenge']
            q['runner_evidence'] = self.attest(runner_data(challenge, q))
        reply = self.call(q)
        self.admitted = True
        return reply

    def release(self, epoch=None):
        """get_key: the app root for the current (or held previous) epoch and its G-signed statement, checked."""
        eph = ec.generate_private_key(ec.SECP256R1())
        r = self.request('get_key', eph_pub=pub(eph), **({} if epoch is None else {'epoch': epoch}))
        statement = b(r['statement'])
        shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(r['epk'])))
        sealed = b(r['sealed'])
        root = AESGCM(HKDF(SHA256(), 32, None, b'dsmack-sdk/v1/release').derive(shared)).decrypt(
            sealed[:12], sealed[12:], hashlib.sha256(statement).digest())
        app_pub = pub(ec.derive_private_key(app_signer(root), ec.SECP256R1()))
        require(r['app_pub'].removeprefix('0x') == app_pub, 'app_pub is not the released root\'s')
        require(statement == app_statement(r['chain_id'], r['registry'], r['scope'], r['key_epoch'], self.app_id, self.compose_hash,
                                           r['block'], r['M'], app_pub), 'statement does not name this app and compose')
        p256_verify(r['group_public'], statement, r['group_signature'])
        return root, r
