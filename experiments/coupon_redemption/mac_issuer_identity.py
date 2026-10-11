"""Mac runner issuer collection; only a remote verifier authenticates evidence.

The Ed25519 signer is derived inside the admitted ARM workload through the
runner key endpoint. These are operator/KMS-readable keys, not Secure Enclave
keys. A host using the assertion endpoint is not by itself an admitted issuer.
"""
import base64
import hashlib
import http.client
import json
import re
import socket
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .spike import RedemptionError
from .staging_approval import canonical
from .transport import _unique_object, _reject_constant

POLICY = 'mac-appattest-coupon-v1'
DOMAIN = 'dsmack-coupon-mac-issuer-identity-v1'
POLICY_DOMAIN = 'dsmack-coupon-mac-issuer-policy-v1'
POSSESSION_DOMAIN = b'dsmack-coupon-mac-issuer-possession-v1\0'
KEY_PATH = 'dsmack/coupon-issuer/mac/v1/ed25519'
MAX_FRAME = 2 * 1024 * 1024


def assertion_data(binding):
    fields = {'version', 'peer_id', 'recipient_peer_id', 'public_key_hex',
              'challenge_hex', 'identity_policy_sha256', 'issuance_policy_sha256'}
    if (type(binding) is not dict or set(binding) != fields
            or type(binding['version']) is not int or binding['version'] != 1
            or any(type(binding[k]) is not str or not re.fullmatch(r'[A-Za-z0-9]{16,128}', binding[k])
                   for k in ('peer_id', 'recipient_peer_id'))
            or any(type(binding[k]) is not str or not re.fullmatch(r'[0-9a-f]{64}', binding[k])
                   for k in fields - {'version', 'peer_id', 'recipient_peer_id'})):
        raise ValueError('invalid Mac issuer binding')
    return DOMAIN + '|' + hashlib.sha256(canonical(binding)).hexdigest()


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=15):
        super().__init__('runner.local', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class RunnerClient:
    def __init__(self, path='/run/egress.sock'):
        p = Path(path)
        if not p.is_absolute() or not stat.S_ISSOCK(p.stat().st_mode):
            raise RedemptionError('Mac runner socket unavailable')
        self.path = str(p)

    def request(self, endpoint, body):
        if endpoint not in ('/key', '/attest'):
            raise ValueError('invalid runner operation')
        connection = UnixHTTP(self.path)
        try:
            connection.request('POST', endpoint, body=canonical(body),
                               headers={'Content-Type': 'application/json', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
                raise ValueError()
            raw = response.read(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME:
                raise ValueError()
            value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            if type(value) is not dict:
                raise ValueError()
            return value
        except Exception:
            raise RedemptionError('Mac runner operation unavailable') from None
        finally:
            connection.close()

    def key(self, path):
        if path not in (KEY_PATH, 'dsmack/coupon-noise/mac/v1/ed25519', 'dsmack/coupon-guard/mac/v1/secp256k1'):
            raise ValueError('invalid issuer key domain')
        value = self.request('/key', {'path': path})
        if set(value) != {'key'} or type(value['key']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['key']):
            raise RedemptionError('Mac runner key unavailable')
        return bytes.fromhex(value['key'])


class MacIssuerIdentity:
    def __init__(self, client):
        self._client = client
        self._signer = Ed25519PrivateKey.from_private_bytes(client.key(KEY_PATH))

    def public_key_hex(self):
        return self._signer.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw).hex()

    def collect(self, binding, app_compose):
        try:
            data = assertion_data(binding)
            if binding['public_key_hex'] != self.public_key_hex():
                raise ValueError()
            if type(app_compose) is not str or not 0 < len(app_compose.encode()) <= 131072:
                raise ValueError()
            evidence = self._client.request('/attest', {'data': data})
            enrollment = json.loads(base64.b64decode(evidence['bootClientData'], validate=True))
            if (evidence.get('type') != 'macrunner'
                    or enrollment.get('attested') is not True
                    or enrollment.get('compose_hash') != hashlib.sha256(app_compose.encode()).hexdigest()):
                raise ValueError()
            return {'domain': DOMAIN, 'binding': dict(binding), 'runner_evidence': evidence,
                    'app_compose': app_compose,
                    'possession_signature_hex': self._signer.sign(POSSESSION_DOMAIN + data.encode('ascii')).hex()}
        except Exception:
            raise RedemptionError('Mac issuer evidence unavailable') from None


class MacIssuerEvidenceService:
    def __init__(self, *, issuer_peer, signing_key, identity_policy_sha256,
                 issuance_policy_sha256, collector, app_compose):
        self.peer = self.issuer_peer = issuer_peer
        self.collector = collector
        self.identity = identity_policy_sha256
        self.issuance = issuance_policy_sha256
        self.compose = app_compose
        public = signing_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw).hex()
        if public != collector.public_key_hex():
            raise ValueError('collector differs from actual signer')
        self.public = public
        if any(type(v) is not str or not re.fullmatch(r'[0-9a-f]{64}', v) for v in (self.identity, self.issuance)):
            raise ValueError('invalid issuer policy pin')

    def dispatch(self, frame, *, local_peer, remote_peer):
        request_id = None
        try:
            if local_peer != self.peer or type(frame) is not bytes or len(frame) > MAX_FRAME:
                raise ValueError()
            request = json.loads(frame, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            if type(request) is not dict or type(request.get('id')) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request['id']):
                raise ValueError()
            request_id = request['id']
            if request.get('op') == 'info' and set(request) == {'id', 'op'}:
                result = {'version': 2, 'issuer_public_key_hex': self.public,
                          'identity_policy_sha256': self.identity, 'issuance_policy_sha256': self.issuance}
            elif request.get('op') == 'evidence' and set(request) == {'id', 'op', 'binding'}:
                binding = request['binding']
                assertion_data(binding)
                if (binding['peer_id'] != local_peer or binding['recipient_peer_id'] != remote_peer
                        or binding['public_key_hex'] != self.public or binding['identity_policy_sha256'] != self.identity
                        or binding['issuance_policy_sha256'] != self.issuance):
                    raise ValueError()
                result = self.collector.collect(binding, self.compose)
                if result['binding'] != binding:
                    raise ValueError()
            else:
                raise ValueError()
            encoded = json.dumps({'id': request_id, 'ok': True, 'result': result}, separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > MAX_FRAME:
                raise ValueError()
            return encoded
        except Exception:
            return json.dumps({'id': request_id, 'ok': False, 'error': 'request_failed'}, separators=(',', ':')).encode()
