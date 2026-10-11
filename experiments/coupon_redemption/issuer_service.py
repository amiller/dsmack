"""Public, pre-bearer discovery and bounded evidence collection on Noise peers."""
import json
import re

from cryptography.hazmat.primitives import serialization

from .dstack_issuer_identity import report_data
from .spike import RedemptionError
from .transport import _unique_object, _reject_constant, _finite_float

MAX_ISSUER_FRAME = 2 * 1024 * 1024


class IssuerEvidenceService:
    def __init__(self, *, issuer_peer, signing_key, identity_policy_sha256,
                 issuance_policy_sha256, collector, app_compose):
        self.issuer_peer = issuer_peer
        self.public_key_hex = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        for value in (identity_policy_sha256, issuance_policy_sha256):
            if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
                raise RedemptionError('invalid protected policy pin')
        if collector.public_key_hex() != self.public_key_hex:
            raise RedemptionError('collector differs from actual service signer')
        self.identity_policy = identity_policy_sha256
        self.issuance_policy = issuance_policy_sha256
        self.collector = collector
        self.app_compose = app_compose

    def dispatch(self, frame, *, local_peer, remote_peer):
        request_id = None
        try:
            if (local_peer != self.issuer_peer or type(remote_peer) is not str
                    or not re.fullmatch(r'[A-Za-z0-9]{1,200}', remote_peer)
                    or type(frame) is not bytes or len(frame) > MAX_ISSUER_FRAME):
                raise RedemptionError('invalid trusted peer context')
            request = json.loads(frame.decode(), object_pairs_hook=_unique_object,
                parse_constant=_reject_constant, parse_float=_finite_float)
            if type(request) is not dict or type(request.get('id')) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request['id']):
                raise RedemptionError('invalid issuer request')
            request_id = request['id']
            op = request.get('op')
            if op == 'info' and set(request) == {'id', 'op'}:
                result = {'version': 2, 'issuer_public_key_hex': self.public_key_hex,
                    'identity_policy_sha256': self.identity_policy,
                    'issuance_policy_sha256': self.issuance_policy}
            elif op == 'evidence' and set(request) == {'id', 'op', 'binding'}:
                binding = request['binding']
                report_data(binding)
                if (binding['peer_id'] != local_peer or binding['public_key_hex'] != self.public_key_hex
                        or binding['policy_sha256'] != self.identity_policy):
                    raise RedemptionError('evidence binding differs from actual issuer')
                result = self.collector.collect(binding, self.app_compose)
                # A collector is trusted local code, never caller-controlled.
                # Nevertheless reject a collector accidentally replacing the binding.
                if result.get('binding') != binding:
                    raise RedemptionError('collector changed binding')
            else:
                raise RedemptionError('invalid issuer operation fields')
            encoded = json.dumps({'id': request_id, 'ok': True, 'result': result}, separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > MAX_ISSUER_FRAME:
                raise RedemptionError('issuer evidence frame too large')
            return encoded
        except Exception:
            return json.dumps({'id': request_id, 'ok': False, 'error': 'request_failed'}, separators=(',', ':')).encode()
