"""Transport-neutral experimental dsmack service; no listener or registry.

Principal is trusted adapter context, NEVER decoded from the request frame.
The hosting peer must authenticate and authorize it before calling dispatch.
"""
import base64
import json
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .evidence import observe_and_sign
from .spike import Store, RedemptionError, IssuedKey
from .transport import _unique_object, _reject_constant, _finite_float

# Proposed experimental ID only; not registered in any live peer or registry.
EXPERIMENTAL_PROTOCOL = '/dsmack/coupon/1'
MAX_FRAME = 65536


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset


def _subject(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9:_./-]{1,200}', value):
        raise RedemptionError('invalid subject')
    return value


def _require(principal, role, subject):
    if (not isinstance(principal, Principal) or not isinstance(principal.roles, frozenset)
            or role not in principal.roles or principal.subject != subject):
        raise RedemptionError('access denied')


def _window(start, end):
    if not isinstance(start, str) or not isinstance(end, str) or len(start) > 40 or len(end) > 40:
        raise RedemptionError('invalid window')
    a, b = [datetime.fromisoformat(x.replace('Z', '+00:00')) for x in (start, end)]
    if a.tzinfo is None or b.tzinfo is None or b < a or (b - a).days > 365:
        raise RedemptionError('invalid window')


class DsmackCouponService:
    def __init__(self, store, provider, signing_key, *, sponsor_subject, observer_subject):
        self.store, self.provider, self.signing_key = store, provider, signing_key
        self.sponsor = _subject(sponsor_subject)
        self.observer = _subject(observer_subject)
        store.db.execute('''CREATE TABLE IF NOT EXISTS service_grants (
            digest TEXT PRIMARY KEY, sponsor TEXT NOT NULL,
            recipient TEXT NOT NULL, observer TEXT NOT NULL)''')
        if 'protocol_version' not in {row[1] for row in store.db.execute('PRAGMA table_info(service_grants)')}:
            store.db.execute('ALTER TABLE service_grants ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1')

    def provision(self, principal, budget_nano_usd, recipient_subject):
        """Protected sponsor control plane; provider credentials never on wire.

        This instance is already bound to one trusted provider/account adapter.
        Caller must arrange secure coupon delivery to the named recipient.
        """
        _require(principal, 'sponsor', self.sponsor)
        recipient = _subject(recipient_subject)
        self.store.db.execute('BEGIN IMMEDIATE')
        try:
            coupon = self.store.issue_coupon(budget_nano_usd)
            self.store.db.execute('INSERT INTO service_grants (digest,sponsor,recipient,observer) VALUES (?,?,?,?)',
                                  (self.store.digest(coupon), self.sponsor, recipient, self.observer))
            self.store.db.execute('COMMIT')
            return coupon
        except BaseException:
            self.store.db.execute('ROLLBACK')
            raise

    def dispatch(self, frame, principal):
        """One bounded UTF-8 JSON request -> one bounded JSON response.

        Call serially per Store connection. Framing, transport authentication,
        peer admission/rate limits and stream lifecycle belong to the peer host.
        """
        request_id = None
        try:
            if (not isinstance(principal, Principal) or not isinstance(principal.roles, frozenset)
                    or not principal.subject or type(frame) is not bytes or len(frame) > MAX_FRAME):
                raise RedemptionError('invalid context or frame')
            request = json.loads(frame.decode(), object_pairs_hook=_unique_object,
                                 parse_constant=_reject_constant, parse_float=_finite_float)
            if not isinstance(request, dict):
                raise RedemptionError('invalid request')
            candidate = request.get('id')
            if not isinstance(candidate, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', candidate):
                raise RedemptionError('invalid request id')
            request_id = candidate
            op = request.get('op')
            fields = {'claim': {'recipient_key'}, 'status': set(), 'observe': {'start', 'end', 'challenge'}}
            if op not in fields or set(request) != {'id', 'op', 'coupon'} | fields[op]:
                raise RedemptionError('invalid operation fields')
            coupon = request['coupon']
            if not isinstance(coupon, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', coupon):
                raise RedemptionError('invalid coupon')
            grant = self.store.db.execute('SELECT * FROM service_grants WHERE digest=?',
                                          (self.store.digest(coupon),)).fetchone()
            if (grant is None or grant['protocol_version'] != 1 or grant['sponsor'] != self.sponsor
                    or grant['observer'] != self.observer):
                raise RedemptionError('access denied')
            if op == 'claim':
                _require(principal, 'recipient', grant['recipient'])
                recipient = base64.b64decode(request['recipient_key'], validate=True)
                result = self.store.redeem(coupon, recipient, self.provider)
            elif op == 'status':
                allowed = any(role in principal.roles and principal.subject == grant[role]
                              for role in ('sponsor', 'recipient', 'observer'))
                if not allowed:
                    raise RedemptionError('access denied')
                row = self.store.db.execute('SELECT state,key_id,accounting_blocked FROM coupons WHERE digest=?',
                                             (grant['digest'],)).fetchone()
                result = dict(row)
                result['deposit_release_authorized'] = False
            else:
                _require(principal, 'observer', grant['observer'])
                _window(request['start'], request['end'])
                challenge = request['challenge']
                if not isinstance(challenge, str) or not re.fullmatch(r'[0-9a-f]{64}', challenge):
                    raise RedemptionError('invalid verifier challenge')
                result = observe_and_sign(self.store, coupon, self.provider, self.signing_key,
                                          request['start'], request['end'], challenge)
            response = {'id': request_id, 'ok': True, 'result': result}
            encoded = json.dumps(response, separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > MAX_FRAME:
                raise RedemptionError('response too large')
            return encoded
        except Exception:
            # Same failure envelope for unknown coupon, denied caller, invalid
            # message and upstream failure. No secrets/provider errors echoed.
            return json.dumps({'id': request_id, 'ok': False, 'error': 'request_failed'},
                              separators=(',', ':')).encode()


def main():
    """Local protocol harness, entirely synthetic; opens no network socket."""
    class SyntheticProvider:
        def create_key(self, name, budget):
            return IssuedKey('11111111-1111-4111-8111-111111111111', 'synthetic-private-key')
        def usage_rows(self, key_id, start, end):
            return [{'id': 'synthetic-row', 'source': 'inference', 'api_key_id': key_id,
                     'total_cost_nano_usd': 5_000_000_000}]
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'state.sqlite')
        service = DsmackCouponService(store, SyntheticProvider(), Ed25519PrivateKey.generate(),
                                     sponsor_subject='demo:sponsor', observer_subject='demo:observer')
        coupon = service.provision(Principal('demo:sponsor', frozenset({'sponsor'})),
                                   5_000_000_000, 'demo:recipient')
        public = X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        claim = json.loads(service.dispatch(json.dumps({'id': 'claim1', 'op': 'claim', 'coupon': coupon,
            'recipient_key': base64.b64encode(public).decode()}).encode(),
            Principal('demo:recipient', frozenset({'recipient'}))))
        observation = json.loads(service.dispatch(json.dumps({'id': 'observe1', 'op': 'observe',
            'coupon': coupon, 'start': '2026-10-10T00:00:00Z', 'end': '2026-10-11T00:00:00Z',
            'challenge': 'ab' * 32}).encode(), Principal('demo:observer', frozenset({'observer'}))))
        print(json.dumps({'mode': 'local-protocol-harness', 'claim_ok': claim['ok'],
                          'observation_ok': observation['ok'], 'environment': 'local-unattested',
                          'deposit_release_authorized': False}))
        store.close()


if __name__ == '__main__':
    main()
