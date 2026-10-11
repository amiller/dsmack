"""Pre-bound offer binding experiment; not an accountless public release."""
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timezone

from .evidence import observe_and_sign
from .offer_v2 import amount, canonical, expiry, offer_hash, POLICY
from .service import DsmackCouponService, Principal, MAX_FRAME, _require, _subject, _window
from .spike import RedemptionError
from .transport import _unique_object, _reject_constant, _finite_float


class DsmackCouponServiceV2(DsmackCouponService):
    def __init__(self, store, provider, signing_key, *, sponsor_subject, observer_subject,
                 issuer_peer_id, provider_binding, clock=None):
        super().__init__(store, provider, signing_key, sponsor_subject=sponsor_subject,
                         observer_subject=observer_subject)
        if not isinstance(issuer_peer_id, str) or not re.fullmatch(r'[A-Za-z0-9]{1,200}', issuer_peer_id):
            raise RedemptionError('invalid issuer identity')
        self.issuer_peer = issuer_peer_id
        self.provider_id = 'synthetic-near' if provider_binding['mode'] == 'synthetic' else 'near'
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        store.db.executescript('''
            CREATE TABLE IF NOT EXISTS service_v2_identity (
                singleton INTEGER PRIMARY KEY, issuer_peer TEXT NOT NULL,
                salt BLOB NOT NULL, scope_commitment TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS service_v2_offers (
                digest TEXT PRIMARY KEY, offer TEXT NOT NULL, offer_hash TEXT NOT NULL);
        ''')
        old = store.db.execute('SELECT * FROM service_v2_identity WHERE singleton=1').fetchone()
        salt = old['salt'] if old is not None else secrets.token_bytes(32)
        self.scope_commitment = hashlib.sha256(b'dsmack-coupon-scope-v2\0' + salt + canonical(provider_binding)).hexdigest()
        if old is not None and (old['issuer_peer'] != issuer_peer_id or old['scope_commitment'] != self.scope_commitment):
            raise RedemptionError('v2 state belongs to different issuer or account')
        store.db.execute('INSERT OR IGNORE INTO service_v2_identity VALUES (1,?,?,?)',
                         (issuer_peer_id, salt, self.scope_commitment))

    def provision(self, principal, budget_nano_usd, recipient_subject, claim_expires_at):
        _require(principal, 'sponsor', self.sponsor)
        budget = amount(budget_nano_usd)
        expiry(claim_expires_at)
        recipient = _subject(recipient_subject)
        self.store.db.execute('BEGIN IMMEDIATE')
        try:
            coupon = self.store.issue_coupon(budget)
            digest = self.store.digest(coupon)
            offer = {'version': 2, 'coupon_digest': digest,
                'issuer': {'peer_id': self.issuer_peer, 'policy': POLICY},
                'provider': {'id': self.provider_id, 'scope_commitment': self.scope_commitment},
                'recipient_subject': recipient, 'delivery_profile': 'x25519-aesgcm-session-only',
                'budget_nano_usd': budget_nano_usd, 'cap_semantics': 'nominal-provider-limit',
                'claim_expires_at': claim_expires_at, 'provider_expires_at': None,
                'sponsor_powers': ['revoke', 'change_limits']}
            committed_hash = offer_hash(offer)
            self.store.db.execute('INSERT INTO service_grants (digest,sponsor,recipient,observer,protocol_version) VALUES (?,?,?,?,2)',
                                   (digest, self.sponsor, recipient, self.observer))
            self.store.db.execute('INSERT INTO service_v2_offers VALUES (?,?,?)',
                                   (digest, canonical(offer).decode(), committed_hash))
            self.store.db.execute('COMMIT')
            return {'coupon': coupon, 'offer': offer, 'offer_hash': committed_hash,
                    'deposit_release_authorized': False}
        except BaseException:
            self.store.db.execute('ROLLBACK')
            raise

    def dispatch(self, frame, principal, *, local_peer):
        request_id = None
        try:
            if (local_peer != self.issuer_peer or not isinstance(principal, Principal)
                    or not isinstance(principal.roles, frozenset) or type(frame) is not bytes
                    or len(frame) > MAX_FRAME):
                raise RedemptionError('invalid context or frame')
            request = json.loads(frame.decode(), object_pairs_hook=_unique_object,
                                 parse_constant=_reject_constant, parse_float=_finite_float)
            if not isinstance(request, dict):
                raise RedemptionError('invalid request')
            candidate = request.get('id')
            if not isinstance(candidate, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', candidate):
                raise RedemptionError('invalid request id')
            request_id = candidate
            fields = {'offer': set(), 'status': set(), 'claim': {'recipient_key', 'offer_hash'},
                      'observe': {'start', 'end', 'challenge'}}
            op = request.get('op')
            if op not in fields or set(request) != {'id', 'op', 'coupon'} | fields[op]:
                raise RedemptionError('invalid operation fields')
            coupon = request['coupon']
            if not isinstance(coupon, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', coupon):
                raise RedemptionError('invalid coupon')
            digest = self.store.digest(coupon)
            grant = self.store.db.execute('SELECT * FROM service_grants WHERE digest=?', (digest,)).fetchone()
            if (grant is None or grant['protocol_version'] != 2 or grant['sponsor'] != self.sponsor
                    or grant['observer'] != self.observer):
                raise RedemptionError('access denied')
            if not any(role in principal.roles and principal.subject == grant[role]
                       for role in ('sponsor', 'recipient', 'observer')):
                raise RedemptionError('access denied')
            stored = self.store.db.execute('SELECT * FROM service_v2_offers WHERE digest=?', (digest,)).fetchone()
            offer = json.loads(stored['offer'])
            if offer_hash(offer) != stored['offer_hash']:
                raise RedemptionError('offer state mismatch')
            row = self.store.db.execute('SELECT state,key_id,accounting_blocked,budget FROM coupons WHERE digest=?', (digest,)).fetchone()
            if (offer['coupon_digest'] != digest or amount(offer['budget_nano_usd']) != row['budget']
                    or offer['recipient_subject'] != grant['recipient']
                    or offer['issuer']['peer_id'] != self.issuer_peer
                    or offer['provider'] != {'id': self.provider_id, 'scope_commitment': self.scope_commitment}):
                raise RedemptionError('offer grant binding mismatch')
            expired = self.clock() >= expiry(offer['claim_expires_at'])
            if op == 'offer':
                result = {'offer': offer, 'offer_hash': stored['offer_hash']}
            elif op == 'status':
                state = 'reconciliation_required' if row['state'] in ('issuing', 'quarantined') else row['state']
                if state not in ('ready', 'delivered', 'reconciliation_required'):
                    raise RedemptionError('invalid durable state')
                result = {'state': state, 'claim_expired': expired,
                          'accounting_blocked': bool(row['accounting_blocked']),
                          'automatic_retry_allowed': False, 'deposit_release_authorized': False}
                if row['key_id'] is not None:
                    result['key_id'] = row['key_id']
            elif op == 'claim':
                _require(principal, 'recipient', grant['recipient'])
                if request['offer_hash'] != stored['offer_hash'] or (row['state'] == 'ready' and expired):
                    raise RedemptionError('offer not accepted or expired')
                recipient = base64.b64decode(request['recipient_key'], validate=True)
                result = self.store.redeem(coupon, recipient, self.provider, accepted_offer_hash=stored['offer_hash'])
            else:
                _require(principal, 'observer', grant['observer'])
                _window(request['start'], request['end'])
                challenge = request['challenge']
                if not isinstance(challenge, str) or not re.fullmatch(r'[0-9a-f]{64}', challenge):
                    raise RedemptionError('invalid verifier challenge')
                result = observe_and_sign(self.store, coupon, self.provider, self.signing_key,
                    request['start'], request['end'], challenge, accepted_offer=offer)
            encoded = json.dumps({'id': request_id, 'ok': True, 'result': result},
                                 separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > MAX_FRAME:
                raise RedemptionError('response too large')
            return encoded
        except Exception:
            return json.dumps({'id': request_id, 'ok': False, 'error': 'request_failed'},
                              separators=(',', ':')).encode()
