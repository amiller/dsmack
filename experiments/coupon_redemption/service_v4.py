"""Policy-bound accountless claim; issuance authorization remains independent."""
import base64
import json
import re

from .evidence import observe_and_sign
from .offer_v2 import amount, canonical, expiry, POLICY
from .offer_v4 import offer_hash_v4, peer_hash, recipient_subject, validate_issuer
from .service import Principal, MAX_FRAME, _require, _window
from .service_v2 import DsmackCouponServiceV2
from .spike import RedemptionError
from .transport import _unique_object, _reject_constant, _finite_float


class DsmackCouponServiceV4(DsmackCouponServiceV2):
    def __init__(self, *args, issuer_binding, issuance_authorizer=None,
                 observation_environment='local-unattested', **kwargs):
        super().__init__(*args, **kwargs)
        from cryptography.hazmat.primitives import serialization
        import hashlib
        public = self.signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer_binding = dict(validate_issuer(issuer_binding))
        if (self.issuer_binding['peer_id'] != self.issuer_peer
                or self.issuer_binding['issuer_public_key_sha256'] != hashlib.sha256(public).hexdigest()):
            raise RedemptionError('issuer identity differs from service signer')
        self.issuance_authorizer = issuance_authorizer
        self.observation_environment = observation_environment
        self.store.db.execute('CREATE TABLE IF NOT EXISTS service_v4_binding (singleton INTEGER PRIMARY KEY, value TEXT NOT NULL)')
        binding = canonical(self.issuer_binding).decode()
        self.store.db.execute('INSERT OR IGNORE INTO service_v4_binding VALUES (1,?)', (binding,))
        old = self.store.db.execute('SELECT value FROM service_v4_binding WHERE singleton=1').fetchone()
        if old['value'] != binding:
            raise RedemptionError('state belongs to another issuer policy')
        self.store.db.executescript('''
            CREATE TABLE IF NOT EXISTS service_v4_offers (
                digest TEXT PRIMARY KEY, offer TEXT NOT NULL, offer_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS service_v4_claims (
                digest TEXT PRIMARY KEY, peer TEXT NOT NULL,
                delivery_key BLOB NOT NULL, offer_hash TEXT NOT NULL);
        ''')

    def provision(self, principal, budget_nano_usd, claim_expires_at):
        _require(principal, 'sponsor', self.sponsor)
        budget = amount(budget_nano_usd)
        expiry(claim_expires_at)
        self.store.db.execute('BEGIN IMMEDIATE')
        try:
            coupon = self.store.issue_coupon(budget)
            digest = self.store.digest(coupon)
            offer = {'version': 4, 'coupon_digest': digest,
                'issuer': dict(self.issuer_binding),
                'provider': {'id': self.provider_id, 'scope_commitment': self.scope_commitment},
                'claim_policy': 'first-authenticated-bearer',
                'delivery_profile': 'x25519-aesgcm-session-only', 'budget_nano_usd': budget_nano_usd,
                'cap_semantics': 'nominal-provider-limit', 'claim_expires_at': claim_expires_at,
                'provider_expires_at': None, 'sponsor_powers': ['revoke', 'change_limits']}
            committed_hash = offer_hash_v4(offer)
            self.store.db.execute('INSERT INTO service_grants (digest,sponsor,recipient,observer,protocol_version) VALUES (?,?,?,?,4)',
                                   (digest, self.sponsor, 'unbound:' + digest, self.observer))
            self.store.db.execute('INSERT INTO service_v4_offers VALUES (?,?,?)',
                                   (digest, canonical(offer).decode(), committed_hash))
            self.store.db.execute('COMMIT')
            return {'coupon': coupon, 'offer': offer, 'offer_hash': committed_hash,
                    'deposit_release_authorized': False}
        except BaseException:
            self.store.db.execute('ROLLBACK')
            raise

    def _load(self, coupon):
        digest = self.store.digest(coupon)
        grant = self.store.db.execute('SELECT * FROM service_grants WHERE digest=?', (digest,)).fetchone()
        if (grant is None or grant['protocol_version'] != 4 or grant['sponsor'] != self.sponsor
                or grant['observer'] != self.observer):
            raise RedemptionError('access denied')
        stored = self.store.db.execute('SELECT * FROM service_v4_offers WHERE digest=?', (digest,)).fetchone()
        offer = json.loads(stored['offer'])
        row = self.store.db.execute('SELECT * FROM coupons WHERE digest=?', (digest,)).fetchone()
        if (offer_hash_v4(offer) != stored['offer_hash'] or offer['coupon_digest'] != digest
                or amount(offer['budget_nano_usd']) != row['budget']
                or offer['issuer'] != self.issuer_binding
                or offer['provider'] != {'id': self.provider_id, 'scope_commitment': self.scope_commitment}):
            raise RedemptionError('invalid offer binding')
        return grant, stored, offer, row

    def _access(self, grant, peer, principal):
        if any(role in principal.roles and principal.subject == grant[role] for role in ('sponsor', 'observer')):
            return True
        winner = self.store.db.execute('SELECT peer FROM service_v4_claims WHERE digest=?', (grant['digest'],)).fetchone()
        return (winner is not None and winner['peer'] == peer and grant['recipient'] == recipient_subject(peer))

    def _claim(self, coupon, peer, public, accepted_hash):
        def bind(row):
            # Executed inside Store's BEGIN IMMEDIATE. All acceptance and
            # authority facts are reloaded before the durable intent changes.
            grant, stored, offer, current = self._load(coupon)
            if accepted_hash != stored['offer_hash'] or current['state'] != row['state']:
                raise RedemptionError('invalid accepted offer')
            winner = self.store.db.execute('SELECT * FROM service_v4_claims WHERE digest=?', (grant['digest'],)).fetchone()
            if row['state'] == 'ready':
                if (self.clock() >= expiry(offer['claim_expires_at']) or winner is not None
                        or grant['recipient'] != 'unbound:' + grant['digest']):
                    raise RedemptionError('initial claim unavailable')
                self.store.db.execute('INSERT INTO service_v4_claims VALUES (?,?,?,?)',
                    (grant['digest'], peer, public, accepted_hash))
                self.store.db.execute('UPDATE service_grants SET recipient=? WHERE digest=?',
                    (recipient_subject(peer), grant['digest']))
            elif (winner is None or winner['peer'] != peer or winner['delivery_key'] != public
                    or winner['offer_hash'] != accepted_hash or grant['recipient'] != recipient_subject(peer)):
                raise RedemptionError('coupon bound to different claimant')
        return self.store.redeem(coupon, public, self.provider, accepted_offer_hash=accepted_hash,
                                 claim_guard=bind, recipient_peer=peer, delivery_version=4,
                                 before_create=lambda: self._authorize_creation(coupon, peer, public, accepted_hash))

    def _authorize_creation(self, coupon, peer, public, accepted_hash):
        # Trusted host enforcement boundary, after durable issuing commit and
        # before provider access. A policy hash alone grants no permission.
        if self.issuance_authorizer is None:
            raise RedemptionError('issuance custody is not qualified')
        self.issuance_authorizer(self.store.digest(coupon), peer, public, accepted_hash, dict(self.issuer_binding))

    def dispatch(self, frame, principal, *, local_peer, remote_peer):
        request_id = None
        try:
            if (local_peer != self.issuer_peer or not isinstance(principal, Principal)
                    or not isinstance(principal.roles, frozenset) or type(frame) is not bytes
                    or len(frame) > MAX_FRAME):
                raise RedemptionError('invalid context or frame')
            peer_hash(remote_peer)
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
            grant, stored, offer, row = self._load(coupon)
            if op in ('offer', 'status'):
                if row['state'] != 'ready' and not self._access(grant, remote_peer, principal):
                    raise RedemptionError('access denied')
                if op == 'offer':
                    result = {'offer': offer, 'offer_hash': stored['offer_hash']}
                else:
                    state = 'reconciliation_required' if row['state'] in ('issuing', 'quarantined') else row['state']
                    if state not in ('ready', 'delivered', 'reconciliation_required'):
                        raise RedemptionError('invalid durable state')
                    result = {'state': state, 'claim_expired': self.clock() >= expiry(offer['claim_expires_at']),
                              'accounting_blocked': bool(row['accounting_blocked']),
                              'automatic_retry_allowed': False, 'deposit_release_authorized': False}
                    if row['key_id'] is not None:
                        result['key_id'] = row['key_id']
            elif op == 'claim':
                public = base64.b64decode(request['recipient_key'], validate=True)
                result = self._claim(coupon, remote_peer, public, request['offer_hash'])
            else:
                _require(principal, 'observer', grant['observer'])
                winner = self.store.db.execute('SELECT peer FROM service_v4_claims WHERE digest=?', (grant['digest'],)).fetchone()
                if winner is None:
                    raise RedemptionError('no claimed key')
                _window(request['start'], request['end'])
                challenge = request['challenge']
                if not isinstance(challenge, str) or not re.fullmatch(r'[0-9a-f]{64}', challenge):
                    raise RedemptionError('invalid verifier challenge')
                result = observe_and_sign(self.store, coupon, self.provider, self.signing_key,
                    request['start'], request['end'], challenge, accepted_offer=offer, recipient_peer=winner['peer'],
                    environment=self.observation_environment)
            encoded = json.dumps({'id': request_id, 'ok': True, 'result': result}, separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > MAX_FRAME:
                raise RedemptionError('response too large')
            return encoded
        except Exception:
            return json.dumps({'id': request_id, 'ok': False, 'error': 'request_failed'}, separators=(',', ':')).encode()
