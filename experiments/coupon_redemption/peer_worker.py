"""Protected anonymous-pipe worker for the experimental dsmack peer service.

Only the trusted spawning adapter may write stdin. There is no public listener.
Peer IDs identify transport keys, never attested workloads or provider accounts.
"""
import argparse
import base64
import fcntl
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .near import Near
from .service import DsmackCouponService, Principal, MAX_FRAME, _subject
from .service_v2 import DsmackCouponServiceV2
from .offer_v2 import PROTOCOL_V2
from .offer_v3 import PROTOCOL_V3, peer_hash, recipient_subject
from .service_v3 import DsmackCouponServiceV3
from .service_v4 import DsmackCouponServiceV4
from .offer_v4 import PROTOCOL_V4, ISSUER_PROTOCOL, ISSUER_POLICY, validate_issuer
from .issuer_service import IssuerEvidenceService, MAX_ISSUER_FRAME
from .dstack_issuer_identity import DstackIssuerIdentity
from .spike import Store, IssuedKey, RedemptionError
from .transport import NearHTTPS, _unique_object, _reject_constant, _finite_float

MAX_BRIDGE = 3 * 1024 * 1024
MAX_COUPON_BRIDGE = 100_000
ROLES = {'sponsor', 'recipient', 'observer'}


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant, parse_float=_finite_float)


def _protected(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise RedemptionError('protected file required')
    return info


def _private_file(path, *, read=True):
    """Reject links, foreign ownership and group/world access before opening."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = _protected(fd)
        if not read:
            return None
        if info.st_size > MAX_COUPON_BRIDGE:
            raise RedemptionError('protected file required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            return source.read(MAX_COUPON_BRIDGE + 1)
    finally:
        os.close(fd)


class SyntheticProvider:
    """Explicit local fixture: durable event counts, no real network or secrets."""
    def __init__(self, store):
        self.store = store
        store.db.execute('CREATE TABLE IF NOT EXISTS synthetic_events (kind TEXT NOT NULL)')

    def create_key(self, name, budget):
        self.store.db.execute("INSERT INTO synthetic_events VALUES ('create')")
        return IssuedKey('synthetic-' + name, 'synthetic-only-' + name)

    def usage_rows(self, key_id, start, end):
        self.store.db.execute("INSERT INTO synthetic_events VALUES ('read')")
        return [{'source': 'inference', 'id': 'synthetic-row-' + key_id,
                 'api_key_id': key_id, 'total_cost_nano_usd': 5_000_000_000}]


class Worker:
    def __init__(self, config_path, *, issuer_collector_factory=None, issuance_authorizer=None):
        # These are host-code capabilities, never configuration or wire booleans.
        self.issuer_collector_factory = issuer_collector_factory
        self.issuance_authorizer = issuance_authorizer
        self.lock = self.store = None
        try:
            self._initialize(config_path)
        except BaseException:
            self.close()
            raise

    def _initialize(self, config_path):
        os.umask(0o077)
        config = _json(_private_file(config_path))
        required = {'version', 'state_dir', 'sponsor_subject', 'observer_subject', 'peers', 'provider'}
        if (not isinstance(config, dict) or set(config) not in (required, required | {'issuer_peer_id'}, required | {'issuer_peer_id', 'issuer_evidence'})
                or config['version'] != 1):
            raise RedemptionError('invalid protected configuration')
        _subject(config['sponsor_subject'])
        _subject(config['observer_subject'])
        self.peers = {}
        if not isinstance(config['peers'], dict) or not 1 <= len(config['peers']) <= 1000:
            raise RedemptionError('invalid peer authorization')
        for peer, grant in config['peers'].items():
            if (not isinstance(peer, str) or not 1 <= len(peer) <= 200 or not peer.isalnum()
                    or not isinstance(grant, dict) or set(grant) != {'subject', 'roles'}
                    or not isinstance(grant['roles'], list) or not grant['roles']
                    or any(not isinstance(role, str) or role not in ROLES for role in grant['roles'])
                    or len(grant['roles']) != len(set(grant['roles']))):
                raise RedemptionError('invalid peer authorization')
            self.peers[peer] = Principal(_subject(grant['subject']), frozenset(grant['roles']))
        directory = Path(config['state_dir'])
        if not directory.is_absolute():
            raise RedemptionError('absolute state directory required')
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RedemptionError('protected state directory required')
        # Hold this lock for the worker lifetime. A second supervisor must not
        # mount a competing issuer or create a different signing identity.
        self.lock = os.open(directory / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        _protected(self.lock)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ('state.sqlite', 'state.sqlite-wal', 'state.sqlite-shm'):
            if os.path.lexists(directory / name):
                _private_file(directory / name, read=False)
        key_path = directory / 'observer.key'
        if not os.path.lexists(key_path):
            key = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(key)
                output.flush()
                os.fsync(output.fileno())
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        signing_key = Ed25519PrivateKey.from_private_bytes(_private_file(key_path))
        provider_config = config['provider']
        if not isinstance(provider_config, dict):
            raise RedemptionError('invalid provider configuration')
        mode = provider_config.get('mode')
        if mode == 'synthetic' and set(provider_config) == {'mode'}:
            provider_binding = {'mode': mode}
        elif mode == 'near' and set(provider_config) == {
                'mode', 'workspace_id', 'organization_id', 'credentials_file'}:
            provider_binding = {k: provider_config[k] for k in ('mode', 'workspace_id', 'organization_id')}
        else:
            raise RedemptionError('invalid provider configuration')
        if 'issuer_evidence' in config and mode == 'near':
            # Policy hashes and a valid quote do not authenticate secret custody,
            # configuration provenance, provider owner powers or chain finality.
            # The qualified live factory must be implemented independently.
            raise RedemptionError('qualified near issuance factory unavailable')
        self.store = Store(directory / 'state.sqlite')
        if mode == 'synthetic':
            provider = SyntheticProvider(self.store)
        else:
            credentials_path = Path(provider_config['credentials_file'])
            if not credentials_path.is_absolute():
                raise RedemptionError('absolute protected credentials path required')
            credentials = _json(_private_file(credentials_path))
            if (not isinstance(credentials, dict) or set(credentials) != {'session_jwt', 'reporting_token'}
                    or any(not isinstance(v, str) or not v for v in credentials.values())):
                raise RedemptionError('invalid protected credentials')
            provider = Near(provider_config['workspace_id'], provider_config['organization_id'],
                            credentials['session_jwt'], credentials['reporting_token'], NearHTTPS())
        binding = json.dumps({'sponsor': config['sponsor_subject'], 'observer': config['observer_subject'],
                              'provider': provider_binding,
                              'signing_public_key': base64.b64encode(signing_key.public_key().public_bytes(
                                  serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}, sort_keys=True)
        self.store.db.execute('CREATE TABLE IF NOT EXISTS service_binding (singleton INTEGER PRIMARY KEY, value TEXT NOT NULL)')
        old = self.store.db.execute('SELECT value FROM service_binding WHERE singleton=1').fetchone()
        if old is not None and old['value'] != binding:
            raise RedemptionError('state belongs to a different service account')
        self.store.db.execute('INSERT OR IGNORE INTO service_binding VALUES (1,?)', (binding,))
        self.service = DsmackCouponService(self.store, provider, signing_key,
            sponsor_subject=config['sponsor_subject'], observer_subject=config['observer_subject'])
        self.service_v2 = None
        self.service_v3 = None
        self.service_v4 = None
        self.issuer_service = None
        if 'issuer_peer_id' in config:
            self.service_v2 = DsmackCouponServiceV2(self.store, provider, signing_key,
                sponsor_subject=config['sponsor_subject'], observer_subject=config['observer_subject'],
                issuer_peer_id=config['issuer_peer_id'], provider_binding=provider_binding)
            self.service_v3 = DsmackCouponServiceV3(self.store, provider, signing_key,
                sponsor_subject=config['sponsor_subject'], observer_subject=config['observer_subject'],
                issuer_peer_id=config['issuer_peer_id'], provider_binding=provider_binding)

        if 'issuer_evidence' in config:
            profile = config['issuer_evidence']
            if (type(profile) is not dict or set(profile) != {
                    'identity_policy_sha256', 'issuance_policy_sha256', 'socket_path', 'compose_file'}):
                raise RedemptionError('invalid issuer evidence configuration')
            compose_path = Path(profile['compose_file'])
            if not compose_path.is_absolute():
                raise RedemptionError('absolute protected compose path required')
            compose = _private_file(compose_path).decode('utf8')
            import hashlib
            public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            issuer = {'peer_id': config['issuer_peer_id'], 'policy': ISSUER_POLICY,
                'identity_policy_sha256': profile['identity_policy_sha256'],
                'issuance_policy_sha256': profile['issuance_policy_sha256'],
                'issuer_public_key_sha256': hashlib.sha256(public).hexdigest()}
            validate_issuer(issuer)  # Protected syntax/pins before any guest socket call.
            factory = self.issuer_collector_factory or DstackIssuerIdentity.from_socket
            collector = factory(profile['socket_path'], signing_key=signing_key)
            self.issuer_service = IssuerEvidenceService(issuer_peer=config['issuer_peer_id'], signing_key=signing_key,
                identity_policy_sha256=profile['identity_policy_sha256'],
                issuance_policy_sha256=profile['issuance_policy_sha256'], collector=collector, app_compose=compose)
            self.service_v4 = DsmackCouponServiceV4(self.store, provider, signing_key,
                sponsor_subject=config['sponsor_subject'], observer_subject=config['observer_subject'],
                issuer_peer_id=config['issuer_peer_id'], provider_binding=provider_binding,
                issuer_binding=issuer, issuance_authorizer=self.issuance_authorizer)

    def request(self, request):
        if not isinstance(request, dict) or type(request.get('seq')) is not int:
            raise RedemptionError('invalid bridge request')
        op = request.get('kind')
        if op != 'issuer_dispatch' and len(json.dumps(request).encode()) > MAX_COUPON_BRIDGE:
            raise RedemptionError('coupon bridge frame too large')
        peer = request.get('peer')
        principal = self.peers.get(peer)
        if op in ('dispatch_v3', 'dispatch_v4', 'issuer_dispatch'):
            peer_hash(peer)
            if principal is None:
                # Authenticated transport key + coupon capability authorizes
                # only the v3 bearer path; never invent operator/observer roles.
                principal = Principal(recipient_subject(peer), frozenset())
        if principal is None:
            raise RedemptionError('access denied')
        if op == 'issuer_dispatch':
            if (self.issuer_service is None or request.get('protocol') != ISSUER_PROTOCOL
                    or request.get('local_peer') != self.issuer_service.issuer_peer
                    or set(request) != {'seq', 'kind', 'peer', 'protocol', 'local_peer', 'frame'}):
                raise RedemptionError('invalid issuer context')
            frame = base64.b64decode(request['frame'], validate=True)
            if len(frame) > MAX_ISSUER_FRAME:
                raise RedemptionError('issuer frame too large')
            return {'frame': base64.b64encode(self.issuer_service.dispatch(frame,
                local_peer=request['local_peer'], remote_peer=peer)).decode()}
        if op in ('dispatch_v4', 'provision_v4', 'pending_v4'):
            if (self.service_v4 is None or request.get('protocol') != PROTOCOL_V4
                    or request.get('local_peer') != self.service_v4.issuer_peer):
                raise RedemptionError('invalid v4 issuer context')
            common = {'seq', 'kind', 'peer', 'protocol', 'local_peer'}
            if op == 'dispatch_v4' and set(request) == common | {'frame'}:
                frame = base64.b64decode(request['frame'], validate=True)
                if len(frame) > MAX_FRAME:
                    raise RedemptionError('frame too large')
                return {'frame': base64.b64encode(self.service_v4.dispatch(frame, principal,
                    local_peer=request['local_peer'], remote_peer=peer)).decode()}
            if op == 'provision_v4' and set(request) == common | {'budget', 'claim_expires_at'}:
                return self.service_v4.provision(principal, request['budget'], request['claim_expires_at'])
            if op == 'pending_v4' and set(request) == common:
                if principal.subject != self.service.sponsor or 'sponsor' not in principal.roles:
                    raise RedemptionError('access denied')
                return {'pending': self.store.pending(), 'automatic_retry_allowed': False}
            raise RedemptionError('invalid bridge operation')
        if op in ('dispatch_v3', 'provision_v3', 'pending_v3'):
            if (self.service_v3 is None or request.get('protocol') != PROTOCOL_V3
                    or request.get('local_peer') != self.service_v3.issuer_peer):
                raise RedemptionError('invalid v3 issuer context')
            common = {'seq', 'kind', 'peer', 'protocol', 'local_peer'}
            if op == 'dispatch_v3' and set(request) == common | {'frame'}:
                frame = base64.b64decode(request['frame'], validate=True)
                if len(frame) > MAX_FRAME:
                    raise RedemptionError('frame too large')
                return {'frame': base64.b64encode(self.service_v3.dispatch(
                    frame, principal, local_peer=request['local_peer'], remote_peer=peer)).decode()}
            if op == 'provision_v3' and set(request) == common | {'budget', 'claim_expires_at'}:
                return self.service_v3.provision(principal, request['budget'], request['claim_expires_at'])
            if op == 'pending_v3' and set(request) == common:
                if principal.subject != self.service.sponsor or 'sponsor' not in principal.roles:
                    raise RedemptionError('access denied')
                return {'pending': self.store.pending(), 'automatic_retry_allowed': False}
            raise RedemptionError('invalid bridge operation')
        if op in ('dispatch_v2', 'provision_v2', 'pending_v2'):
            if (self.service_v2 is None or request.get('protocol') != PROTOCOL_V2
                    or request.get('local_peer') != self.service_v2.issuer_peer):
                raise RedemptionError('invalid v2 issuer context')
            common = {'seq', 'kind', 'peer', 'protocol', 'local_peer'}
            if op == 'dispatch_v2' and set(request) == common | {'frame'}:
                frame = base64.b64decode(request['frame'], validate=True)
                if len(frame) > MAX_FRAME:
                    raise RedemptionError('frame too large')
                return {'frame': base64.b64encode(self.service_v2.dispatch(
                    frame, principal, local_peer=request['local_peer'])).decode()}
            if op == 'provision_v2' and set(request) == common | {'budget', 'recipient_peer', 'claim_expires_at'}:
                recipient = self.peers.get(request['recipient_peer'])
                if recipient is None or 'recipient' not in recipient.roles:
                    raise RedemptionError('recipient not admitted')
                return self.service_v2.provision(principal, request['budget'], recipient.subject, request['claim_expires_at'])
            if op == 'pending_v2' and set(request) == common:
                if principal.subject != self.service.sponsor or 'sponsor' not in principal.roles:
                    raise RedemptionError('access denied')
                return {'pending': self.store.pending(), 'automatic_retry_allowed': False}
            raise RedemptionError('invalid bridge operation')
        if op == 'dispatch' and set(request) == {'seq', 'kind', 'peer', 'frame'}:
            frame = base64.b64decode(request['frame'], validate=True)
            if len(frame) > MAX_FRAME:
                raise RedemptionError('frame too large')
            return {'frame': base64.b64encode(self.service.dispatch(frame, principal)).decode()}
        if op == 'provision' and set(request) == {'seq', 'kind', 'peer', 'budget', 'recipient_peer'}:
            recipient = self.peers.get(request['recipient_peer'])
            if recipient is None or 'recipient' not in recipient.roles:
                raise RedemptionError('recipient not admitted')
            coupon = self.service.provision(principal, request['budget'], recipient.subject)
            return {'coupon': coupon, 'deposit_release_authorized': False}
        if op == 'pending' and set(request) == {'seq', 'kind', 'peer'}:
            if principal.subject != self.service.sponsor or 'sponsor' not in principal.roles:
                raise RedemptionError('access denied')
            return {'pending': self.store.pending(), 'automatic_retry_allowed': False}
        raise RedemptionError('invalid bridge operation')

    def close(self):
        if self.store is not None:
            self.store.close()
            self.store = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        if _json(_private_file(args.config)).get('domain') == 'dsmack-coupon-staging-config-v1':
            from .live_worker import LiveWorker
            worker = LiveWorker(args.config)
        else:
            worker = Worker(args.config)
    except Exception:
        print('Coupon worker setup failed.', file=sys.stderr)
        return 1
    print(json.dumps(worker.ready() if hasattr(worker, 'ready') else
        {'ready': True, 'environment': 'local-unattested'}), flush=True)
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_BRIDGE + 1)
            if not raw:
                return 0
            if len(raw) > MAX_BRIDGE or not raw.endswith(b'\n'):
                return 1
            seq = None
            try:
                request = _json(raw)
                seq = request.get('seq') if isinstance(request, dict) else None
                result = worker.request(request)
                response = {'seq': seq, 'ok': True, 'result': result}
            except Exception:
                response = {'seq': seq, 'ok': False, 'error': 'request_failed'}
            encoded = json.dumps(response, separators=(',', ':'), allow_nan=False)
            if len(encoded.encode()) > MAX_BRIDGE:
                return 1
            print(encoded, flush=True)
    finally:
        worker.close()


if __name__ == '__main__':
    raise SystemExit(main())
