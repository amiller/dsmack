"""Signed, genuine-SDK debug-staging worker. No legacy provider create routes."""
import fcntl
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .async_service_v4 import AsyncCouponServiceV4
from .dstack_issuer_identity import DstackIssuerIdentity
from .issuer_service import IssuerEvidenceService
from .issuance_guard import FinalizedIssuanceGuard, BaseSafeIssuanceGuard
from .near import Near
from .offer_v2 import amount, expiry
from .offer_v4 import ISSUER_POLICY
from .peer_worker import Worker, _private_file, _protected, _json, ROLES
from .service import Principal, _subject
from .spike import Store, RedemptionError
from .staging_approval import approval, configuration, APPROVAL_DOMAIN, payload_hash, canonical
from .transport import NearHTTPS

NOISE_KEY_PATH = 'dsmack/coupon-noise/v1/ed25519'
GUARD_KEY_PATH = 'dsmack/coupon-guard/v1/secp256k1'


def approval_root():
    # Measured image content, not an operator-selected config field or env key.
    path = Path(__file__).resolve().parents[2] / 'packaging/coupon/approval-root.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 256
                or info.st_nlink != 1 or info.st_uid not in (0, os.getuid())):
            raise RedemptionError('measured approval root required')
        root = _json(os.read(fd, 257))
        if (type(root) is not dict or set(root) != {'public_key_hex'}
                or type(root['public_key_hex']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', root['public_key_hex'])):
            # The shipped root is {"public_key_hex":null}: fail with the named
            # refusal, never a TypeError from the regex on a non-string.
            raise RedemptionError('measured approval root unavailable')
        return bytes.fromhex(root['public_key_hex'])
    finally:
        os.close(fd)


class StagingProvider:
    def __init__(self, provider, approved):
        self.provider, self.approved = provider, approved

    def create_key(self, name, budget):
        if (datetime.now(timezone.utc) >= expiry(self.approved['expires_at'])
                or budget > amount(self.approved['max_coupon_nano_usd'])):
            raise RedemptionError('staging effect approval expired')
        return self.provider.create_key(name, budget)

    def usage_rows(self, *args):
        return self.provider.usage_rows(*args)


class LiveWorker(Worker):
    approval_domain = APPROVAL_DOMAIN
    issuer_policy = ISSUER_POLICY
    noise_key_path = NOISE_KEY_PATH
    guard_key_path = GUARD_KEY_PATH

    def _authorization(self, config_path, root):
        approved = approval(_private_file(Path(config_path).parent / 'approval.json'), root)
        return approved, configuration(_private_file(config_path), root, approved)

    def _collector(self, config):
        return DstackIssuerIdentity.from_socket('/var/run/dstack.sock')

    def _runtime_info(self, collector, config):
        info = collector._client.info()
        if (info.app_id != self.approved['app_id'] or info.compose_hash != self.approved['compose_hash']
                or info.tcb_info.compose_hash != self.approved['compose_hash']):
            raise RedemptionError('signed configuration differs from actual application')
        return info.tcb_info.app_compose

    def _key(self, collector, path, algorithm):
        purpose = ('coupon encrypted peer identity' if path == NOISE_KEY_PATH
                   else 'coupon irreversible issuance attempt')
        return collector._client.get_key(path, purpose=purpose, algorithm=algorithm).decode_key()

    def _rpc(self, config):
        return None

    def _transport(self):
        return NearHTTPS()

    def _evidence_service(self, collector, app_compose):
        return IssuerEvidenceService(issuer_peer=self.issuer_peer, signing_key=collector._signer,
            identity_policy_sha256=self.approved['identity_policy_sha256'],
            issuance_policy_sha256=self.approved['issuance_policy_sha256'], collector=collector,
            app_compose=app_compose)

    def _initialize(self, config_path):
        os.umask(0o077)
        root = approval_root()
        self.approved, config = self._authorization(config_path, root)
        collector = self._collector(config)
        app_compose = self._runtime_info(collector, config)
        public = bytes.fromhex(collector.public_key_hex())
        if hashlib.sha256(public).hexdigest() != self.approved['issuer_public_key_sha256']:
            raise RedemptionError('signed configuration differs from SDK issuer key')
        self.noise_seed = self._key(collector, self.noise_key_path, 'ed25519')
        if type(self.noise_seed) is not bytes or len(self.noise_seed) != 32:
            raise RedemptionError('SDK peer identity unavailable')
        self.issuer_peer = config['issuer_peer_id']
        # Node computes the actual PeerId from these exact bytes before listening.
        self.peers = {}
        if type(config['peers']) is not dict or not 1 <= len(config['peers']) <= 1000:
            raise RedemptionError('invalid signed peer authorization')
        for peer, grant in config['peers'].items():
            if (type(peer) is not str or not re.fullmatch(r'[A-Za-z0-9]{16,128}', peer)
                    or type(grant) is not dict or set(grant) != {'subject', 'roles'}
                    or type(grant['roles']) is not list or not grant['roles']
                    or len(set(grant['roles'])) != len(grant['roles'])
                    or any(role not in ROLES for role in grant['roles'])):
                raise RedemptionError('invalid signed peer authorization')
            self.peers[peer] = Principal(_subject(grant['subject']), frozenset(grant['roles']))
        _subject(config['sponsor_subject']); _subject(config['observer_subject'])
        directory = Path(config['state_dir'])
        if not directory.is_absolute():
            raise RedemptionError('absolute state directory required')
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
            raise RedemptionError('protected state directory required')
        self.lock = os.open(directory / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        _protected(self.lock)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ('state.sqlite', 'state.sqlite-wal', 'state.sqlite-shm'):
            if os.path.lexists(directory / name):
                _private_file(directory / name, read=False)
        self.store = Store(directory / 'state.sqlite')
        binding = canonical({'approval_sha256': payload_hash(self.approval_domain, self.approved),
                             'issuer_peer': self.issuer_peer}).decode()
        self.store.db.execute('CREATE TABLE IF NOT EXISTS staging_binding (singleton INTEGER PRIMARY KEY, value TEXT NOT NULL)')
        self.store.db.execute('INSERT OR IGNORE INTO staging_binding VALUES (1,?)', (binding,))
        if self.store.db.execute('SELECT value FROM staging_binding WHERE singleton=1').fetchone()[0] != binding:
            raise RedemptionError('existing obligations require explicit policy migration')
        self.store.db.execute('CREATE TABLE IF NOT EXISTS service_v2_identity (singleton INTEGER PRIMARY KEY, issuer_peer TEXT NOT NULL, salt BLOB NOT NULL, scope_commitment TEXT NOT NULL)')
        self.store.db.execute('INSERT OR IGNORE INTO service_v2_identity VALUES (1,?,?,?)',
            (self.issuer_peer, bytes.fromhex(config['scope_salt_hex']), self.approved['provider_scope_commitment']))
        # SQL enforces both caps atomically even across independent connections.
        self.store.db.execute('CREATE TABLE IF NOT EXISTS staging_caps (singleton INTEGER PRIMARY KEY, coupon INTEGER NOT NULL, total INTEGER NOT NULL)')
        self.store.db.execute('INSERT OR IGNORE INTO staging_caps VALUES (1,?,?)',
            (amount(self.approved['max_coupon_nano_usd']), amount(self.approved['max_total_nano_usd'])))
        persisted = self.store.db.execute('SELECT coupon, total FROM staging_caps WHERE singleton=1').fetchone()
        if (persisted['coupon'] != amount(self.approved['max_coupon_nano_usd'])
                or persisted['total'] != amount(self.approved['max_total_nano_usd'])):
            # Existing state keeps its original authority; a re-signed budget is
            # an explicit migration, never a silent raise or cut.
            raise RedemptionError('staging budget cap migration required')
        self.store.db.executescript('''CREATE TRIGGER IF NOT EXISTS staging_budget BEFORE INSERT ON coupons
            WHEN NEW.budget > (SELECT coupon FROM staging_caps WHERE singleton=1)
              OR NEW.budget > (SELECT total FROM staging_caps WHERE singleton=1) - COALESCE((SELECT SUM(budget) FROM coupons),0)
            BEGIN SELECT RAISE(ABORT, 'staging budget cap'); END;''')
        # Checker consumes exact protected profile bytes; current intent never
        # enters this file. Configuration has already been independently signed.
        profile_path = directory / 'finality-profile.json'
        encoded_profile = canonical(config['finality_profile'])
        if os.path.lexists(profile_path):
            if _private_file(profile_path) != encoded_profile:
                raise RedemptionError('finality profile migration required')
        else:
            fd = os.open(profile_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(encoded_profile); file.flush(); os.fsync(file.fileno())
        guard_key = self._key(collector, self.guard_key_path, 'secp256k1')
        guard_type = BaseSafeIssuanceGuard if self.approved['guard']['chain_id'] == 8453 else FinalizedIssuanceGuard
        guard = guard_type(profile=config['finality_profile'], profile_path=profile_path,
            binary=str(Path(__file__).resolve().parents[2] / 'bin/dsmack-ethereum-finality'),
            private_key=guard_key, gas_price_wei=config['gas_price_wei'],
            deadline_seconds=config['job_deadline_seconds'] - 10, rpc=self._rpc(config))
        credentials = config['provider']
        near = Near(credentials['workspace_id'], credentials['organization_id'], credentials['session_jwt'],
                    credentials['reporting_token'], self._transport())
        provider = StagingProvider(near, self.approved)
        issuer = {'peer_id': self.issuer_peer, 'policy': self.issuer_policy,
            **{name: self.approved[name] for name in ('identity_policy_sha256', 'issuance_policy_sha256', 'issuer_public_key_sha256')}}
        self.service_v4 = AsyncCouponServiceV4(self.store, provider, collector._signer,
            sponsor_subject=config['sponsor_subject'], observer_subject=config['observer_subject'],
            issuer_peer_id=self.issuer_peer, provider_binding={'mode': 'near',
                **{k: credentials[k] for k in ('workspace_id', 'organization_id')}},
            issuer_binding=issuer, issuance_authorizer=guard,
            observation_environment='debug-staging-operator-readable',
            max_active_jobs=config['max_active_jobs'], job_deadline_seconds=config['job_deadline_seconds'])
        self.service = self.service_v4  # protected pending authority only
        self.service_v2 = self.service_v3 = None
        self.issuer_service = self._evidence_service(collector, app_compose)

    def request(self, request):
        if (type(request) is not dict or request.get('kind') not in
                ('dispatch_v4', 'issuer_dispatch', 'provision_v4', 'pending_v4')
                or datetime.now(timezone.utc) >= expiry(self.approved['expires_at'])):
            raise RedemptionError('staging route not approved')
        return super().request(request)

    def ready(self):
        sponsor = next((peer for peer, principal in self.peers.items()
            if principal.subject == self.service.sponsor and 'sponsor' in principal.roles), None)
        if sponsor is None:
            raise RedemptionError('signed sponsor mapping required')
        return {'ready': True, 'environment': 'debug-staging', 'noise_seed_hex': self.noise_seed.hex(),
                'issuer_peer_id': self.issuer_peer, 'sponsor_peer': sponsor,
                'approval_sha256': payload_hash(self.approval_domain, self.approved)}

    def close(self):
        if getattr(self, 'service_v4', None) is not None:
            self.service_v4.close_jobs()
        super().close()
