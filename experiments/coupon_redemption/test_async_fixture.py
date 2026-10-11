"""EXPLICIT SYNTHETIC ASYNC /4 FIXTURE for client-lane interop. Never packaged.

The existing synthetic /4 profile stays synchronous. This wrapper swaps the
signed synthetic worker's v4 service for the real AsyncCouponServiceV4 with a
gate-file issuance authorizer, so a client can exercise actual
encrypted-peer cancellation and reconciliation behavior: an accepted claim
returns `in_progress`, polling must not create a provider key, a crash after
the durable intent requires reconciliation, and restart never auto-retries.

Mount it exactly like the issuer fixture the client already uses:

    #!/usr/bin/env python3
    import sys, os
    sys.path.insert(0, os.getcwd())
    from experiments.coupon_redemption import peer_worker
    from experiments.coupon_redemption.test_async_fixture import async_fixture_worker
    peer_worker.Worker = async_fixture_worker
    raise SystemExit(peer_worker.main(sys.argv[3:]))

passed as `python` to createCouponPeerService, or as `workerExecutable` to
startCouponNode, with a synthetic config that includes the same
`issuer_evidence` section as test_issuer_fixture (which this module reuses).

The gate file lives at `<state_dir>/async-issuance-gate` and selects the
authorization outcome per attempt: absent or "grant" delivers, "hold" leaves
the job in progress, "fail" refuses, "crash" exits after the durable intent.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .async_service_v4 import AsyncCouponServiceV4, PENDING
from .dstack_issuer_identity import DstackIssuerIdentity
from .offer_v4 import PROTOCOL_V4, delivery_aad_v4
from .peer_worker import Worker as RealWorker, _private_file
from .spike import IssuedKey, RedemptionError, Store, decrypt_secret
from .test_issuer_fixture import (COMPOSE, IDENTITY_POLICY_HASH, ISSUANCE_POLICY_HASH,
                                  SyntheticGuest)
from .test_live_fixture import GATE_NAME, await_gate

MAX_ACTIVE_JOBS = 2
JOB_DEADLINE_SECONDS = 120
EFFECT_LOG_NAME = 'async-provider-effects'


class AsyncFileProvider:
    """Fork-child-safe synthetic provider.

    The async service's forked job closes the inherited store connection, so a
    provider that shares the worker's Store (like SyntheticProvider) breaks in
    the child. This double logs each provider effect to an append-only file
    instead: the client lane counts its lines to prove that polling never
    causes provider-key creation.
    """

    def __init__(self, path):
        self.path = Path(path)

    def create_key(self, name, budget):
        with self.path.open('a') as output:
            output.write('create\n')
            output.flush()
            os.fsync(output.fileno())
        return IssuedKey('synthetic-async-' + name.split('-')[-1][:16], 'synthetic-async-secret')

    def usage_rows(self, key_id, start, end):
        return [{'source': 'inference', 'id': 'synthetic-async-row', 'api_key_id': key_id,
                 'total_cost_nano_usd': 5_000_000_000}]


class AsyncFixtureWorker(RealWorker):
    """Synthetic worker whose v4 route is the real bounded async service."""

    def __init__(self, config_path, *, effect_log, **kwargs):
        self.effect_log = effect_log
        super().__init__(config_path, **kwargs)

    def _initialize(self, config_path):
        super()._initialize(config_path)  # Synthetic profile, issuer evidence, store.
        sync = self.service_v4
        self.service_v4 = AsyncCouponServiceV4(sync.store, AsyncFileProvider(self.effect_log),
            sync.signing_key, sponsor_subject=sync.sponsor, observer_subject=sync.observer,
            issuer_peer_id=sync.issuer_peer, provider_binding={'mode': 'synthetic'},
            issuer_binding=sync.issuer_binding, issuance_authorizer=self.issuance_authorizer,
            max_active_jobs=MAX_ACTIVE_JOBS, job_deadline_seconds=JOB_DEADLINE_SECONDS)

    def close(self):
        service = getattr(self, 'service_v4', None)
        if isinstance(service, AsyncCouponServiceV4):
            service.close_jobs()
        super().close()


def async_fixture_worker(config_path):
    """Validating factory compatible with `peer_worker.Worker = ...` patching."""
    config = json.loads(_private_file(config_path))
    profile = config.get('issuer_evidence')
    if (config['provider'] != {'mode': 'synthetic'} or profile is None
            or profile['identity_policy_sha256'] != IDENTITY_POLICY_HASH
            or profile['issuance_policy_sha256'] != ISSUANCE_POLICY_HASH
            or _private_file(profile['compose_file']).decode() != COMPOSE):
        raise RedemptionError('synthetic async fixture profile required')
    state = Path(config['state_dir'])
    gate = state / GATE_NAME

    def authorize(_digest, _peer, _public, _accepted_hash, binding):
        if binding['issuance_policy_sha256'] != ISSUANCE_POLICY_HASH:
            raise RedemptionError('synthetic fixture cannot authorize near credentials')
        await_gate(gate)

    return AsyncFixtureWorker(config_path, effect_log=state / EFFECT_LOG_NAME,
        issuer_collector_factory=lambda socket_path, signing_key: DstackIssuerIdentity(
            SyntheticGuest(), signing_key),
        issuance_authorizer=authorize)


def main(argv=None):
    """Standalone bridge worker with peer_worker's exact line protocol."""
    from .peer_worker import main as peer_main
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['-m'] and len(argv) >= 2:
        # Invoked through a launcher that forwards the fixed peer_worker shape.
        if argv[1] != 'experiments.coupon_redemption.peer_worker':
            raise SystemExit('unsupported worker invocation')
        argv = argv[2:]
    if not argv or argv[0] != '--config' or len(argv) != 2:
        raise SystemExit('usage: --config PATH (directly or behind a peer_worker launcher)')
    import experiments.coupon_redemption.peer_worker as peer_worker
    peer_worker.Worker = async_fixture_worker
    return peer_main(argv)


def synthetic_config(root):
    """A synthetic worker config carrying the issuer-evidence section the
    client lane appends to initializeSynthetic output."""
    root = Path(root)
    compose = root / 'compose.json'
    compose.write_text(COMPOSE)
    compose.chmod(0o600)
    config = {'version': 1, 'state_dir': str(root / 'state'), 'issuer_peer_id': ISSUER,
        'sponsor_subject': 'dev:sponsor', 'observer_subject': 'dev:observer',
        'peers': {SPONSOR: {'subject': 'dev:sponsor', 'roles': ['sponsor']},
                  OBSERVER: {'subject': 'dev:observer', 'roles': ['observer']}},
        'provider': {'mode': 'synthetic'},
        'issuer_evidence': {'identity_policy_sha256': IDENTITY_POLICY_HASH,
            'issuance_policy_sha256': ISSUANCE_POLICY_HASH,
            'socket_path': '/synthetic/test-only.sock', 'compose_file': str(compose)}}
    path = root / 'config.json'
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    return path


ISSUER = 'IssuerPeer00000001'
SPONSOR = 'SponsorPeer0000001'
OBSERVER = 'ObserverPeer0001'
CLAIMANT = 'ClaimantPeer000001'


class AsyncInteropTests(unittest.TestCase):
    """Client-lane /4 behavior: bounded in-progress claims, effect-free polling,
    explicit reconciliation. Every path here is synthetic; no hardware,
    provider or chain is reachable."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.config = synthetic_config(self.root)
        state = self.root / 'state'
        self.gate = state / GATE_NAME
        self.effects = state / EFFECT_LOG_NAME
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def worker(self):
        worker = async_fixture_worker(self.config)
        self.addCleanup(worker.close)
        return worker

    def provision(self, worker, budget='1000000000', expiry='2099-01-01T00:00:00Z'):
        return worker.request({'seq': 1, 'kind': 'provision_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': budget,
            'claim_expires_at': expiry})

    def dispatch(self, worker, peer, frame):
        encoded = frame if isinstance(frame, bytes) else json.dumps(frame).encode()
        response = worker.request({'seq': 2, 'kind': 'dispatch_v4', 'peer': peer,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
            'frame': base64.b64encode(encoded).decode()})
        return json.loads(base64.b64decode(response['frame']))

    def claim_frame(self, bundle, identifier='c1'):
        return {'id': identifier, 'op': 'claim', 'coupon': bundle['coupon'],
                'recipient_key': base64.b64encode(self.public).decode(),
                'offer_hash': bundle['offer_hash']}

    def status_frame(self, bundle, identifier='s1'):
        return {'id': identifier, 'op': 'status', 'coupon': bundle['coupon'],
                'recipient_key': base64.b64encode(self.public).decode(),
                'offer_hash': bundle['offer_hash']}

    def wait_for(self, worker, bundle, state):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = self.dispatch(worker, CLAIMANT, self.status_frame(bundle))
            if result['ok'] and result['result'].get('state') == state:
                return result
            time.sleep(0.02)
        self.fail(f'state transition deadline: {state}')

    def effect_count(self):
        return len(self.effects.read_text().splitlines()) if self.effects.exists() else 0

    def test_in_progress_claim_and_effect_free_polling(self):
        worker = self.worker()
        bundle = self.provision(worker)
        self.gate.write_text('hold')
        claim = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))
        self.assertEqual(claim, {'id': 'c1', 'ok': True, 'result': dict(PENDING)})
        # Repeated status polling never creates a provider key and never
        # re-enters issuance; the single held job is the only activity.
        for _ in range(5):
            status = self.dispatch(worker, CLAIMANT, self.status_frame(bundle))
            self.assertTrue(status['ok'])
            self.assertEqual(status['result']['state'], 'in_progress')
            time.sleep(0.02)
        self.assertEqual(self.effect_count(), 0)
        self.assertEqual(len(worker.service_v4.jobs), 1)
        # A different peer or key learns nothing about the in-flight claim.
        self.assertFalse(self.dispatch(worker, 'ClaimantPeer000002',
            self.status_frame(bundle))['ok'])

    def test_grant_delivers_exactly_once_and_replay_creates_nothing(self):
        worker = self.worker()
        bundle = self.provision(worker)
        self.gate.write_text('hold')
        self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))
        self.wait_for(worker, bundle, 'in_progress')
        self.gate.write_text('grant')
        delivered = self.wait_for(worker, bundle, 'delivered')
        key_id = delivered['result']['key_id']
        self.assertTrue(key_id.startswith('synthetic-async-'))
        self.assertEqual(self.effect_count(), 1, 'exactly one provider key per coupon')
        # The winner's replay claim is the only effect-free completion that
        # returns the encrypted delivery envelope.
        replay = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle, 'c2'))
        self.assertTrue(replay['ok'])
        self.assertEqual(replay['result']['key_id'], key_id)
        aad = delivery_aad_v4(Store.digest(bundle['coupon']), key_id, self.public,
                              bundle['offer_hash'], CLAIMANT)
        self.assertEqual(decrypt_secret(replay['result']['envelope'], self.private, aad),
                         'synthetic-async-secret')
        self.assertEqual(self.effect_count(), 1, 'replay must not create provider keys')
        # A non-winner still cannot complete the claim after delivery.
        self.assertFalse(self.dispatch(worker, 'ClaimantPeer000002',
            self.claim_frame(bundle, 'c3'))['ok'])

    def test_refusal_or_crash_after_intent_requires_reconciliation(self):
        for mode in ('fail', 'crash'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.chmod(root, 0o700)
                config = synthetic_config(root)
                worker = async_fixture_worker(config)
                try:
                    bundle = worker.request({'seq': 1, 'kind': 'provision_v4',
                        'peer': SPONSOR, 'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
                        'budget': '1000000000', 'claim_expires_at': '2099-01-01T00:00:00Z'})
                    (root / 'state' / GATE_NAME).write_text(mode)
                    frame = {'id': 'c1', 'op': 'claim', 'coupon': bundle['coupon'],
                             'recipient_key': base64.b64encode(self.public).decode(),
                             'offer_hash': bundle['offer_hash']}
                    response = worker.request({'seq': 2, 'kind': 'dispatch_v4',
                        'peer': CLAIMANT, 'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
                        'frame': base64.b64encode(json.dumps(frame).encode()).decode()})
                    result = json.loads(base64.b64decode(response['frame']))
                    self.assertEqual(result['result']['state'], 'in_progress')
                    deadline = time.monotonic() + 10
                    while worker.service_v4.jobs and time.monotonic() < deadline:
                        time.sleep(0.02)
                    status = {'id': 's1', 'op': 'status', 'coupon': bundle['coupon'],
                              'recipient_key': base64.b64encode(self.public).decode(),
                              'offer_hash': bundle['offer_hash']}
                    response = worker.request({'seq': 3, 'kind': 'dispatch_v4',
                        'peer': CLAIMANT, 'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
                        'frame': base64.b64encode(json.dumps(status).encode()).decode()})
                    result = json.loads(base64.b64decode(response['frame']))
                    self.assertEqual(result['result']['state'], 'reconciliation_required')
                    self.assertFalse(result['result']['automatic_retry_allowed'])
                    # No provider key was created and a new claim is refused.
                    self.assertFalse((root / 'state' / EFFECT_LOG_NAME).exists())
                    response = worker.request({'seq': 4, 'kind': 'dispatch_v4',
                        'peer': CLAIMANT, 'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
                        'frame': base64.b64encode(json.dumps({**frame, 'id': 'c2'}).encode()).decode()})
                    self.assertFalse(json.loads(base64.b64decode(response['frame']))['ok'])
                finally:
                    worker.close()

    def test_concurrent_issuance_is_bounded_by_the_job_cap(self):
        worker = self.worker()
        bundles = [self.provision(worker) for _ in range(3)]
        self.gate.write_text('hold')
        for index, bundle in enumerate(bundles[:MAX_ACTIVE_JOBS]):
            claim = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle, f'c{index}'))
            self.assertEqual(claim['result']['state'], 'in_progress')
        refused = self.dispatch(worker, CLAIMANT, self.claim_frame(bundles[2], 'c2x'))
        self.assertFalse(refused['ok'])
        self.assertEqual(self.effect_count(), 0)


class AsyncBridgeTests(unittest.TestCase):
    """The launcher-shaped bridge protocol over the async fixture worker."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.config = synthetic_config(self.root)
        self.gate = self.root / 'state' / GATE_NAME

    def spawn(self):
        process = subprocess.Popen([sys.executable,
            '-m', 'experiments.coupon_redemption.test_async_fixture',
            '-m', 'experiments.coupon_redemption.peer_worker',
            '--config', str(self.config)], cwd=Path(__file__).resolve().parents[2],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True)

        def reap():
            try:
                os.killpg(process.pid, 9)
            except OSError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass
        self.addCleanup(reap)
        ready = json.loads(process.stdout.readline())
        self.assertTrue(ready['ready'])
        self.assertEqual(ready['environment'], 'local-unattested')
        return process

    def call(self, process, request):
        process.stdin.write(json.dumps(request).encode() + b'\n')
        process.stdin.flush()
        line = process.stdout.readline()
        self.assertTrue(line, 'worker exited or closed the bridge')
        response = json.loads(line)
        self.assertEqual(response['seq'], request['seq'])
        return response

    def dispatch(self, process, frame, seq, peer=CLAIMANT):
        response = self.call(process, {'seq': seq, 'kind': 'dispatch_v4', 'peer': peer,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
            'frame': base64.b64encode(json.dumps(frame).encode()).decode()})
        return json.loads(base64.b64decode(response['result']['frame'])) if response['ok'] else response

    def test_eof_close_and_restart_never_auto_retries_the_interrupted_job(self):
        process = self.spawn()
        bundle = self.call(process, {'seq': 1, 'kind': 'provision_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': '1000000000',
            'claim_expires_at': '2099-01-01T00:00:00Z'})['result']
        self.gate.write_text('hold')
        public = base64.b64encode(bytes(range(32))).decode()
        self.assertEqual(self.dispatch(process, {'id': 'c1', 'op': 'claim',
            'coupon': bundle['coupon'], 'recipient_key': public,
            'offer_hash': bundle['offer_hash']}, 2)['result']['state'], 'in_progress')
        process.stdin.close()  # Operator pipe EOF is the documented shutdown.
        self.assertEqual(process.wait(timeout=15), 0)
        # Restart on the same synthetic state: the interrupted job requires
        # explicit reconciliation and a now-granting gate must not resume it.
        restarted = self.spawn()
        try:
            status = self.dispatch(restarted, {'id': 's1', 'op': 'status',
                'coupon': bundle['coupon'], 'recipient_key': public,
                'offer_hash': bundle['offer_hash']}, 3)
            self.assertEqual(status['result']['state'], 'reconciliation_required')
            pending = self.call(restarted, {'seq': 4, 'kind': 'pending_v4', 'peer': SPONSOR,
                'protocol': PROTOCOL_V4, 'local_peer': ISSUER})
            self.assertEqual(pending['result']['pending'],
                [{'digest': Store.digest(bundle['coupon']), 'state': 'quarantined'}])
            self.gate.write_text('grant')
            time.sleep(0.3)
            self.assertFalse((self.root / 'state' / EFFECT_LOG_NAME).exists(),
                             'restart must never auto-retry issuance')
            replay = self.dispatch(restarted, {'id': 'c2', 'op': 'claim',
                'coupon': bundle['coupon'], 'recipient_key': public,
                'offer_hash': bundle['offer_hash']}, 5)
            self.assertFalse(replay['ok'])
        finally:
            restarted.stdin.close()
            self.assertEqual(restarted.wait(timeout=15), 0)


if __name__ == '__main__':
    raise SystemExit(main())
