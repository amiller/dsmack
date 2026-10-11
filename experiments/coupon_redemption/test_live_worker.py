"""LiveWorker boundary tests over the explicit synthetic fixture.

The positive test is the first full startup of the signed staging worker:
measured-root admission, genuine-SDK-shaped identity, signed provider account,
guarded async /4 claim and delivery. All refusals are asserted to happen
before provider credentials are constructed, and no test here can reach
hardware, a provider or a chain.
"""
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .live_worker import LiveWorker
from .offer_v4 import PROTOCOL_V4, delivery_aad_v4
from .spike import Store, RedemptionError, decrypt_secret
from .staging_approval import APPROVAL_DOMAIN, payload_hash
from .test_live_fixture import (APP_ID, COMPOSE_HASH, GATE_NAME, ISSUER_SEED, NOISE_SEED,
                                PROVIDER, approval_payload, install, write_envelopes)

SPONSOR = 'SponsorPeer0000001'
OBSERVER = 'ObserverPeer0001'
ISSUER = 'IssuerPeer00000001'
CLAIMANT = 'ClaimantPeer000001'


class LiveWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.restore = install()
        self.addCleanup(self.restore)
        self.info = write_envelopes(self.root)
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def worker(self, config=None):
        return LiveWorker(config or self.info['config'])

    def provision(self, worker, budget='1000000000', expiry_at='2099-01-01T00:00:00Z'):
        return worker.request({'seq': 1, 'kind': 'provision_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': budget,
            'claim_expires_at': expiry_at})

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

    def test_first_full_startup_async_claim_and_delivery(self):
        worker = self.worker()
        self.addCleanup(worker.close)
        ready = worker.ready()
        self.assertEqual(ready, {'ready': True, 'environment': 'debug-staging',
            'noise_seed_hex': NOISE_SEED.hex(), 'issuer_peer_id': ISSUER,
            'sponsor_peer': SPONSOR, 'approval_sha256': payload_hash(
                APPROVAL_DOMAIN, approval_payload())})
        # Credentials come only from the signed configuration, after every
        # signature, measurement and state check has passed.
        self.assertEqual(len(worker.service_v4.jobs), 0)
        bundle = self.provision(worker)
        issuer_public = hashlib.sha256(worker.service_v4.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
        self.assertEqual(bundle['offer']['issuer'], {'peer_id': ISSUER,
            'policy': 'dstack-tdx-coupon-v1', 'identity_policy_sha256': '02' * 32,
            'issuance_policy_sha256': '03' * 32,
            'issuer_public_key_sha256': issuer_public})
        self.assertEqual(bundle['offer']['provider'], {'id': 'near',
            'scope_commitment': approval_payload()['provider_scope_commitment']})
        self.assertFalse(bundle['deposit_release_authorized'])
        claim = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))
        self.assertEqual(claim, {'id': 'c1', 'ok': True, 'result': {
            'state': 'in_progress', 'automatic_retry_allowed': False,
            'deposit_release_authorized': False}})
        delivered = self.wait_for(worker, bundle, 'delivered')
        key_id = delivered['result']['key_id']
        self.assertTrue(key_id.startswith('synthetic-live-'))
        # The winner's replay claim is the only effect-free completion that
        # returns the encrypted delivery envelope.
        replay = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle, 'c2'))
        self.assertTrue(replay['ok'])
        self.assertEqual(replay['result']['key_id'], key_id)
        aad = delivery_aad_v4(Store.digest(bundle['coupon']), key_id, self.public,
                              bundle['offer_hash'], CLAIMANT)
        self.assertEqual(decrypt_secret(replay['result']['envelope'], self.private, aad),
                         'synthetic-live-secret')
        # A different peer or key can learn nothing.
        self.assertFalse(self.dispatch(worker, 'ClaimantPeer000002', self.claim_frame(bundle, 'c3'))['ok'])
        self.assertFalse(self.dispatch(worker, 'ClaimantPeer000002', self.status_frame(bundle, 's2'))['ok'])
        observation = self.dispatch(worker, OBSERVER, {'id': 'o1', 'op': 'observe',
            'coupon': bundle['coupon'], 'start': '2026-10-10T00:00:00Z',
            'end': '2026-10-11T00:00:00Z', 'challenge': 'ab' * 32})
        self.assertTrue(observation['ok'])
        self.assertEqual(observation['result']['payload']['environment'],
                         'debug-staging-operator-readable')
        self.assertEqual(observation['result']['payload']['version'], 4)

    def test_signed_measurement_or_account_mismatch_stops_before_credentials(self):
        cases = {
            'app': {'approval_overrides': {'app_id': 'ff' * 20}},
            'compose': {'approval_overrides': {'compose_hash': '02' * 32}},
            'issuer key': {'approval_overrides': {'issuer_public_key_sha256': 'ff' * 32}},
            'expired approval': {'approval_overrides': {'expires_at': '2000-01-01T00:00:00Z'}},
            'substituted provider account': {'config_overrides': {'provider': {
                **PROVIDER, 'organization_id': '33333333-3333-4333-8333-333333333333'}}},
            # Review F2: malformed-but-signed state_dir/issuer_peer_id must be
            # refused inside configuration() — never a naked TypeError at
            # Path() nor sqlite3.ProgrammingError at the identity INSERT.
            'state_dir type': {'config_overrides': {'state_dir': 123}},
            'issuer_peer_id type': {'issuer_peer_id': ['IssuerPeer00000001']},
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                self.info = write_envelopes(self.root, expect_valid=False, **overrides)
                with self.assertRaises(RedemptionError):
                    LiveWorker(self.info['config'])
                self.assertEqual(len(_near_constructions()), 0,
                                 'credentials must not be constructed before all checks')
                self.assertFalse((self.root / 'state').exists(),
                                 'no durable state may be created before all checks')
        # The same files under the wrong measured root are refused identically.
        import experiments.coupon_redemption.live_worker as live_worker
        original = live_worker.approval_root
        live_worker.approval_root = lambda: bytes(32)
        try:
            with self.assertRaises(RedemptionError):
                LiveWorker(self.info['config'])
        finally:
            live_worker.approval_root = original

    def test_persisted_staging_caps_are_atomic_and_migration_is_explicit(self):
        worker = self.worker()
        self.provision(worker, '3000000000')
        # Per-coupon and aggregate caps are enforced by the durable SQL trigger;
        # the raw abort is the fail-closed mechanism under any connection.
        with self.assertRaises(sqlite3.IntegrityError):
            self.provision(worker, '6000000000')
        with self.assertRaises(sqlite3.IntegrityError):
            self.provision(worker, '3000000000')
        self.assertEqual(worker.store.db.execute('SELECT count(*) FROM coupons').fetchone()[0], 1)
        # The trigger binds any independent connection to the same state file.
        other = Store(self.root / 'state' / 'state.sqlite')
        with self.assertRaises(sqlite3.IntegrityError):
            other.db.execute("INSERT INTO coupons(digest,budget,state) VALUES ('aa',6000000000,'ready')")
        other.close()
        worker.close()
        # A re-signed budget is never a silent migration: persisted caps that
        # differ from the signed approval refuse startup before credentials.
        connection = sqlite3.connect(self.root / 'state' / 'state.sqlite')
        connection.execute('UPDATE staging_caps SET total=9000000000 WHERE singleton=1')
        connection.commit()
        connection.close()
        with self.assertRaises(RedemptionError) as failure:
            LiveWorker(self.info['config'])
        self.assertIn('migration', str(failure.exception))
        self.assertEqual(len(_near_constructions()), 1)

    def test_only_signed_staging_routes_are_accepted(self):
        worker = self.worker()
        self.addCleanup(worker.close)
        bundle = self.provision(worker)
        frame = base64.b64encode(json.dumps(self.status_frame(bundle)).encode()).decode()
        legacy = [
            {'seq': 3, 'kind': 'dispatch', 'peer': SPONSOR, 'frame': frame},
            {'seq': 3, 'kind': 'provision', 'peer': SPONSOR, 'budget': 1, 'recipient_peer': CLAIMANT},
            {'seq': 3, 'kind': 'pending', 'peer': SPONSOR},
            {'seq': 3, 'kind': 'dispatch_v2', 'peer': SPONSOR, 'protocol': '/dsmack/coupon/2',
             'local_peer': ISSUER, 'frame': frame},
            {'seq': 3, 'kind': 'provision_v3', 'peer': SPONSOR, 'protocol': '/dsmack/coupon/3',
             'local_peer': ISSUER, 'budget': '1', 'claim_expires_at': '2099-01-01T00:00:00Z'},
            {'seq': 3, 'kind': 'pending_v3', 'peer': SPONSOR, 'protocol': '/dsmack/coupon/3',
             'local_peer': ISSUER},
            {'seq': 3, 'kind': 'unexpected', 'peer': SPONSOR},
        ]
        for request in legacy:
            with self.subTest(kind=request['kind']):
                with self.assertRaises(RedemptionError):
                    worker.request(request)
        # The four signed staging kinds keep working through the same boundary.
        self.assertTrue(self.dispatch(worker, CLAIMANT, self.status_frame(bundle))['ok'])
        pending = worker.request({'seq': 4, 'kind': 'pending_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER})
        self.assertEqual(pending, {'pending': [], 'automatic_retry_allowed': False})

    def test_malformed_status_stays_generic_and_preserves_only_valid_ids(self):
        worker = self.worker()
        self.addCleanup(worker.close)
        bundle = self.provision(worker)
        (self.root / 'state' / GATE_NAME).write_text('hold')
        self.assertEqual(self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))['result']['state'],
                         'in_progress')
        # Once issuance is in flight, an uncommitted status is refused exactly
        # like an unknown coupon: no enumeration of account or state.
        known = json.dumps({'id': 'x1', 'op': 'status', 'coupon': bundle['coupon']}).encode()
        unknown = json.dumps({'id': 'x1', 'op': 'status', 'coupon': 'A' * 43}).encode()
        self.assertEqual(self.dispatch(worker, CLAIMANT, known),
                         self.dispatch(worker, CLAIMANT, unknown))
        self.assertEqual(self.dispatch(worker, CLAIMANT, known),
                         {'id': 'x1', 'ok': False, 'error': 'request_failed'})
        # A syntactically valid request id survives correlation when the async
        # status commitment handling itself fails; unparseable frames keep the
        # base service's null id, and nothing enumerates account or state.
        wrong_commitments = json.dumps({'id': 'k1', 'op': 'status',
            'coupon': bundle['coupon'], 'recipient_key': '!!!not-base64!!!',
            'offer_hash': bundle['offer_hash']}).encode()
        self.assertEqual(self.dispatch(worker, CLAIMANT, wrong_commitments),
                         {'id': 'k1', 'ok': False, 'error': 'request_failed'})
        truncated = b'{"id":"bad1","op":"status"'
        self.assertEqual(self.dispatch(worker, CLAIMANT, truncated),
                         {'id': None, 'ok': False, 'error': 'request_failed'})
        invalid_id = b'{"id":"not a valid id!","op":"status"}'
        self.assertEqual(self.dispatch(worker, CLAIMANT, invalid_id),
                         {'id': None, 'ok': False, 'error': 'request_failed'})
        garbage = b'\x00\xff not json'
        self.assertEqual(self.dispatch(worker, CLAIMANT, garbage),
                         {'id': None, 'ok': False, 'error': 'request_failed'})

    def test_shutdown_terminates_held_job_and_restart_requires_reconciliation(self):
        worker = self.worker()
        bundle = self.provision(worker)
        gate = self.root / 'state' / GATE_NAME
        gate.write_text('hold')
        claim = self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))
        self.assertEqual(claim['result']['state'], 'in_progress')
        self.wait_for(worker, bundle, 'in_progress')
        child = next(iter(worker.service_v4.jobs.values()))
        worker.close()
        deadline = time.monotonic() + 5
        while Path(f'/proc/{child.pid}').exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(Path(f'/proc/{child.pid}').exists(), 'held job must be terminated')
        # Restarting on the same state cannot resume the interrupted effect.
        restarted = self.worker()
        self.addCleanup(restarted.close)
        status = self.dispatch(restarted, CLAIMANT, self.status_frame(bundle))
        self.assertEqual(status['result']['state'], 'reconciliation_required')
        self.assertFalse(status['result']['automatic_retry_allowed'])
        self.assertFalse(self.dispatch(restarted, CLAIMANT, self.claim_frame(bundle, 'c9'))['ok'])
        pending = restarted.request({'seq': 5, 'kind': 'pending_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER})
        # Graceful shutdown lets the interrupted job record its own quarantine;
        # the hard-kill path in the bridge tests leaves the durable 'issuing'.
        self.assertEqual(pending['pending'], [{'digest': Store.digest(bundle['coupon']),
                                               'state': 'quarantined'}])
        self.assertEqual(len(restarted.service_v4.jobs), 0)

    def test_guard_crash_after_intent_never_auto_retries(self):
        worker = self.worker()
        self.addCleanup(worker.close)
        bundle = self.provision(worker)
        (self.root / 'state' / GATE_NAME).write_text('crash')
        self.assertEqual(self.dispatch(worker, CLAIMANT, self.claim_frame(bundle))['result']['state'],
                         'in_progress')
        deadline = time.monotonic() + 5
        while worker.service_v4.jobs and time.monotonic() < deadline:
            time.sleep(0.02)
        status = self.dispatch(worker, CLAIMANT, self.status_frame(bundle))
        self.assertEqual(status['result']['state'], 'reconciliation_required')


def _near_constructions():
    from .test_live_fixture import FakeNear
    return FakeNear.constructed


class BridgeLifecycleTests(unittest.TestCase):
    """The packaged bridge protocol over a real fixture worker subprocess."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.info = write_envelopes(self.root)

    def spawn(self):
        process = subprocess.Popen([sys.executable, '-m',
            'experiments.coupon_redemption.test_live_fixture', 'worker',
            '--config', self.info['config']], cwd=Path(__file__).resolve().parents[2],
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
        self.assertEqual(ready['environment'], 'debug-staging')
        return process

    def call(self, process, request, timeout=15):
        process.stdin.write(json.dumps(request).encode() + b'\n')
        process.stdin.flush()
        line = process.stdout.readline()
        self.assertTrue(line, 'worker exited or closed the bridge')
        response = json.loads(line)
        self.assertEqual(response['seq'], request['seq'])
        return response

    def dispatch(self, process, peer, frame, seq):
        encoded = frame if isinstance(frame, bytes) else json.dumps(frame).encode()
        response = self.call(process, {'seq': seq, 'kind': 'dispatch_v4', 'peer': peer,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER,
            'frame': base64.b64encode(encoded).decode()}, timeout=30)
        return json.loads(base64.b64decode(response['result']['frame'])) if response['ok'] else response

    def lingering(self):
        """Processes whose command line still references this operator config."""
        marker = str(self.info['config']).encode()
        found = []
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                with open(f'/proc/{entry}/cmdline', 'rb') as file:
                    if marker in file.read():
                        found.append(int(entry))
            except OSError:
                continue
        return found

    def wait_until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.02)
        self.fail('bridge lifecycle deadline')

    def test_bridge_worker_group_cleanup_and_durable_restart_state(self):
        process = self.spawn()
        bundle = self.call(process, {'seq': 1, 'kind': 'provision_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': '4000000000',
            'claim_expires_at': '2099-01-01T00:00:00Z'})['result']
        (self.root / 'state' / GATE_NAME).write_text('hold')
        self.assertEqual(self.dispatch(process, CLAIMANT, {'id': 'c1', 'op': 'claim',
            'coupon': bundle['coupon'], 'recipient_key': base64.b64encode(bytes(range(32))).decode(),
            'offer_hash': bundle['offer_hash']}, 2)['result']['state'], 'in_progress')
        # The whole process group (worker plus its forked issuance job) exists
        # while a job is held, and every member is gone after a hard kill.
        self.wait_until(lambda: len(self.lingering()) >= 2)
        os.killpg(process.pid, 9)
        process.wait(timeout=10)
        self.wait_until(lambda: not self.lingering())
        # A fresh worker on the same signed state reports the interrupted job
        # and keeps enforcing the persisted aggregate cap.
        restarted = self.spawn()
        try:
            status = self.dispatch(restarted, CLAIMANT, {'id': 's1', 'op': 'status',
                'coupon': bundle['coupon'],
                'recipient_key': base64.b64encode(bytes(range(32))).decode(),
                'offer_hash': bundle['offer_hash']}, 3)
            self.assertEqual(status['result']['state'], 'reconciliation_required')
            pending = self.call(restarted, {'seq': 4, 'kind': 'pending_v4', 'peer': SPONSOR,
                'protocol': PROTOCOL_V4, 'local_peer': ISSUER})
            self.assertEqual(pending['result']['pending'][0]['state'], 'issuing')
            refused = self.call(restarted, {'seq': 5, 'kind': 'provision_v4', 'peer': SPONSOR,
                'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': '2000000000',
                'claim_expires_at': '2099-01-01T00:00:00Z'})
            self.assertFalse(refused['ok'])
            granted = self.call(restarted, {'seq': 6, 'kind': 'provision_v4', 'peer': SPONSOR,
                'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': '1000000000',
                'claim_expires_at': '2099-01-01T00:00:00Z'})
            self.assertTrue(granted['ok'])
        finally:
            restarted.stdin.close()
            self.assertEqual(restarted.wait(timeout=15), 0)
            self.wait_until(lambda: not self.lingering())

    def test_graceful_eof_close_terminates_a_held_job(self):
        process = self.spawn()
        bundle = self.call(process, {'seq': 1, 'kind': 'provision_v4', 'peer': SPONSOR,
            'protocol': PROTOCOL_V4, 'local_peer': ISSUER, 'budget': '1000000000',
            'claim_expires_at': '2099-01-01T00:00:00Z'})['result']
        (self.root / 'state' / GATE_NAME).write_text('hold')
        self.assertEqual(self.dispatch(process, CLAIMANT, {'id': 'c1', 'op': 'claim',
            'coupon': bundle['coupon'], 'recipient_key': base64.b64encode(bytes(range(32))).decode(),
            'offer_hash': bundle['offer_hash']}, 2)['result']['state'], 'in_progress')
        self.wait_until(lambda: len(self.lingering()) >= 2)
        process.stdin.close()  # Operator pipe EOF is the documented shutdown.
        self.assertEqual(process.wait(timeout=15), 0)
        self.wait_until(lambda: not self.lingering())


class ApprovalRootTests(unittest.TestCase):
    def test_shipped_null_root_refuses_with_the_named_error(self):
        # The default image ships {"public_key_hex":null}: the hex regex must
        # never see a non-string member (review L1 — previously a TypeError
        # escaped before the intended RedemptionError).
        import experiments.coupon_redemption.live_worker as live_worker
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'packaging' / 'coupon').mkdir(parents=True)
            shipped = root / 'packaging' / 'coupon' / 'approval-root.json'
            shipped.write_bytes(b'{"public_key_hex":null}\n')
            shipped.chmod(0o644)  # passes the stat gate so the null key is reached
            original = live_worker.__file__
            live_worker.__file__ = str(root / 'experiments' / 'coupon_redemption' / 'live_worker.py')
            try:
                with self.assertRaises(RedemptionError) as raised:
                    live_worker.approval_root()
                self.assertEqual(str(raised.exception), 'measured approval root unavailable')
            finally:
                live_worker.__file__ = original


if __name__ == '__main__':
    unittest.main()
