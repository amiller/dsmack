"""Public read transport failures never replay a transaction or provider POST."""
import itertools
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from .issuance_guard import GuardRPC, GuardReadUnavailable
from .spike import Store, IssuedKey, RedemptionError
from .test_base_guard import BaseGuardTests
from . import test_async_service_v4 as async_fixture


class Response:
    status = 200
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *_args): pass
    def read(self, limit): return self.data[:limit]


class ResponseEvidenceTests(unittest.TestCase):
    def test_decode_retry_is_at_most_two_then_terminal(self):
        rpc = GuardRPC('https://example.invalid')
        with patch.object(rpc.opener, 'open', return_value=Response(b'<html>')) as opener:
            for _ in range(2):
                with self.assertRaises(GuardReadUnavailable): rpc.call('eth_getBlockByNumber', ['safe', False])
            with self.assertRaises(RedemptionError) as raised: rpc.call('eth_getBlockByNumber', ['safe', False])
            self.assertNotIsInstance(raised.exception, GuardReadUnavailable)
            self.assertEqual(opener.call_count, 3)

    def test_failure_categories_and_evidence_do_not_retain_body_or_parameters(self):
        cases = [(b'PRIVATE_BODY_CANARY', 'response_decode', True),
            (b'x'*65537, 'response_oversized', False),
            (b'{"jsonrpc":"2.0","id":2,"result":null}', 'response_envelope', False),
            (b'{"jsonrpc":"2.0","id":1,"error":{"code":-32011,"message":"PRIVATE_BODY_CANARY"}}', 'rpc_error', False),
            (b'{"jsonrpc":"2.0","id":1,"id":1,"result":null}', 'response_envelope', False)]
        for method in ('eth_getBlockByNumber', 'eth_sendRawTransaction'):
            for body, category, transient in cases:
                with self.subTest(method=method, category=category):
                    rpc = GuardRPC('https://example.invalid'); evidence = []
                    rpc.diagnostic_observer = evidence.append
                    with patch.object(rpc.opener, 'open', return_value=Response(body)) as opener:
                        with self.assertRaises(RedemptionError) as raised:
                            rpc.call(method, ['PRIVATE_PARAMETER_CANARY'])
                    self.assertEqual(opener.call_count, 1)
                    self.assertEqual(isinstance(raised.exception, GuardReadUnavailable), transient and method != 'eth_sendRawTransaction')
                    self.assertEqual(evidence[0]['category'], category)
                    self.assertEqual(evidence[0]['response_bytes'], len(body))
                    self.assertEqual(evidence[0]['http_status'], 200)
                    self.assertEqual(evidence[0]['attempt'], 1)
                    self.assertEqual(evidence[0]['rpc_code'], -32011 if category == 'rpc_error' else None)
                    self.assertNotIn('PRIVATE_', json.dumps(evidence))
                    self.assertNotIn('PRIVATE_', str(raised.exception))

    def test_private_journal_whitelist_and_bounded_one_row(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root)/'state.sqlite'); coupon = store.issue_coupon(100000000)
            digest = store.digest(coupon)
            detail = {'method':'eth_getBlockByNumber','category':'response_decode',
                'http_status':200,'rpc_code':None,'response_bytes':5,'attempt':1,'elapsed_ms':4}
            store.note_guard_rpc(digest, 'guard_read', detail)
            store.note_guard_rpc(digest, 'guard_read', dict(detail, attempt=2))
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM issuance_rpc_diagnostics').fetchone()[0], 1)
            for change in [dict(detail, body='PRIVATE_BODY_CANARY'), dict(detail, method='PRIVATE_CANARY'),
                    dict(detail, category='PRIVATE_CANARY'), dict(detail, elapsed_ms=True), dict(detail, response_bytes=65538)]:
                with self.assertRaises(RedemptionError): store.note_guard_rpc(digest, 'guard_read', change)
            store.close()


class OriginalAttemptTests(BaseGuardTests):
    def exercise(self, always):
        fixture = self.rpc; rpc = GuardRPC('https://mainnet.base.org'); reads = []
        class Opener:
            def open(self, request, timeout):
                value = json.loads(request.data); method, params = value['method'], value['params']
                if method == 'eth_getBlockByNumber':
                    reads.append(params)
                    if always or len(reads) == 1: return Response(b'<html>PRIVATE_UPSTREAM_CANARY</html>')
                return Response(json.dumps({'jsonrpc':'2.0','id':1,'result':fixture.call(method, params)}).encode())
        rpc.opener = Opener(); self.rpc = rpc
        guard = self.guard(); provider_calls = []
        class Provider:
            def create_key(self, name, budget):
                provider_calls.append(True); return IssuedKey('synthetic-key', 'SYNTHETIC_ONLY')
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root)/'state.sqlite'); coupon = store.issue_coupon(100000000)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            guard.rpc_diagnostics = lambda stage, detail: store.note_guard_rpc(store.digest(coupon), stage, detail)
            with patch('time.sleep'):
                if always:
                    ticks = itertools.count(0, .1)
                    with patch('time.monotonic', side_effect=lambda: next(ticks)), self.assertRaises(RedemptionError):
                        store.redeem(coupon, recipient, Provider(), before_create=lambda: guard(
                            store.digest(coupon), 'ActualPeer0000001', recipient, 'cc'*32, {'issuance_policy_sha256':'44'*32}))
                else:
                    store.redeem(coupon, recipient, Provider(), before_create=lambda: guard(
                        store.digest(coupon), 'ActualPeer0000001', recipient, 'cc'*32, {'issuance_policy_sha256':'44'*32}))
            self.assertEqual(len(fixture.sent), 1)
            self.assertEqual(len(provider_calls), 0 if always else 1)
            self.assertEqual(store.db.execute('SELECT state FROM coupons').fetchone()[0], 'quarantined' if always else 'delivered')
            evidence = store.db.execute('SELECT * FROM issuance_rpc_diagnostics').fetchone()
            self.assertEqual(evidence['stage'], 'guard_read')
            self.assertEqual(json.loads(evidence['metadata'])['category'], 'response_decode')
            self.assertNotIn('PRIVATE_UPSTREAM', str(tuple(evidence)))
            store.close()
        self.assertGreater(len(reads), 1)

    def test_decode_failure_then_safe_one_send_one_provider(self): self.exercise(False)
    def test_decode_budget_quarantines_without_resend_or_provider(self): self.exercise(True)


class AsyncDiagnosticTests(unittest.TestCase):
    def test_actual_job_persists_static_rpc_failure_before_provider(self):
        fixture = async_fixture.AsyncServiceTests('test_crash_after_guard_before_provider_does_not_recreate_permission')
        fixture.setUp()
        class RefusingAuthorizer:
            progress = rpc_diagnostics = None
            def __call__(self, *_args):
                rpc = GuardRPC('https://example.invalid')
                rpc.observer = lambda method, error: self.progress('guard_read', method, error)
                rpc.diagnostic_observer = lambda detail: self.rpc_diagnostics('guard_read', detail)
                body = b'{"jsonrpc":"2.0","id":1,"error":{"code":-32011,"message":"PRIVATE_CANARY"}}'
                with patch.object(rpc.opener, 'open', return_value=Response(body)):
                    rpc.call('eth_getBlockByNumber', ['safe', False])
        try:
            fixture.service.close_jobs(); fixture.service = fixture.make(RefusingAuthorizer())
            fixture.request(); fixture.wait_state('quarantined')
            for job in fixture.service.jobs.values(): job.join(2)
            row = fixture.store.db.execute('SELECT * FROM issuance_rpc_diagnostics').fetchone()
            self.assertEqual(row['stage'], 'guard_read')
            detail = json.loads(row['metadata'])
            self.assertEqual((detail['method'], detail['category'], detail['rpc_code']),
                             ('eth_getBlockByNumber', 'rpc_error', -32011))
            self.assertFalse((fixture.root/'effects').exists())
            self.assertNotIn('PRIVATE_CANARY', str(tuple(row)))
        finally: fixture.tearDown()


if __name__ == '__main__': unittest.main()
