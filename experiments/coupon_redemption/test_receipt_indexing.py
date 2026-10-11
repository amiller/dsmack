"""Exact receipt-index lag: same submission/deadline, no other retry policy."""
import copy
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
from . import test_async_service_v4 as async_fixture
from . import test_base_guard as base_fixture

INDEXING = {'jsonrpc': '2.0', 'id': 1,
            'error': {'code': -32000, 'message': 'transaction indexing is in progress'}}


class Response:
    def __init__(self, value): self.data = json.dumps(value).encode()
    def __enter__(self): return self
    def __exit__(self, *_args): pass
    def read(self, limit): return self.data[:limit]


class ReceiptEnvelopeTests(unittest.TestCase):
    def test_only_exact_documented_receipt_error_is_transient(self):
        negatives = []
        for method in ('eth_getTransactionByHash', 'eth_sendRawTransaction', 'eth_getCode'):
            negatives.append((method, copy.deepcopy(INDEXING), 'rpc_error'))
        for path, value in [('code', -32001), ('message', 'transaction indexing is in progress '),
                            ('message', 'PRIVATE_RPC_MESSAGE_CANARY')]:
            changed = copy.deepcopy(INDEXING); changed['error'][path] = value
            negatives.append(('eth_getTransactionReceipt', changed, 'rpc_error'))
        for changed in [dict(INDEXING, id=True), dict(INDEXING, id=2),
                        dict(INDEXING, result=None), dict(INDEXING, jsonrpc='1.0'),
                        dict(INDEXING, error={**INDEXING['error'], 'data': 'PRIVATE_RPC_DATA_CANARY'}),
                        dict(INDEXING, error={'code': '-32000', 'message': INDEXING['error']['message']})]:
            negatives.append(('eth_getTransactionReceipt', changed, 'invalid_response'))
        cases = [('eth_getTransactionReceipt', INDEXING, 'receipt_indexing'), *negatives]
        for method, envelope, category in cases:
            with self.subTest(method=method, envelope=envelope):
                rpc = GuardRPC('https://example.invalid'); observations = []
                rpc.observer = lambda m, c: observations.append((m, c))
                with patch.object(rpc.opener, 'open', return_value=Response(envelope)):
                    with self.assertRaises(RedemptionError) as raised: rpc.call(method, ['0x'+'aa'*32])
                self.assertEqual(raised.exception.category, category)
                self.assertEqual(isinstance(raised.exception, GuardReadUnavailable), category == 'receipt_indexing')
                self.assertEqual(observations[-1], (method, category))
                self.assertNotIn('PRIVATE_RPC', str(raised.exception))


class ReceiptDeadlineTests(base_fixture.BaseGuardTests):
    def install_rpc(self, *, always=False):
        fixture = self.rpc
        rpc = GuardRPC('https://mainnet.base.org'); receipt_hashes = []
        class Opener:
            def open(self, request, timeout):
                value = json.loads(request.data); method, params = value['method'], value['params']
                if method == 'eth_getTransactionReceipt':
                    receipt_hashes.append(params[0])
                    if always or len(receipt_hashes) == 1: return Response(INDEXING)
                return Response({'jsonrpc':'2.0', 'id':1, 'result':fixture.call(method, params)})
        rpc.opener = Opener(); self.rpc = rpc
        return fixture, receipt_hashes

    def test_indexing_then_safe_uses_original_hash_and_one_provider_post(self):
        fixture, hashes = self.install_rpc()
        provider_calls = []
        class Provider:
            def create_key(self, name, budget):
                provider_calls.append((name, budget)); return IssuedKey('synthetic-key', 'SYNTHETIC_ONLY')
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary)/'state.sqlite'); coupon = store.issue_coupon(100000000)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            guard = self.guard()
            try:
                with patch('time.sleep'):
                    store.redeem(coupon, recipient, Provider(), before_create=lambda:
                        guard(store.digest(coupon), 'ActualPeer0000001', recipient, 'cc'*32,
                              {'issuance_policy_sha256':'44'*32}))
                self.assertEqual(len(fixture.sent), 1)
                self.assertEqual(len(hashes), 2); self.assertEqual(len(set(hashes)), 1)
                self.assertEqual(len(provider_calls), 1)
                store.redeem(coupon, recipient, Provider()); self.assertEqual(len(provider_calls), 1)
            finally: store.close()

    def test_indexing_exhausts_original_deadline_without_resending_or_provider(self):
        fixture, hashes = self.install_rpc(always=True); guard = self.guard()
        ticks = itertools.count(0, 1)
        provider_calls = []
        class Provider:
            def create_key(self, *_args): provider_calls.append(True); raise AssertionError('no provider effect allowed')
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary)/'state.sqlite'); coupon = store.issue_coupon(100000000)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            try:
                with patch('time.monotonic', side_effect=lambda: next(ticks)), patch('time.sleep'):
                    with self.assertRaises(RedemptionError):
                        store.redeem(coupon, recipient, Provider(), before_create=lambda:
                            guard(store.digest(coupon), 'ActualPeer0000001', recipient, 'cc'*32,
                                  {'issuance_policy_sha256':'44'*32}))
                self.assertEqual(store.db.execute('SELECT state FROM coupons').fetchone()[0], 'quarantined')
                self.assertEqual(provider_calls, [])
            finally: store.close()
        self.assertEqual(len(fixture.sent), 1)
        self.assertGreater(len(hashes), 1); self.assertEqual(len(set(hashes)), 1)

    def test_receipt_semantic_refusals_keep_static_category_and_one_send(self):
        for field, value, category in [
            ('transactionHash', '0x'+'ff'*32, 'receipt_hash_mismatch'),
            ('from', '0x'+'ff'*20, 'receipt_authority_mismatch'),
            ('to', '0x'+'ff'*20, 'receipt_authority_mismatch'),
            ('status', '0x0', 'receipt_reverted'), ('status', '0x2', 'receipt_status_invalid'),
            ('blockNumber', '0x05', 'receipt_quantity_invalid'),
            ('blockHash', 'PRIVATE_CANARY', 'receipt_hash_invalid')]:
            with self.subTest(field=field):
                self.rpc = base_fixture.BaseRPCFixture(self.profile); fixture = self.rpc
                original = fixture.call
                def changed(method, params):
                    result = original(method, params)
                    if method == 'eth_getTransactionReceipt': result[field] = value
                    return result
                fixture.call = changed
                guard = self.guard(); observations = []
                guard.progress = lambda stage, method, error: observations.append((stage, method, error))
                with self.assertRaises(RedemptionError) as raised:
                    guard('aa'*32, 'ActualPeer0000001', b'\x55'*32, 'cc'*32,
                          {'issuance_policy_sha256':'44'*32})
                self.assertEqual(raised.exception.category, category)
                self.assertEqual(observations[-1], ('guard_read', 'eth_getTransactionReceipt', category))
                self.assertEqual(len(fixture.sent), 1)
                self.assertNotIn('PRIVATE_CANARY', str(raised.exception))


class JournalCategoryTests(unittest.TestCase):
    def test_async_quarantine_preserves_rpc_category_without_provider_or_raw_message(self):
        fixture = async_fixture.AsyncServiceTests('test_crash_after_guard_before_provider_does_not_recreate_permission')
        fixture.setUp()
        class RefusingAuthorizer:
            progress = None
            def __call__(self, *_args):
                rpc = GuardRPC('https://example.invalid')
                rpc.observer = lambda method, error: self.progress('guard_read', method, error)
                envelope = copy.deepcopy(INDEXING)
                envelope['error']['message'] = 'PRIVATE_RPC_MESSAGE_CANARY'
                with patch.object(rpc.opener, 'open', return_value=Response(envelope)):
                    rpc.call('eth_getTransactionReceipt', ['0x'+'aa'*32])
        try:
            fixture.service.close_jobs(); fixture.service = fixture.make(RefusingAuthorizer())
            fixture.request(); fixture.wait_state('quarantined')
            for job in fixture.service.jobs.values(): job.join(2)
            row = fixture.store.db.execute('SELECT * FROM issuance_progress').fetchone()
            self.assertEqual((row['stage'], row['rpc_method'], row['error_category']),
                             ('guard_read', 'eth_getTransactionReceipt', 'rpc_error'))
            self.assertFalse((fixture.root/'effects').exists())
            self.assertNotIn('PRIVATE_RPC_MESSAGE_CANARY', str(tuple(row)))
        finally: fixture.tearDown()


if __name__ == '__main__': unittest.main()
