"""Documented Base B256::ZERO pending receipt is a wait, never a permission.

Source: base/base 749fe75d4c92d94ccb4375d6f6ba39bcb8ad4299,
crates/execution/flashblocks/src/state_builder.rs and rpc/eth.rs.
The original smoke5 response was not retained; this is a sourced fixture.
"""
import itertools
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from . import test_base_guard as base_fixture
from .spike import Store, IssuedKey, RedemptionError

ZERO_HASH = '0x' + '00' * 32


class FlashblockReceiptTests(base_fixture.BaseGuardTests):
    def install_pending(self, *, always=False, change=None):
        fixture = self.rpc; call = fixture.call; hashes = []
        def pending(method, params):
            value = call(method, params)
            if method == 'eth_getTransactionReceipt':
                hashes.append(params[0])
                if always or len(hashes) == 1:
                    value['blockHash'] = ZERO_HASH
                    if change: value.update(change)
            return value
        fixture.call = pending
        return fixture, hashes

    def redeem(self, guard, provider_calls):
        class Provider:
            def create_key(self, name, budget):
                provider_calls.append((name, budget))
                return IssuedKey('synthetic-key', 'SYNTHETIC_ONLY')
        store = Store(Path(self.temp.name)/'state.sqlite')
        coupon = store.issue_coupon(100000000)
        key = X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return store, coupon, key, Provider(), lambda: guard(
            store.digest(coupon), 'ActualPeer0000001', key, 'cc'*32,
            {'issuance_policy_sha256':'44'*32})

    def test_documented_pending_then_safe_sends_once_and_creates_once(self):
        fixture, hashes = self.install_pending(); provider_calls = []; progress = []
        guard = self.guard(); guard.progress = lambda *args: progress.append(args)
        store, coupon, key, provider, before = self.redeem(guard, provider_calls)
        try:
            with patch('time.sleep'):
                store.redeem(coupon, key, provider, before_create=before)
            self.assertEqual(len(fixture.sent), 1)
            self.assertEqual(len(hashes), 2); self.assertEqual(len(set(hashes)), 1)
            self.assertEqual(len(provider_calls), 1)
            self.assertIn(('guard_read', 'eth_getTransactionReceipt', 'receipt_preconfirmed'), progress)
            self.assertLess(progress.index(('guard_read', 'eth_getTransactionReceipt', 'receipt_preconfirmed')),
                            progress.index(('guard_confirmed', None, None)))
            store.redeem(coupon, key, provider); self.assertEqual(len(provider_calls), 1)
        finally: store.close()

    def test_pending_exhausts_original_deadline_without_second_send_or_provider(self):
        fixture, hashes = self.install_pending(always=True); provider_calls = []
        guard = self.guard(); progress = []; guard.progress = lambda *args: progress.append(args)
        store, coupon, key, provider, before = self.redeem(guard, provider_calls)
        try:
            clock = itertools.count()
            with patch('time.monotonic', side_effect=lambda: next(clock)), patch('time.sleep'):
                with self.assertRaisesRegex(RedemptionError, 'reconciliation'):
                    store.redeem(coupon, key, provider, before_create=before)
            self.assertEqual(len(fixture.sent), 1)
            self.assertGreater(len(hashes), 1); self.assertEqual(len(set(hashes)), 1)
            self.assertEqual(provider_calls, [])
            self.assertNotIn(('guard_confirmed', None, None), progress)
        finally: store.close()

    def test_invalid_and_semantically_wrong_pending_receipts_stay_terminal(self):
        cases = [({'blockNumber':None}, 'receipt_quantity_invalid'),
                 ({'blockNumber':'0x05'}, 'receipt_quantity_invalid'),
                 ({'blockHash':None}, 'receipt_hash_invalid'),
                 ({'blockHash':'0x0'}, 'receipt_hash_invalid'),
                 ({'blockHash':'00'*32}, 'receipt_hash_invalid'),
                 ({'blockHash':'0x'+'00'*31}, 'receipt_hash_invalid'),
                 ({'from':'0x'+'ff'*20}, 'receipt_authority_mismatch'),
                 ({'status':'0x0'}, 'receipt_reverted'),
                 ({'transactionHash':'0x'+'ff'*32}, 'receipt_hash_mismatch')]
        for change, category in cases:
            with self.subTest(change=change):
                self.rpc = base_fixture.BaseRPCFixture(self.profile)
                fixture, hashes = self.install_pending(always=True, change=change)
                with self.assertRaises(RedemptionError) as raised: self.claim()
                self.assertEqual(raised.exception.category, category)
                self.assertEqual(len(fixture.sent), 1); self.assertEqual(len(hashes), 1)

    def test_pending_then_canonical_reorg_never_authorizes_provider(self):
        fixture, hashes = self.install_pending(); fixture.change = 'receipt_reorg'
        provider_calls = []; guard = self.guard()
        store, coupon, key, provider, before = self.redeem(guard, provider_calls)
        try:
            with patch('time.sleep'):
                with self.assertRaisesRegex(RedemptionError, 'reconciliation'):
                    store.redeem(coupon, key, provider, before_create=before)
            self.assertEqual(len(fixture.sent), 1); self.assertEqual(provider_calls, [])
            self.assertEqual(len(hashes), 2)
        finally: store.close()

    def test_private_journal_distinguishes_pending_and_invalid_fields(self):
        store = Store(Path(self.temp.name)/'categories.sqlite')
        try:
            digest = store.digest(store.issue_coupon(100000000))
            for category in ('receipt_preconfirmed', 'receipt_quantity_invalid',
                             'receipt_hash_invalid', 'receipt_block_invalid'):
                store.note_issuance(digest, 'guard_read', 'eth_getTransactionReceipt', category)
                self.assertEqual(store.db.execute(
                    'SELECT error_category FROM issuance_progress').fetchone()[0], category)
            with self.assertRaises(RedemptionError):
                store.note_issuance(digest, 'guard_read', 'eth_getTransactionReceipt', 'PRIVATE_RPC_CANARY')
            self.assertNotIn('PRIVATE_RPC_CANARY', str(tuple(store.db.execute(
                'SELECT * FROM issuance_progress').fetchone())))
        finally: store.close()


if __name__ == '__main__': unittest.main()
