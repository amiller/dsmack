"""Specific live failure boundaries: temporary reads and private stage records."""
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from .issuance_guard import GuardRPC, GuardReadUnavailable
from .spike import Store, IssuedKey, RedemptionError
from .test_base_guard import BaseGuardTests, BaseRPCFixture


class ProgressTests(BaseGuardTests):
    # Reuse exact signed transaction/state fixture, not a second protocol model.
    def test_temporary_post_submit_read_reuses_one_submission_then_one_provider_post(self):
        original = self.rpc.call
        failed = [False]
        def transient(method, params):
            if method == 'eth_getTransactionReceipt' and not failed[0]:
                failed[0] = True
                raise GuardReadUnavailable('http_retryable')
            return original(method, params)
        self.rpc.call = transient
        guard = self.guard()
        class Provider:
            calls = 0
            def create_key(self, name, budget):
                self.calls += 1
                return IssuedKey('fixture-key', 'SYNTHETIC_ONLY')
        provider = Provider()
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory)/'state.sqlite'); coupon = store.issue_coupon(100000000)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            with patch('time.sleep'):
                store.redeem(coupon, recipient, provider, before_create=lambda:
                    guard(store.digest(coupon), 'ActualPeer0000001', recipient, 'cc'*32,
                          {'issuance_policy_sha256':'44'*32}))
            store.close()
        self.assertTrue(failed[0])
        self.assertEqual(len(self.rpc.sent), 1)
        self.assertEqual(provider.calls, 1)
        # A terminal binding failure never retries the send or reaches provider.
        self.rpc = BaseRPCFixture(self.profile); self.rpc.change = 'input'
        with self.assertRaises(RedemptionError): self.claim()
        self.assertEqual(len(self.rpc.sent), 1)

    def test_private_journal_marks_provider_ambiguity_without_secret_material(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory)/'state.sqlite')
            coupon = store.issue_coupon(100000000); digest = store.digest(coupon)
            store.effect_observer = lambda stage: store.note_issuance(digest, stage)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            class Provider:
                calls = 0
                def create_key(self, name, budget):
                    self.calls += 1
                    raise RuntimeError('PRIVATE_TOKEN_CANARY do not retain')
            provider = Provider()
            with self.assertRaises(RedemptionError): store.redeem(coupon, recipient, provider)
            self.assertEqual(provider.calls, 1)
            row = store.db.execute('SELECT * FROM issuance_progress').fetchone()
            self.assertEqual(row['stage'], 'provider_post_started')
            self.assertEqual(store.db.execute('SELECT state FROM coupons').fetchone()[0], 'quarantined')
            self.assertNotIn(coupon, str(tuple(row)))
            self.assertNotIn('PRIVATE_TOKEN_CANARY', str(tuple(row)))
            with self.assertRaises(RedemptionError): store.note_issuance(digest, 'PRIVATE_TOKEN_CANARY')
            store.close()

    def test_delivery_and_last_stage_commit_together(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory)/'state.sqlite')
            coupon = store.issue_coupon(100000000); digest = store.digest(coupon)
            recipient = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            class Provider:
                calls = 0
                def create_key(self, name, budget):
                    self.calls += 1
                    return IssuedKey('fixture-key', 'PRIVATE_PROVIDER_SECRET_CANARY')
            provider = Provider()
            store.effect_observer = lambda stage: store.note_issuance(digest, stage)
            store.redeem(coupon, recipient, provider)
            self.assertEqual(store.db.execute('SELECT state FROM coupons').fetchone()[0], 'delivered')
            self.assertEqual(store.db.execute('SELECT stage FROM issuance_progress').fetchone()[0], 'delivery_committed')
            store.redeem(coupon, recipient, provider)
            self.assertEqual(provider.calls, 1)
            self.assertNotIn('PRIVATE_PROVIDER_SECRET_CANARY', str(tuple(store.db.execute('SELECT * FROM issuance_progress').fetchone())))
            store.close()


class TransportClassificationTests(unittest.TestCase):
    def test_only_temporary_read_transport_is_retryable(self):
        rpc = GuardRPC('https://mainnet.base.org')
        for method, status, expected in [('eth_getTransactionReceipt',429,GuardReadUnavailable),
                ('eth_getCode',503,GuardReadUnavailable),('eth_sendRawTransaction',429,RedemptionError),
                ('eth_getTransactionCount',429,RedemptionError),('eth_getCode',401,RedemptionError)]:
            with self.subTest(method=method,status=status), patch.object(rpc.opener,'open',
                    side_effect=urllib.error.HTTPError('https://mainnet.base.org',status,'PRIVATE_CANARY',{},None)):
                with self.assertRaises(expected) as raised: rpc.call(method, [])
                if expected is RedemptionError: self.assertNotIsInstance(raised.exception, GuardReadUnavailable)
                self.assertNotIn('PRIVATE_CANARY',str(raised.exception))


if __name__ == '__main__': unittest.main()
