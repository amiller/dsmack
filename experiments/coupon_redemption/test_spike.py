import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .evidence import observe_and_sign, verify_local_signature, authorize_deposit_release
from .near import Near
from .spike import Store, IssuedKey, RedemptionError, decrypt_secret

KEY_ID = '11111111-1111-4111-8111-111111111111'
WS_ID = '22222222-2222-4222-8222-222222222222'
ORG_ID = '33333333-3333-4333-8333-333333333333'


class MockProvider:
    def __init__(self):
        self.calls = 0
        self.fail = False
        self.crash = False
        self.rows = []

    def create_key(self, name, budget):
        self.calls += 1
        if self.fail:
            raise RuntimeError('sensitive-upstream-secret')
        if self.crash:
            raise KeyboardInterrupt('simulated process death after provider creation')
        return IssuedKey(KEY_ID, 'synthetic-private-credential')

    def usage_rows(self, key_id, start_time, end_time):
        return self.rows


class SpikeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.sqlite'
        self.store = Store(self.path)
        self.coupon = self.store.issue_coupon(5_000_000_000)
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.provider = MockProvider()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def redeem(self):
        return self.store.redeem(self.coupon, self.public, self.provider)

    def row(self, row_id='row1', cost=5_000_000_000):
        return {'id': row_id, 'source': 'inference', 'api_key_id': KEY_ID,
                'workspace_id': WS_ID, 'total_cost_nano_usd': cost}

    def test_delivery_restart_and_replay(self):
        first = self.redeem()
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(first, self.redeem())
        self.assertEqual(self.provider.calls, 1)
        aad = (Store.digest(self.coupon) + ':' + KEY_ID).encode()
        self.assertEqual(decrypt_secret(first['envelope'], self.private, aad), 'synthetic-private-credential')
        dump = '\n'.join(self.store.db.iterdump())
        self.assertNotIn('synthetic-private-credential', dump)
        self.assertNotIn(self.coupon, dump)
        with self.assertRaises(RedemptionError):
            decrypt_secret(first['envelope'], self.private, b'wrong-binding')

    def test_wrong_recipient_and_invalid_point(self):
        with self.assertRaises(RedemptionError):
            self.store.redeem(self.coupon, bytes(32), self.provider)
        self.assertEqual(self.provider.calls, 0)
        self.redeem()
        other = X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with self.assertRaises(RedemptionError):
            self.store.redeem(self.coupon, other, self.provider)

    def test_ambiguous_failure_not_retried_or_leaked(self):
        self.provider.fail = True
        with self.assertRaises(RedemptionError) as caught:
            self.redeem()
        self.assertNotIn('sensitive-upstream-secret', str(caught.exception))
        with self.assertRaises(RedemptionError):
            self.redeem()
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(self.store.pending()[0]['state'], 'quarantined')

    def test_crash_after_creation_never_reissues(self):
        self.provider.crash = True
        with self.assertRaises(KeyboardInterrupt):
            self.redeem()
        self.store.close()
        self.store = Store(self.path)
        with self.assertRaises(RedemptionError):
            self.redeem()
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(self.store.pending()[0]['state'], 'issuing')

    def test_crash_during_delivery_persistence(self):
        self.store.db.executescript("""CREATE TRIGGER fail_delivery BEFORE UPDATE ON coupons
        WHEN NEW.state='delivered' BEGIN SELECT RAISE(FAIL, 'injected'); END;""")
        with self.assertRaises(RedemptionError):
            self.redeem()
        with self.assertRaises(RedemptionError):
            self.redeem()
        self.assertEqual(self.provider.calls, 1)

    def test_concurrent_claim(self):
        entered, release = Event(), Event()
        outer = self
        class BlockingProvider(MockProvider):
            def create_key(self, name, budget):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('test timeout')
                return super().create_key(name, budget)
        provider = BlockingProvider()
        def claim():
            store = Store(outer.path)
            try:
                return store.redeem(outer.coupon, outer.public, provider)
            finally:
                store.close()
        with ThreadPoolExecutor() as pool:
            first = pool.submit(claim)
            self.assertTrue(entered.wait(5))
            try:
                with self.assertRaises(RedemptionError):
                    self.redeem()
            finally:
                release.set()
            first.result(timeout=5)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(self.provider.calls, 0)

    def test_accounting_dedup_conflict_and_atomic_batch(self):
        self.redeem()
        self.store.ingest(self.coupon, [self.row()])
        self.store.ingest(self.coupon, [self.row()])
        preview = self.store.accounting(self.coupon, 1, 1000)
        self.assertEqual(preview['provider_reported_nano_usd'], 5_000_000_000)
        self.assertFalse(preview['deposit_release_authorized'])
        wrong = dict(self.row('wrong'), api_key_id='other-key')
        with self.assertRaises(RedemptionError):
            self.store.ingest(self.coupon, [wrong])
        self.store.ingest(self.coupon, [self.row('over', 1)])
        self.assertEqual(self.store.accounting(self.coupon, 1, 1)['overshoot_nano_usd'], 1)

    def test_correction_durably_blocks_fresh_signatures(self):
        self.redeem()
        self.store.ingest(self.coupon, [self.row()])
        with self.assertRaises(RedemptionError):
            self.store.ingest(self.coupon, [self.row('new', 3), self.row(cost=-1)])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM usage').fetchone()[0], 1)
        self.store.close()
        self.store = Store(self.path)
        with self.assertRaises(RedemptionError):
            self.store.accounting(self.coupon, 1, 1)
        self.provider.rows = []
        with self.assertRaises(RedemptionError):
            observe_and_sign(self.store, self.coupon, self.provider, Ed25519PrivateKey.generate(),
                             'start', 'end', 'new-challenge')

    def test_signed_observer_tamper_and_unattested_gate(self):
        self.redeem()
        self.provider.rows = [self.row()]
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        evidence = observe_and_sign(self.store, self.coupon, self.provider, signer,
                                    '2026-10-10T00:00:00Z', '2026-10-11T00:00:00Z', 'contract-challenge')
        self.assertEqual(verify_local_signature(evidence, public)['provider_reported_nano_usd'], 5_000_000_000)
        with self.assertRaises(RedemptionError):
            authorize_deposit_release(evidence)
        evidence['payload']['provider_reported_nano_usd'] += 1
        with self.assertRaises(RedemptionError):
            verify_local_signature(evidence, public)

    def test_missing_cost_on_known_row_blocks_accounting(self):
        self.redeem()
        self.store.ingest(self.coupon, [self.row()])
        malformed = self.row()
        del malformed['total_cost_nano_usd']
        with self.assertRaises(RedemptionError):
            self.store.ingest(self.coupon, [malformed])
        with self.assertRaises(RedemptionError):
            self.store.accounting(self.coupon, 1, 1)

    def test_adapter_wire_contract_and_pagination(self):
        calls = []
        def transport(method, url, bearer, body):
            calls.append((method, url, bearer, body))
            if method == 'POST':
                return {'id': KEY_ID, 'key': 'synthetic-secret'}
            return {'data': [self.row()], 'next_cursor': None}
        near = Near(WS_ID, ORG_ID, 'mock-session', 'mock-reporting', transport)
        issued = near.create_key('coupon-demo', 5_000_000_000)
        self.assertNotIn('synthetic-secret', repr(issued))
        self.assertEqual(calls[0][3]['spendLimit'], {'amount': 5_000_000_000, 'currency': 'USD'})
        self.assertEqual(near.usage_rows(KEY_ID, 'start', 'end'), [self.row()])
        self.assertIn('api_key_id=' + KEY_ID, calls[-1][1])
        self.assertEqual(calls[-1][2], 'mock-reporting')

    def test_repeated_cursor_rejected(self):
        near = Near(WS_ID, ORG_ID, 'session', 'reporting',
                    lambda *args: {'data': [], 'next_cursor': 'same'})
        with self.assertRaises(RedemptionError):
            near.usage_rows(KEY_ID, 'start', 'end')

    def test_export_attribution_and_successful_pagination(self):
        for field in ['workspace_id', 'api_key_id']:
            wrong = dict(self.row(), **{field: 'wrong'})
            near = Near(WS_ID, ORG_ID, 'session', 'reporting',
                        lambda *args: {'data': [wrong], 'next_cursor': None})
            with self.assertRaises(RedemptionError):
                near.usage_rows(KEY_ID, 'start', 'end')
        urls = []
        def pages(method, url, bearer, body):
            urls.append(url)
            return {'data': [self.row(str(len(urls)))],
                    'next_cursor': 'opaque+/=' if len(urls) == 1 else None}
        near = Near(WS_ID, ORG_ID, 'session', 'reporting', pages)
        self.assertEqual(len(near.usage_rows(KEY_ID, 'start', 'end')), 2)
        self.assertTrue(urls[1].startswith(urls[0] + '&cursor='))


if __name__ == '__main__':
    unittest.main()
