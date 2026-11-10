"""Offline checks for deployment identity and Base Sepolia RPC input."""
from email.message import Message
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import deploy
from rpc import ChainReader, RPCError

URLS = ("https://one.invalid", "https://two.invalid", "https://three.invalid")
HEADER = {"number": "0x100", "hash": "0x" + "ab" * 32, "timestamp": hex(int(time.time()))}


class PaymentsScriptsTest(unittest.TestCase):
    def responses(self, url, method, params):
        if method == "eth_chainId": return "0x14a34"
        if method == "eth_getBlockByNumber": return HEADER.copy()
        if method == "eth_getCode":
            self.assertEqual(params[-1], {"blockHash": HEADER["hash"], "requireCanonical": True})
            return "0x6000"
        raise AssertionError(method)

    def test_owner_mismatch_stops_before_rpc_or_build(self):
        with tempfile.TemporaryDirectory() as scratch:
            key = Path(scratch) / "dummy.key"
            key.write_text("0x" + "01" * 32)
            with patch.object(deploy, "ChainReader") as rpc, patch.object(deploy.subprocess, "run") as build:
                with patch.object(deploy.sys, "argv", ["deploy.py", str(key), scratch]):
                    with self.assertRaisesRegex(ValueError, "does not derive"):
                        deploy.main()
                rpc.assert_not_called()
                build.assert_not_called()

    def test_one_healthy_provider_pins_block_hash(self):
        def query(url, method, params):
            if url != URLS[2]: raise TimeoutError()
            return self.responses(url, method, params)
        with patch('rpc.call', query):
            reader = ChainReader(URLS)
            self.assertEqual(reader.at('eth_getCode', ['0x'+'12'*20], reader.finalized()), '0x6000')

    def test_stale_and_future_finalized_heads_fail(self):
        for delta in (-1801, 31):
            def query(url, method, params):
                value = self.responses(url, method, params)
                if method == 'eth_getBlockByNumber': value['timestamp'] = hex(int(time.time()) + delta)
                return value
            with patch('rpc.call', query), self.assertRaisesRegex(RuntimeError, 'stale or future'):
                ChainReader(URLS).finalized()

    def test_wrong_chain_cannot_supply_state(self):
        calls = []
        def query(url, method, params):
            calls.append(method)
            return '0x2105'
        with patch('rpc.call', query), self.assertRaisesRegex(RuntimeError, 'Base Sepolia'):
            ChainReader(URLS).finalized()
        self.assertEqual(calls, ['eth_chainId'] * 3)

    def test_failover_checks_pinned_block_hash_and_number(self):
        for changed in ({'hash': '0x'+'cd'*32}, {'number': '0x101'}):
            def query(url, method, params):
                if url == URLS[0] and method == 'eth_getCode': raise TimeoutError()
                value = self.responses(url, method, params)
                if method == 'eth_getBlockByNumber' and url != URLS[0]: value.update(changed)
                return value
            with patch('rpc.call', query):
                reader = ChainReader(URLS)
                with self.assertRaisesRegex(RuntimeError, 'snapshot block changed'):
                    reader.at('eth_getCode', ['0x'+'12'*20], reader.finalized())

    def test_lagging_finalized_provider_does_not_block_healthy_provider(self):
        def query(url, method, params):
            value = self.responses(url, method, params)
            if url == URLS[0] and method == 'eth_getBlockByNumber': value['timestamp'] = '0x1'
            return value
        with patch('rpc.call', query):
            self.assertEqual(ChainReader(URLS).finalized(), HEADER)

    def test_http_429_backoff_honors_retry_after_and_recovers(self):
        now = [1000]
        attempts = []
        headers = Message(); headers['Retry-After'] = '10'
        def query(url, method, params):
            if url == URLS[0]:
                attempts.append(now[0])
                raise HTTPError(url, 429, 'limited', headers, None)
            if url == URLS[1]: raise TimeoutError()
            return self.responses(url, method, params)
        with patch('rpc.call', query):
            reader = ChainReader(URLS, clock=lambda: now[0])
            self.assertEqual(reader.read('eth_getCode', ['x', {'blockHash': HEADER['hash'], 'requireCanonical': True}]), '0x6000')
            reader.read('eth_chainId', [])
            self.assertEqual(attempts, [1000])
            now[0] = 1010
            reader.read('eth_chainId', [])
            self.assertEqual(attempts, [1000, 1010])

    def test_json_quota_backoff_increases_and_all_unavailable_fails(self):
        now = [0]; attempts = []
        def query(url, method, params):
            if method == 'eth_chainId': return '0x14a34'
            attempts.append(now[0])
            raise RPCError(method, {'code': -32007, 'message': 'quota'})
        with patch('rpc.call', query):
            reader = ChainReader([URLS[0]], clock=lambda: now[0])
            for instant in (0, 0.5, 1, 2.9, 3):
                now[0] = instant
                with self.assertRaisesRegex(RuntimeError, 'RPC unavailable'):
                    reader.read('eth_blockNumber', [])
        self.assertEqual(attempts, [0, 1, 3])

    def test_contract_revert_is_not_hidden_by_failover(self):
        def query(url, method, params):
            if method == 'eth_chainId': return '0x14a34'
            raise RPCError(method, {'code': 3, 'message': 'execution reverted'})
        with patch('rpc.call', side_effect=query) as call, self.assertRaisesRegex(RPCError, 'execution reverted'):
            ChainReader(URLS).read('eth_call', [])
        self.assertEqual(call.call_count, 2)

    def test_ambiguous_submission_retries_identical_signed_bytes_and_checks_receipt(self):
        calls = []
        def query(url, method, params):
            calls.append((url, method, params))
            if method == 'eth_chainId': return '0x14a34'
            if url == URLS[0]: raise TimeoutError('response lost')
            if method == 'eth_sendRawTransaction': return 'hash'
            return {'transactionHash': 'hash', 'status': '0x1'}
        with patch('rpc.call', query):
            reader = ChainReader(URLS)
            self.assertEqual(reader.request(None, 'eth_sendRawTransaction', ['signed-bytes']), 'hash')
            self.assertEqual(deploy.wait_receipt(reader, 'hash')['status'], '0x1')
        self.assertEqual([params for _, method, params in calls if method == 'eth_sendRawTransaction'], [['signed-bytes'], ['signed-bytes']])


if __name__ == '__main__': unittest.main()
