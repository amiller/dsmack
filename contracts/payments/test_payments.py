"""Offline trust-boundary checks for deployment identity and RPC quorum."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import deploy
from rpc import Quorum

URLS = ("https://one.invalid", "https://two.invalid", "https://three.invalid")
HEADER = {"number": "0x100", "hash": "0x" + "ab" * 32, "timestamp": hex(int(time.time()))}


class PaymentsScriptsTest(unittest.TestCase):
    def responses(self, url, method, params):
        if method == "eth_chainId":
            return "0x14a34"
        if method == "eth_getBlockByNumber":
            return HEADER.copy()
        if method == "eth_getCode":
            self.assertEqual(params[-1], {"blockHash": HEADER["hash"], "requireCanonical": True})
            return "0x6000"
        raise AssertionError(method)

    def test_owner_mismatch_stops_before_rpc_or_build(self):
        with tempfile.TemporaryDirectory() as scratch:
            key = Path(scratch) / "dummy.key"
            key.write_text("0x" + "01" * 32)
            with patch.object(deploy, "Quorum") as rpc, patch.object(deploy.subprocess, "run") as build:
                with patch.object(deploy.sys, "argv", ["deploy.py", str(key), scratch]):
                    with self.assertRaisesRegex(ValueError, "does not derive"):
                        deploy.main()
                rpc.assert_not_called()
                build.assert_not_called()

    def test_two_agree_and_one_rpc_failure_still_pins_block_hash(self):
        def query(url, method, params):
            if url == URLS[2]:
                raise TimeoutError("dummy timeout")
            return self.responses(url, method, params)
        with patch("rpc.call", query):
            q = Quorum(URLS)
            header = q.finalized()
            self.assertEqual(q.at("eth_getCode", ["0x" + "12" * 20], header), "0x6000")
            self.assertEqual(len(q.urls), 2)

    def test_stale_finalized_head_fails(self):
        def query(url, method, params):
            result = self.responses(url, method, params)
            if method == "eth_getBlockByNumber":
                result["timestamp"] = hex(int(time.time()) - 1801)
            return result
        with patch("rpc.call", query):
            with self.assertRaisesRegex(RuntimeError, "stale"):
                Quorum(URLS).finalized()

    def test_wrong_chain_cannot_supply_majority(self):
        with patch("rpc.call", return_value="0x2105"):
            with self.assertRaisesRegex(RuntimeError, "Base Sepolia"):
                Quorum(URLS).finalized()

    def test_disagreeing_hashes_fail(self):
        def query(url, method, params):
            result = self.responses(url, method, params)
            if method == "eth_getBlockByNumber" and params[0] != "finalized":
                result["hash"] = "0x" + str(URLS.index(url) + 1) * 64
            return result
        with patch("rpc.call", query):
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                Quorum(URLS).finalized()

    def test_state_must_agree_at_pinned_block(self):
        def query(url, method, params):
            if method == "eth_getCode":
                return "0x600" + str(URLS.index(url))
            return self.responses(url, method, params)
        with patch("rpc.call", query):
            q = Quorum(URLS)
            header = q.finalized()
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                q.at("eth_getCode", ["0x" + "12" * 20], header)

    def test_highest_quorum_finalized_height_ignores_a_lagging_provider(self):
        requested = []
        def query(url, method, params):
            result = self.responses(url, method, params)
            if method == "eth_getBlockByNumber":
                if params[0] == "finalized":
                    result["number"] = hex(256 + URLS.index(url))
                else:
                    requested.append(params[0])
                    result["number"] = params[0]
            return result
        with patch("rpc.call", query):
            self.assertEqual(Quorum(URLS).finalized()["number"], "0x101")
        self.assertEqual(requested, ["0x101"] * 2)


if __name__ == "__main__":
    unittest.main()
