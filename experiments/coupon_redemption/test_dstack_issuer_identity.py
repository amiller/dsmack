import hashlib
import asyncio
import importlib.metadata
import json
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .dstack_issuer_identity import DstackIssuerIdentity, DOMAIN, KEY_PATH, POSSESSION_DOMAIN, report_data, main
from .spike import RedemptionError


class SyntheticSdk:
    def __init__(self):
        self.calls = []

    def get_key(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return SimpleNamespace(decode_key=lambda: b"\x42" * 32)

    def get_quote(self, data):
        self.calls.append(data)
        return SimpleNamespace(quote="00", event_log="[]")

    def version(self):
        return SimpleNamespace(version="0.5.7")


class DstackIssuerTests(unittest.TestCase):
    def setUp(self):
        self.sdk = SyntheticSdk()
        self.identity = DstackIssuerIdentity(self.sdk)
        self.binding = {"version": 2, "peer_id": "12D3KooWTestOnlySyntheticIssuerPeer0001",
                        "public_key_hex": self.identity.public_key_hex(),
                        "challenge_hex": "aa" * 32, "policy_sha256": "bb" * 32}

    def test_separate_key_domain_raw_binding_and_possession_not_hardware(self):
        evidence = self.identity.collect(self.binding, '{"SYNTHETIC TEST ONLY":true}')
        self.assertEqual(self.sdk.calls[0], (KEY_PATH, {"purpose": "coupon issuer signing", "algorithm": "ed25519"}))
        expected = hashlib.sha512(DOMAIN.encode() + b"\x00" + json.dumps(
            self.binding, sort_keys=True, separators=(",", ":")).encode()).digest()
        self.assertEqual(self.sdk.calls[-1], expected)
        self.assertEqual(len(expected), 64)
        self.identity._signer.public_key().verify(bytes.fromhex(evidence["possession_signature_hex"]), POSSESSION_DOMAIN + expected)
        self.assertNotIn((b"\x42" * 32).hex(), json.dumps(evidence))
        self.assertNotIn("verified", evidence)
        self.assertEqual(evidence["binding"], self.binding)

    def test_actual_service_signer_can_be_bound_without_rederiving_another_key(self):
        sdk = SyntheticSdk()
        identity = DstackIssuerIdentity(sdk, Ed25519PrivateKey.generate())
        binding = {**self.binding, "public_key_hex": identity.public_key_hex()}
        evidence = identity.collect(binding, "{}")
        self.assertEqual(len(sdk.calls), 1)
        identity._signer.public_key().verify(bytes.fromhex(evidence["possession_signature_hex"]), POSSESSION_DOMAIN + report_data(binding))

    def test_invalid_or_changed_binding_refused_before_socket_quote(self):
        for change in [{"version": True}, {"peer_id": "role:recipient"}, {"challenge_hex": "short"},
                       {"public_key_hex": "00" * 32}, {"policy_sha256": "CC" * 32}, {"role": "issuer"}]:
            with self.assertRaises(RedemptionError):
                self.identity.collect({**self.binding, **change}, "{}")
        self.assertEqual(len(self.sdk.calls), 1)

    def test_quote_and_compose_limits_sdk_errors_are_sanitized(self):
        with self.assertRaises(RedemptionError):
            self.identity.collect(self.binding, "x" * 131073)
        self.assertEqual(len(self.sdk.calls), 1)
        for quote, log in [("00" * 131073, "[]"), ("not-hex", "[]"), ("00", " " * 1048577)]:
            self.sdk.get_quote = lambda _data: SimpleNamespace(quote=quote, event_log=log)
            with self.assertRaises(RedemptionError):
                self.identity.collect(self.binding, "{}")
        self.sdk.get_quote = lambda _data: (_ for _ in ()).throw(RuntimeError("secret-canary"))
        with self.assertRaises(RedemptionError) as raised:
            self.identity.collect(self.binding, "{}")
        self.assertNotIn("secret-canary", str(raised.exception))

    def test_normal_factory_requires_explicit_unix_socket_and_pinned_sdk(self):
        for path in ["relative.sock", "http://127.0.0.1:9999", "/nonexistent-dstack-issuer-test.sock"]:
            with self.assertRaises(RedemptionError):
                DstackIssuerIdentity.from_socket(path)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "guest.sock")
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(path)
                with patch("importlib.metadata.version", return_value="0.5.3"):
                    with self.assertRaises(RedemptionError):
                        DstackIssuerIdentity.from_socket(path)
                with patch("importlib.metadata.version", return_value="0.5.4"), patch("dstack_sdk.DstackClient", return_value=SyntheticSdk()) as factory:
                    DstackIssuerIdentity.from_socket(path)
                    factory.assert_called_once_with(path, timeout=10)

    def test_cli_invalid_binding_is_bounded_and_does_not_derive_key(self):
        with tempfile.TemporaryDirectory() as directory:
            binding = Path(directory) / "binding.json"
            compose = Path(directory) / "compose.json"
            binding.write_text(" " * 2049)
            compose.write_text("{}")
            with patch.object(DstackIssuerIdentity, "from_socket") as factory, patch("sys.stderr"):
                self.assertEqual(main(["collect", "--binding-file", str(binding), "--compose-file", str(compose)]), 1)
                factory.assert_not_called()

    def test_pinned_sdk_raw_quote_and_ed25519_rpc_contract(self):
        if importlib.metadata.version("dstack-sdk") != "0.5.4":
            self.skipTest("run this SDK contract check in the declared dstack-sdk 0.5.4 environment")
        from dstack_sdk import AsyncDstackClient
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "sdk-contract.sock")
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(path)
                client = AsyncDstackClient(path)
                calls = []

                async def synthetic_rpc(method, data):
                    calls.append((method, data))
                    if method == "Version":
                        return {"version": "0.5.7", "rev": "synthetic-only"}
                    if method == "GetKey":
                        return {"key": "42" * 32, "signature_chain": []}
                    return {"quote": "00", "event_log": "[]", "report_data": data["report_data"]}

                client._send_rpc_request = synthetic_rpc

                async def exercise():
                    key = await client.get_key(KEY_PATH, purpose="coupon issuer signing", algorithm="ed25519")
                    self.assertEqual(key.decode_key(), b"\x42" * 32)
                    result = await client.get_quote(report_data(self.binding))
                    self.assertEqual(result.report_data, report_data(self.binding).hex())

                asyncio.run(exercise())
                self.assertEqual(calls, [("Version", {}), ("GetKey", {
                    "path": KEY_PATH, "purpose": "coupon issuer signing", "algorithm": "ed25519"}),
                    ("GetQuote", {"report_data": report_data(self.binding).hex()})])


if __name__ == "__main__":
    unittest.main()
