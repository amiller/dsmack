import unittest
from types import SimpleNamespace
from unittest.mock import patch

from .dstack_identity import DstackIdentity, KEY_PATH, report_data, verify_remote_identity
from .spike import RedemptionError


class FakeSdk:
    def __init__(self):
        self.calls = []

    def get_key(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return SimpleNamespace(decode_key=lambda: b"\x42" * 32)

    def get_quote(self, data):
        self.calls.append(data)
        return SimpleNamespace(quote="abcd", event_log="[]", vm_config="{}")


class DstackIdentityTests(unittest.TestCase):
    def test_stable_signer_and_challenge_binding_not_verification(self):
        sdk = FakeSdk()
        identity = DstackIdentity(sdk)
        again = DstackIdentity(FakeSdk())
        self.assertEqual(identity.public_key_bytes(), again.public_key_bytes())
        a, b = identity.quote(b"a" * 32), identity.quote(b"b" * 32)
        self.assertEqual(sdk.calls[0][0], KEY_PATH)
        self.assertEqual(sdk.calls[0][1]["algorithm"], "ed25519")
        self.assertEqual(len(sdk.calls[-1]), 64)
        self.assertNotEqual(a["expected_report_data_hex"], b["expected_report_data_hex"])
        self.assertEqual(a["evidence_status"], "unverified-dstack-quote")
        self.assertNotIn((b"\x42" * 32).hex(), str(a))
        with self.assertRaises(RedemptionError):
            verify_remote_identity(a, {"accept_all": True})

    def test_invalid_binding_input(self):
        for key, challenge in [(b"x", b"a" * 32), (b"x" * 32, b"short"),
                               (b"x" * 32, "a" * 32)]:
            with self.assertRaises(ValueError):
                report_data(key, challenge)

    def test_sdk_failures_redacted(self):
        sdk = FakeSdk()
        sdk.get_key = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("secret-value"))
        with self.assertRaises(RedemptionError) as caught:
            DstackIdentity(sdk)
        self.assertNotIn("secret-value", str(caught.exception))
        sdk = FakeSdk()
        identity = DstackIdentity(sdk)
        sdk.get_quote = lambda *a: SimpleNamespace(quote="", event_log="[]", vm_config="{}")
        with self.assertRaises(RedemptionError):
            identity.quote(b"a" * 32)

    def test_socket_factory_rejects_remote_or_missing_socket(self):
        with patch.dict("os.environ", {"DSTACK_SIMULATOR_ENDPOINT": "http://untrusted:8090"}):
            for endpoint in ["http://untrusted:8090", "/no/such/dstack.sock"]:
                with self.assertRaises(RedemptionError):
                    DstackIdentity.from_socket(endpoint)


if __name__ == "__main__":
    unittest.main()
