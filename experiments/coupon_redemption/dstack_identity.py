"""Collect dstack TDX evidence; collection is not remote verification.

Uses dstack-sdk 0.5.4 GetKey/GetQuote, with an explicit Unix socket so simulator
environment variables cannot silently select a remote key service. Production
acceptance still requires hardware verification, approved measurements, key
custody/KMS policy and a fresh verifier challenge. This module authorizes nothing.
"""

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .spike import RedemptionError


DOMAIN = b"dsmack-coupon-observer-identity-v1\x00"
KEY_PATH = "dsmack/coupon-observer/v1/ed25519"


def report_data(public_key, challenge):
    """64-byte domain-separated quote binding; challenge comes from verifier."""
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError("32-byte Ed25519 public key required")
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError("32-byte verifier challenge required")
    return hashlib.sha512(DOMAIN + public_key + challenge).digest()


class DstackIdentity:
    """SDK client injection is for tests; it never implies verified hardware."""

    def __init__(self, client):
        self._client = client
        try:
            derived = client.get_key(KEY_PATH, purpose="coupon observer signing",
                                     algorithm="ed25519")
            seed = derived.decode_key()
            if not isinstance(seed, bytes) or len(seed) != 32:
                raise ValueError("invalid key length")
            self.signing_key = Ed25519PrivateKey.from_private_bytes(seed)
        except Exception:
            raise RedemptionError("dstack identity unavailable") from None

    @classmethod
    def from_socket(cls, socket_path="/var/run/dstack.sock"):
        path = Path(socket_path)
        try:
            if not path.is_absolute() or not stat.S_ISSOCK(path.stat().st_mode):
                raise ValueError("Unix socket required")
            from dstack_sdk import DstackClient
            client = DstackClient(str(path), timeout=10)
        except Exception:
            raise RedemptionError("dstack Unix socket unavailable") from None
        return cls(client)

    def public_key_bytes(self):
        return self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def quote(self, challenge):
        public = self.public_key_bytes()
        binding = report_data(public, challenge)
        try:
            result = self._client.get_quote(binding)
            # Format validation only. Neither parsing nor matching an echoed
            # report_data field proves the quote contains this binding.
            if not isinstance(result.quote, str) or not bytes.fromhex(result.quote):
                raise ValueError("empty quote")
            if not isinstance(result.event_log, str) or not isinstance(result.vm_config, str):
                raise ValueError("invalid supporting evidence")
            return {"domain": "dsmack-coupon-observer-identity-v1",
                    "evidence_status": "unverified-dstack-quote",
                    "public_key_hex": public.hex(), "challenge_hex": challenge.hex(),
                    "expected_report_data_hex": binding.hex(),
                    "quote_hex": result.quote, "event_log": result.event_log,
                    "vm_config": result.vm_config}
        except Exception:
            raise RedemptionError("dstack quote unavailable") from None


def verify_remote_identity(bundle, policy=None):
    """No verifier implemented: decoding a quote must never authorize release."""
    raise RedemptionError("remote hardware and measurement verification required")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect an UNVERIFIED dstack observer quote")
    parser.add_argument("--challenge-hex", required=True, help="32-byte fresh verifier challenge")
    parser.add_argument("--socket", default="/var/run/dstack.sock")
    args = parser.parse_args(argv)
    try:
        challenge = bytes.fromhex(args.challenge_hex)
        # Validate before deriving the identity or touching the socket.
        report_data(bytes(32), challenge)
        identity = DstackIdentity.from_socket(args.socket)
        print(json.dumps(identity.quote(challenge), sort_keys=True))
    except (ValueError, RedemptionError):
        print("Identity collection failed; no verified identity was established.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
