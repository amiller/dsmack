"""Collect issuer-v2 evidence. Only the independent verifier can authenticate it."""

import argparse
import hashlib
import importlib.metadata
import json
import re
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .spike import RedemptionError

DOMAIN = "dsmack-coupon-issuer-identity-v2"
KEY_PATH = "dsmack/coupon-issuer/v2/ed25519"
POSSESSION_DOMAIN = b"dsmack-coupon-issuer-possession-v2\x00"


def report_data(binding):
    if (type(binding) is not dict or set(binding) != {
            "version", "peer_id", "public_key_hex", "challenge_hex", "policy_sha256"}
            or type(binding["version"]) is not int or binding["version"] != 2
            or type(binding["peer_id"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9]{16,128}", binding["peer_id"])
            or any(type(binding[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", binding[name])
                   for name in ("public_key_hex", "challenge_hex", "policy_sha256"))):
        raise ValueError("invalid issuer binding")
    canonical = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha512(DOMAIN.encode("ascii") + b"\x00" + canonical).digest()


class DstackIssuerIdentity:
    """Inject a service signer only if it is the actual signing identity being admitted.

    The default uses a new domain-separated SDK key. It must not silently replace
    the coupon service's current signing identity. The caller owns that integration.
    """

    def __init__(self, client, signing_key=None):
        self._client = client
        try:
            if signing_key is None:
                derived = client.get_key(KEY_PATH, purpose="coupon issuer signing", algorithm="ed25519")
                seed = derived.decode_key()
                if type(seed) is not bytes or len(seed) != 32:
                    raise ValueError()
                signing_key = Ed25519PrivateKey.from_private_bytes(seed)
            if not isinstance(signing_key, Ed25519PrivateKey):
                raise ValueError()
            self._signer = signing_key
        except Exception:
            raise RedemptionError("dstack issuer identity unavailable") from None

    @classmethod
    def from_socket(cls, socket_path="/var/run/dstack.sock", signing_key=None):
        try:
            path = Path(socket_path)
            if not path.is_absolute() or not stat.S_ISSOCK(path.stat().st_mode):
                raise ValueError()
            if importlib.metadata.version("dstack-sdk") != "0.5.4":
                raise ValueError()
            from dstack_sdk import DstackClient
            client = DstackClient(str(path), timeout=10)
            version = client.version().version
            match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
            if not match or tuple(map(int, match.groups())) < (0, 5, 7):
                raise ValueError()
            return cls(client, signing_key)
        except Exception:
            raise RedemptionError("dstack issuer Unix socket unavailable") from None

    def public_key_hex(self):
        return self._signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def collect(self, binding, app_compose):
        try:
            data = report_data(binding)
            if binding["public_key_hex"] != self.public_key_hex():
                raise ValueError()
            if type(app_compose) is not str or not 0 < len(app_compose.encode("utf8")) <= 131072:
                raise ValueError()
            result = self._client.get_quote(data)
            if (type(result.quote) is not str or not re.fullmatch(r"(?:[0-9a-f]{2})+", result.quote)
                    or len(result.quote) > 262144 or type(result.event_log) is not str
                    or len(result.event_log.encode("utf8")) > 1048576):
                raise ValueError()
            return {"domain": DOMAIN, "binding": dict(binding), "quote_hex": result.quote,
                    "event_log": result.event_log, "app_compose": app_compose,
                    "possession_signature_hex": self._signer.sign(POSSESSION_DOMAIN + data).hex()}
        except Exception:
            raise RedemptionError("dstack issuer evidence unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect UNVERIFIED dstack issuer-v2 evidence")
    parser.add_argument("operation", choices=("public-key", "collect"))
    parser.add_argument("--socket", default="/var/run/dstack.sock")
    parser.add_argument("--binding-file", help="fresh verifier-owned binding JSON (public fields only)")
    parser.add_argument("--compose-file", help="exact application compose bytes measured by dstack")
    args = parser.parse_args(argv)
    try:
        if args.operation == "collect":
            if not args.binding_file or not args.compose_file:
                raise ValueError()
            with Path(args.binding_file).open("rb") as source:
                binding_bytes = source.read(2049)
            with Path(args.compose_file).open("rb") as source:
                compose_bytes = source.read(131073)
            if len(binding_bytes) > 2048 or len(compose_bytes) > 131072:
                raise ValueError()
            binding = json.loads(binding_bytes)
            report_data(binding)  # Reject invalid challenges before touching the guest socket.
            app_compose = compose_bytes.decode("utf8")
        identity = DstackIssuerIdentity.from_socket(args.socket)
        if args.operation == "public-key":
            print(json.dumps({"domain": DOMAIN, "public_key_hex": identity.public_key_hex(),
                              "evidence_status": "unverified-key-only"}, sort_keys=True))
        else:
            print(json.dumps(identity.collect(binding, app_compose), sort_keys=True))
        return 0
    except Exception:
        print("Issuer evidence collection failed; no verified issuer was established.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
