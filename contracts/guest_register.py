"""Calldata for GuestEscrow.registerGuestKey from a Layover guest's key attestation.

python3 contracts/guest_register.py <attestation hex>

The guest attests report_data = key || operator (each a left-padded 20-byte address) and writes
{address, operator, escrow, attestation} to its outputs (`guest-key`). Anyone may submit the calldata:
cast send $ESCROW <calldata>. The Mac's App Attest key must be enrolled in the escrow's verifier (`attest()`).
"""
import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_abi import encode
from eth_utils import to_checksum_address

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "dstack-compat")]
import guest_attest  # noqa: E402
from verifier import core  # noqa: E402

SIG = "registerGuestKey(address,address,(bytes32,bytes32,bytes32,bytes32),(string,bytes)[],bytes)"


def calldata(attestation):
    a = guest_attest.verify(attestation)
    rd = a["report_data"]
    if len(rd) != 64 or any(rd[:12]) or any(rd[32:44]):
        raise ValueError("report_data is not key || operator (two left-padded addresses)")
    key, operator = to_checksum_address(rd[12:32]), to_checksum_address(rd[44:64])
    m = core.decode(a["assertion"])
    r, s = decode_dss_signature(m["signature"])
    proof = encode(["bytes32", "bytes", "uint256", "uint256"], [a["key_id"], m["authenticatorData"], r, s])
    events = a["system_events"] + [(guest_attest.SYSTEM_READY, b"")]
    args = encode(["address", "address", "(bytes32,bytes32,bytes32,bytes32)", "(string,bytes)[]", "bytes"],
                  [key, operator, (a["os_image_hash"], a["manifest_sha256"], a["run"], a["caller"]), events, proof])
    return keccak.new(digest_bits=256, data=SIG.encode()).digest()[:4] + args, key, operator, a


if __name__ == "__main__":
    data, key, operator, a = calldata(bytes.fromhex(sys.argv[1]))
    print(json.dumps({"calldata": "0x" + data.hex(), "key": key, "operator": operator, "kid": "0x" + a["key_id"].hex(),
                      "image": "0x" + a["os_image_hash"].hex(), "manifest": "0x" + a["manifest_sha256"].hex(),
                      "caller": "0x" + a["caller"].hex(), "client_data_hash": "0x" + a["client_data_hash"].hex()}))
