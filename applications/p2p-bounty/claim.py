#!/usr/bin/env python3
"""Calldata for Bounty.claim from the result.json of a passing run.

python3 claim.py <result.json> <id>      prints the calldata; send it to the Bounty from any account
"""
import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_abi import encode

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "dstack-compat")]
import guest_attest  # noqa: E402
from verifier import core  # noqa: E402

SIG = "claim(uint256,address,bytes20,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes),bytes)"


def calldata(result, id_):
    assert result["passed"], "the check did not pass; there is nothing to claim"
    a = guest_attest.verify(bytes.fromhex(result["attestation"]))
    assert a["report_data"].hex() == result["report_data"]
    m = core.decode(a["assertion"])
    r, s = decode_dss_signature(m["signature"])
    proof = encode(["bytes32", "bytes", "uint256", "uint256"], [a["key_id"], m["authenticatorData"], r, s])
    args = encode(["uint256", "address", "bytes20", "(bytes32,bytes32,bytes32,bytes32,bytes32,bytes)", "bytes"],
                  [id_, result["payee"], bytes.fromhex(result["commit"]),
                   (a["os_image_hash"], a["manifest_sha256"], a["run"], a["head"], a["caller"], a["report_data"]), proof])
    return keccak.new(digest_bits=256, data=SIG.encode()).digest()[:4] + args


if __name__ == "__main__":
    print("0x" + calldata(json.loads(Path(sys.argv[1]).read_bytes()), int(sys.argv[2])).hex())
