"""Calldata for Canary.claimKey from a guest Attest attestation and a canary private key.

python3 contracts/canary_claim.py <attestation hex> <key hex> <claimant> <id> <canary> <chainid>

<attestation hex> is the `attestation` the canary workload wrote to its outputs; <key hex>
the 32-byte P-256 scalar of the canary key (canary-guest-key or canary-runner-key), which
only a broken boundary yields.
"""
import hashlib
import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from eth_abi import encode

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "dstack-compat")]
import guest_attest  # noqa: E402
from verifier import core  # noqa: E402

SIG = "claimKey(uint256,address,(bytes32,bytes32,bytes32,bytes32,bytes),(string,bytes)[],bytes,bytes32,bytes32)"


def claim_digest(chainid, canary, id_, claimant):
    return hashlib.sha256(b"dsmack.canary.claim/1" + chainid.to_bytes(32, "big") + bytes.fromhex(canary[2:])
                          + id_.to_bytes(32, "big") + bytes.fromhex(claimant[2:])).digest()


def calldata(attestation, key, claimant, id_, canary, chainid):
    a = guest_attest.verify(attestation)
    m = core.decode(a["assertion"])
    r, s = decode_dss_signature(m["signature"])
    proof = encode(["bytes32", "bytes", "uint256", "uint256"], [a["key_id"], m["authenticatorData"], r, s])
    sk = ec.derive_private_key(key, ec.SECP256R1())
    kr, ks = decode_dss_signature(sk.sign(claim_digest(chainid, canary, id_, claimant), ec.ECDSA(Prehashed(hashes.SHA256()))))
    events = a["system_events"] + [(guest_attest.SYSTEM_READY, b"")]
    args = encode(["uint256", "address", "(bytes32,bytes32,bytes32,bytes32,bytes)", "(string,bytes)[]", "bytes", "bytes32", "bytes32"],
                  [id_, claimant, (a["os_image_hash"], a["manifest_sha256"], a["run"], a["caller"], a["report_data"]),
                   events, proof, kr.to_bytes(32, "big"), ks.to_bytes(32, "big")])
    return keccak.new(digest_bits=256, data=SIG.encode()).digest()[:4] + args, a


if __name__ == "__main__":
    att, key, claimant, id_, canary, chainid = sys.argv[1:]
    data, a = calldata(bytes.fromhex(att), int(key, 16), claimant, int(id_), canary, int(chainid))
    print(json.dumps({"calldata": "0x" + data.hex(), "client_data_hash": a["client_data_hash"].hex(),
                      "events": [[n, p.hex()] for n, p in a["system_events"]]}))
