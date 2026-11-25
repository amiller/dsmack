"""Calldata for the attest-nft example, as 0x hex for `cast send ADDRESS 0x...`.

python3 calldata.py enroll DIR INTERMEDIATE_ID   AppleAttestAnyBuildV1.enroll from the app's enroll output
python3 calldata.py claim DIR                    AttestNFT.claim from the app's claim output
"""
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_abi import encode
from eth_utils import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from verifier import core  # noqa: E402


def call(sig, types, values):
    return '0x' + (keccak(text=sig)[:4] + encode(types, values)).hex()


def enroll(d, intermediate_id):
    att = core.decode((d / 'attestation.cbor').read_bytes())
    return call('enroll(bytes,bytes,bytes,bytes32)', ['bytes', 'bytes', 'bytes', 'bytes32'],
                [att['attStmt']['x5c'][0], att['authData'], (d / 'clientData.bin').read_bytes(), bytes.fromhex(intermediate_id.removeprefix('0x'))])


def claim(d):
    m = core.decode((d / 'assertion.cbor').read_bytes())
    r, s = decode_dss_signature(m['signature'])
    kid = base64.b64decode((d / 'keyId.txt').read_text().strip(), validate=True)
    proof = encode(['bytes32', 'bytes', 'uint256', 'uint256'], [kid, m['authenticatorData'], r, s])
    c = json.loads((d / 'claim.json').read_bytes())
    return call('claim(address,bytes32,uint32,bytes32,bytes)', ['address', 'bytes32', 'uint32', 'bytes32', 'bytes'],
                [c['to'], bytes.fromhex(c['chip'][2:]), int(c['chipId'], 16), bytes.fromhex(c['device'][2:]), proof])


if __name__ == '__main__':
    d = Path(sys.argv[2])
    print(enroll(d, sys.argv[3]) if sys.argv[1] == 'enroll' else claim(d))
