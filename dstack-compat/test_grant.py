import hashlib
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from grant import SEAL_INFO, grant_request_client_data, seal

# Shared with the Swift WorkerGrant tests in marAttestTests: the app opens this sealed grant.
VECTOR = pathlib.Path(__file__).parent.parent / "runner-vm/control-src/Tests/marAttestTests/Fixtures/worker-grant-vector.json"
APP_KEY, EPH_KEY, NONCE = 0x5EA1, 0xE9E9, bytes(range(12))
GRANT = {"grant": json.dumps({"task_id": "t", "worker_id": "w", "chain": []}, sort_keys=True), "root_key": "77" * 32}


def pub(k):
    return ec.derive_private_key(k, ec.SECP256R1()).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def vector():
    sealed = seal(GRANT, pub(APP_KEY), ec.derive_private_key(EPH_KEY, ec.SECP256R1()), NONCE)
    return {"app_key": "%064x" % APP_KEY, "sealed": sealed, "root_key": GRANT["root_key"],
            "grant_sha256": hashlib.sha256(GRANT["grant"].encode()).hexdigest(),
            "request_client_data": grant_request_client_data(b"\x22" * 32, b"\x33" * 32, pub(APP_KEY), "t").hex()}


def test_vector_is_current_and_opens():
    v = json.loads(VECTOR.read_text())
    assert v == vector()
    s = v["sealed"]
    app = ec.derive_private_key(APP_KEY, ec.SECP256R1())
    epk = bytes.fromhex(s["epk"])
    shared = app.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk))
    key = HKDF(SHA256(), 32, None, SEAL_INFO + pub(APP_KEY) + epk).derive(shared)
    root = AESGCM(key).decrypt(bytes.fromhex(s["nonce"]), bytes.fromhex(s["ct"]), bytes.fromhex(v["grant_sha256"]))
    assert root.hex() == v["root_key"] and len(bytes.fromhex(v["request_client_data"])) == 160


if __name__ == "__main__":
    # Regenerate the shared vector: python3 test_grant.py
    VECTOR.write_text(json.dumps(vector(), indent=1, sort_keys=True) + "\n")
