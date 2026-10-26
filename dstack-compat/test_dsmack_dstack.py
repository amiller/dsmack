import pytest

from dsmack_dstack import (get_key, grant_statement, kms_message, sign, verify_dstack_chain,
                           verify_worker_chain, derive)
from coincurve import PrivateKey

# docs/guest-api-v1.md test vectors: a shim key must equal the key dstack would derive.
ROOT = bytes.fromhex("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b")
VECTORS = [
    ("", "secp256k1", "59f60584ce6fd2a3a31997256db9d77322463fc8a6b1520110401bcb1ee92387",
     "0377c7fb050db181d392266a3cee9adb2901c6d665f11bac68be5457f577ba4908"),
    ("", "ed25519", "b023493030669cf22e9cafa6a464d4cf3ae4edfe5474ec796710f21ea011946d",
     "a3dc149fd5b765eab2eb7d3174fa939e39386898f10b15b7b146f6f1358ecf2a"),
    ("storage-encryption", "secp256k1", "5510330f86902ddae38c6d89c93a8408019332c17a429e1abd01c4a28d1544a6",
     "03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764"),
    ("k\0:ey", "ed25519", "42da8bf0b479ed125c370e3b91f982735bf08ff592abbd586985affa43ee96a1",
     "c833107822b003ff5675b33b90b151d4315c3ab9162b17d876e8dffde41abf9b"),
]
LINK0 = ("5b6193729ce7976ec67863f21692d4b98c69832698aae8e001a7d33a6f818b6e"
         "46ca950725b6e90e8ca9bcf394abd03ce264bf9b7eec1e91693247f9dd53c26901")


@pytest.mark.parametrize("domain,alg,priv,pub", VECTORS)
def test_kdf_matches_dstack(domain, alg, priv, pub):
    key, public = derive(ROOT, domain, alg)
    assert (key.hex(), public.hex()) == (priv, pub)


def test_link0_matches_dstack():
    assert get_key(ROOT, "storage-encryption", "secp256k1", [])["signature_chain"][0] == LINK0


def test_worker_chain_reaches_kms_root_and_is_not_a_coordinator_key():
    kms, app_root, app_id = b"\x01" * 32, b"\x02" * 32, b"\xaa" * 20
    app_pub = PrivateKey(app_root).public_key.format()
    link1 = sign(kms, kms_message(app_id, app_pub)).hex()
    signer = get_key(app_root, "dsmack-grant-signer/1", "secp256k1", [link1])
    scoped = derive(app_root, "dsmack-worker-root/1/t/w", "secp256k1")
    g = {"task_id": "t", "worker_id": "w", "compose_hash": "cd" * 32, "expires": 2000,
         "root_pub": scoped[1].hex(), "signer_domain": "dsmack-grant-signer/1"}
    tail = [sign(bytes.fromhex(signer["key"]), grant_statement(g)).hex()] + signer["signature_chain"]
    k = get_key(scoped[0], "worker-signing", "secp256k1", tail)
    pub, chain = bytes.fromhex(k["public_key"]), [bytes.fromhex(c) for c in k["signature_chain"]]
    kms_pub = PrivateKey(kms).public_key.format()
    assert verify_worker_chain(pub, chain, "worker-signing", "secp256k1", app_id, g, 1000) == kms_pub
    with pytest.raises(ValueError):
        verify_dstack_chain(pub, chain, "worker-signing", "secp256k1", app_id)
    with pytest.raises(ValueError, match="expired"):
        verify_worker_chain(pub, chain, "worker-signing", "secp256k1", app_id, g, 2000)


def test_stdlib_primitives_match_reference_libraries():
    # The guest has no crypto packages; its keccak and ECDSA must equal pycryptodome's and libsecp256k1's.
    import os
    from Crypto.Hash import keccak
    from coincurve import PublicKey
    from dsmack_dstack import keccak256, recover
    for n in (0, 1, 135, 136, 137, 300):
        m = os.urandom(n)
        assert keccak256(m) == keccak.new(digest_bits=256, data=m).digest()
    for _ in range(8):
        k, d = os.urandom(32), os.urandom(32)
        sig = sign(k, d)
        assert sig == PrivateKey(k).sign_recoverable(d, hasher=None)
        assert recover(sig, d) == PrivateKey(k).public_key.format() == PublicKey.from_signature_and_message(sig, d, hasher=None).format()
