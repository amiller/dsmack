"""dstack guest-api-v1 key derivation and the dsmack worker-grant chain.

A dsmack guest serves dstack's GetKey from a scoped root key that a dstack
coordinator app grants per (task, worker). The returned signature chain is
[link0 by scoped root, grant by coordinator signer, signer's dstack chain (2 links)],
so a Mac-derived key verifies to the dstack KMS root but never as the coordinator's own key.
"""
import struct
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Hash import keccak

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def lp(x):
    if isinstance(x, str):
        x = x.encode()
    return struct.pack(">I", len(x)) + x


def keccak256(b):
    return keccak.new(digest_bits=256, data=b).digest()


def derive(root, domain, algorithm):
    """dstack guest-api-v1 KDF (docs/guest-api-v1.md, "The KDF")."""
    if algorithm not in ("secp256k1", "ed25519"):
        raise ValueError("algorithm must be secp256k1 or ed25519")
    info = lp("dstack-guest-v1-key") + lp(algorithm) + lp(domain)
    key = HKDF(SHA256(), 32, b"dstack-guest-v1", info).derive(root)
    if algorithm == "secp256k1":
        if not 0 < int.from_bytes(key, "big") < N:
            raise ValueError("derived scalar out of range; choose another domain")
        return key, PrivateKey(key).public_key.format(compressed=True)
    pub = Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, pub


def key_claim(algorithm, domain, pub):
    return keccak256(lp("dstack-guest-v1-key-claim") + lp(algorithm) + lp(domain) + lp(pub))


def kms_message(app_id, app_root_pub):
    return keccak256(b"dstack-kms-issued:" + app_id + app_root_pub)


def grant_statement(g):
    return keccak256(lp("dsmack-worker-grant/1") + lp(g["task_id"]) + lp(g["worker_id"])
                     + lp(bytes.fromhex(g["compose_hash"])) + struct.pack(">Q", g["expires"])
                     + lp(bytes.fromhex(g["root_pub"])))


def sign(priv, digest):
    return PrivateKey(priv).sign_recoverable(digest, hasher=None)


def recover(sig, digest):
    if int.from_bytes(sig[32:64], "big") > N // 2:
        raise ValueError("high-S signature")
    return PublicKey.from_signature_and_message(sig, digest, hasher=None).format(compressed=True)


def get_key(root, domain, algorithm, tail):
    key, pub = derive(root, domain, algorithm)
    return {"key": key.hex(), "public_key": pub.hex(),
            "signature_chain": [sign(root, key_claim(algorithm, domain, pub)).hex()] + tail}


def verify_dstack_chain(pub, chain, domain, algorithm, app_id):
    """Steps 2-5 of "Verifying a chain"; returns the KMS root key the chain recovers to."""
    if len(chain) != 2:
        raise ValueError("dstack chain has %d links, expected 2" % len(chain))
    app_root = recover(chain[0], key_claim(algorithm, domain, pub))
    return recover(chain[1], kms_message(app_id, app_root))


def verify_worker_chain(pub, chain, domain, algorithm, app_id, grant, now):
    """Mac key -> grant -> coordinator signer -> KMS root. Returns the KMS root key."""
    if len(chain) != 4:
        raise ValueError("worker chain has %d links, expected 4" % len(chain))
    if now >= grant["expires"]:
        raise ValueError("grant expired")
    if recover(chain[0], key_claim(algorithm, domain, pub)).hex() != grant["root_pub"]:
        raise ValueError("link0 not signed by the granted root")
    signer = recover(chain[1], grant_statement(grant))
    return verify_dstack_chain(signer, chain[2:], grant["signer_domain"], "secp256k1", app_id)
