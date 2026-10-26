"""Open a task secret that the release policy (secret_policy.mjs) sealed to the guest's secret-key.

Ephemeral-static P-256 ECDH, HKDF-SHA256 over info = INFO || epk || recipient || task id, then
AES-256-GCM. Stdlib plus the image's libcrypto, which supplies AES-GCM through ctypes.
"""
import ctypes
import hashlib
import hmac

from guest_attest import P256_P, p256_mul, p256_public

INFO = b"dsmack.secret-release/1"
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def hkdf(ikm, info):
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\1", hashlib.sha256).digest()


def aes_gcm_open(key, iv, ct):
    c = ctypes.CDLL("libcrypto.so.3")
    c.EVP_CIPHER_CTX_new.restype = c.EVP_aes_256_gcm.restype = ctypes.c_void_p
    c.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p] * 5
    c.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    c.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    c.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    c.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    if len(iv) != 12 or len(ct) < 16:
        raise ValueError("AES-GCM needs a 12-byte iv and a 16-byte tag")
    body, tag = ct[:-16], ct[-16:]
    out, n, fin = ctypes.create_string_buffer(len(body) + 16), ctypes.c_int(), ctypes.c_int()
    ctx = c.EVP_CIPHER_CTX_new()
    try:
        ok = (c.EVP_DecryptInit_ex(ctx, c.EVP_aes_256_gcm(), None, key, iv) == 1
              and c.EVP_DecryptUpdate(ctx, out, ctypes.byref(n), body, len(body)) == 1
              and c.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag) == 1  # EVP_CTRL_GCM_SET_TAG
              and c.EVP_DecryptFinal_ex(ctx, out, ctypes.byref(fin)) == 1)
    finally:
        c.EVP_CIPHER_CTX_free(ctx)
    if not ok:
        raise ValueError("secret does not open under this guest's secret-key")
    return out.raw[:n.value]


def open_secret(k, task_id, epk, iv, ct):
    """k is the guest's secret-key scalar; epk the policy's ephemeral public key x || y."""
    x, y = int.from_bytes(epk[:32], "big"), int.from_bytes(epk[32:], "big")
    # epk is network input: an off-curve point would make decryption an invalid-curve oracle on k.
    if len(epk) != 64 or x >= P256_P or y >= P256_P or (y * y - x ** 3 + 3 * x - P256_B) % P256_P:
        raise ValueError("epk is not a P-256 point")
    z = p256_mul(k, (x, y))[0].to_bytes(32, "big")
    return aes_gcm_open(hkdf(z, INFO + epk + p256_public(k) + task_id.encode()), iv, ct)
