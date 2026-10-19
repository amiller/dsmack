"""Open a recorded KMS /release body with a P-256 key other than the runner's eph key; AES-GCM must reject it.
usage: parcel_wrong_key.py BODY.json clientData.bin"""
import base64, hashlib, json, sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

body = json.loads(open(sys.argv[1], 'rb').read())
assert set(body) == {'epk', 'sealed'}, f'unexpected fields {sorted(body)}'
epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(body['epk']))
aead = HKDF(hashes.SHA256(), 32, None, b'mac-compose-key-release/1').derive(ec.generate_private_key(ec.SECP256R1()).exchange(ec.ECDH(), epk))
sealed = base64.b64decode(body['sealed'])
try:
    AESGCM(aead).decrypt(sealed[:12], sealed[12:], hashlib.sha256(open(sys.argv[2], 'rb').read()).digest())
    sys.exit('decrypted with the wrong key')
except InvalidTag:
    print('wrong key: InvalidTag')
