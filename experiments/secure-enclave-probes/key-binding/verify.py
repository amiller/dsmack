"""Independently verify that binaries A and B signed under one SE key, for both the wrapped blob and the persistent key."""
import json
import sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

results = Path(sys.argv[1])
create, reopen = (json.loads((results / n).read_text()) for n in ('public-create.json', 'public-reopen.json'))
assert create['publicKeyX963'] == reopen['publicKeyX963']
key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(create['publicKeyX963']))
out = {'sameKey': True, 'vectors': []}
for name, doc in (('public-create.json', create), ('public-reopen.json', reopen)):
    for v in doc['vectors']:
        message = v['messageUTF8'].encode()
        key.verify(bytes.fromhex(v['signatureDER']), message, ec.ECDSA(hashes.SHA256()))
        wrong = message.replace(v['domain'].encode(), b'wrong.example.invalid')
        try:
            key.verify(bytes.fromhex(v['signatureDER']), wrong, ec.ECDSA(hashes.SHA256()))
            rejected = False
        except InvalidSignature:
            rejected = True
        assert rejected
        out['vectors'].append({'file': name, 'vector': v['id'], 'valid': True, 'wrongMessageRejected': rejected})
print(json.dumps(out, indent=2))

a, b = (json.loads((results / n).read_text()) for n in ('persistent-sep-A-signature.json', 'persistent-sep-B-signature.json'))
assert a['publicKeyX963'] == b['publicKeyX963']
sep = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(a['publicKeyX963']))
for s in (a, b):
    sep.verify(bytes.fromhex(s['signatureDER']), bytes.fromhex(s['messageHex']), ec.ECDSA(hashes.SHA256()))
print(json.dumps({'samePersistentSEPKeySignedByBoth': True, 'independentSignaturesVerified': 2}, indent=2))
