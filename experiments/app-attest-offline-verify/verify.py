"""Verify an Apple App Attest attestation offline, in the five steps Apple documents."""
import base64, hashlib, sys
from pathlib import Path
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ObjectIdentifier

NONCE_OID = ObjectIdentifier('1.2.840.113635.100.8.2')


def verify(attestation, key_id, client_data_hash, app_id, root_pem):
    att = cbor2.loads(attestation)
    assert att['fmt'] == 'apple-appattest', 'format'
    leaf, intermediate = (x509.load_der_x509_certificate(c) for c in att['attStmt']['x5c'])
    root = x509.load_pem_x509_certificate(root_pem)
    intermediate.verify_directly_issued_by(root)
    leaf.verify_directly_issued_by(intermediate)
    issued = leaf.not_valid_before_utc
    for cert in (leaf, intermediate, root):
        assert cert.not_valid_before_utc <= issued <= cert.not_valid_after_utc, 'validity'
    auth = att['authData']
    nonce = hashlib.sha256(auth + client_data_hash).digest()
    assert leaf.extensions.get_extension_for_oid(NONCE_OID).value.value.endswith(nonce), 'nonce'
    public = leaf.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert hashlib.sha256(public).digest() == key_id, 'key id'
    assert auth[:32] == hashlib.sha256(app_id.encode()).digest(), 'app id'
    counter, aaguid = int.from_bytes(auth[33:37], 'big'), auth[37:53]
    length = int.from_bytes(auth[53:55], 'big')
    assert counter == 0, 'counter'
    assert auth[55:55 + length] == key_id, 'credential id'
    return {'issued': issued.isoformat(), 'aaguid': aaguid.rstrip(b'\0').decode(), 'public_key': public.hex()}


if __name__ == '__main__':
    vector, app_id, root = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    print(verify((vector / 'attestation.cbor').read_bytes(), base64.b64decode((vector / 'keyId.txt').read_text().strip()),
                 (vector / 'clientDataHash.bin').read_bytes(), app_id, root.read_bytes()))
