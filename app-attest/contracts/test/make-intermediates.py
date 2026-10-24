#!/usr/bin/env python3
from pathlib import Path
import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = Path(__file__).resolve().parents[1] / 'fixtures/rotation'
out.mkdir(parents=True, exist_ok=True)
root = ec.derive_private_key(7, ec.SECP384R1())
for i in (2, 3, 5):
    key = ec.derive_private_key(i, ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Rotation')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(i)
            .not_valid_before(datetime(2031 if i >= 4 else 2026, 1, i, tzinfo=timezone.utc))
            .not_valid_after(datetime(2033 if i >= 4 else 2029, 1, i, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(root, hashes.SHA384()))
    (out / f'ca{i}.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    if i == 2:
        reissued = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(22)
                    .not_valid_before(datetime(2026, 2, 1, tzinfo=timezone.utc))
                    .not_valid_after(datetime(2028, 1, 1, tzinfo=timezone.utc)))
        for ext in cert.extensions:
            reissued = reissued.add_extension(ext.value, ext.critical)
        (out / 'ca2-reissued.der').write_bytes(reissued.sign(root, hashes.SHA384()).public_bytes(serialization.Encoding.DER))

    fixture = json.loads((out.parent / ('real-apple.json' if i == 2 else 'fresh-apple.json')).read_text())
    leaf = x509.load_der_x509_certificate(bytes.fromhex(fixture['cert'].removeprefix('0x')))
    builder = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(name)
               .public_key(leaf.public_key()).serial_number(leaf.serial_number)
               .not_valid_before(datetime(2031, 2, 1, tzinfo=timezone.utc) if i >= 4 else leaf.not_valid_before)
               .not_valid_after(datetime(2032, 2, 1, tzinfo=timezone.utc) if i >= 4 else leaf.not_valid_after))
    for ext in leaf.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    (out / f'leaf{i}.der').write_bytes(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
