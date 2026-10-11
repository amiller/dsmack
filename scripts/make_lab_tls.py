#!/usr/bin/env python3
"""Create an isolated lab TLS CA + server certificate, never an attestation CA."""
import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path)
parser.add_argument('--host', action='append', default=['localhost'])
args = parser.parse_args()
os.umask(0o077)
args.directory.mkdir(parents=True, exist_ok=True)
if any(args.directory.iterdir()):
    parser.error('use an empty directory; existing TLS identities are never overwritten')
now = datetime.now(timezone.utc)
issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'App Attest Lab TLS CA')])
root_key = ec.generate_private_key(ec.SECP256R1())
root = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True)
        .sign(root_key, hashes.SHA256()))
key = ec.generate_private_key(ec.SECP256R1())
names = []
for host in args.host:
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        names.append(x509.DNSName(host))
leaf = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host[0])]))
        .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
        .sign(root_key, hashes.SHA256()))
for name, cert in [('ca', root), ('server', leaf)]:
    (args.directory / f'{name}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
for name, private in [('ca', root_key), ('server', key)]:
    (args.directory / f'{name}.key').write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print(f'TLS-only CA SHA256: {root.fingerprint(hashes.SHA256()).hex()}')
