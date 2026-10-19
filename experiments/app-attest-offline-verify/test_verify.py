import base64, hashlib
from pathlib import Path
import pytest
from verify import verify

HERE = Path(__file__).parent
VECTOR = HERE / 'vectors' / 'mini-2026-09-16'
ROOT = (HERE / '../../trust/apple-app-attestation-root.pem').read_bytes()
APP = 'DC9JH5DRMY.dev.dsmack.provider'
ATT = (VECTOR / 'attestation.cbor').read_bytes()
KEY = base64.b64decode((VECTOR / 'keyId.txt').read_text().strip())
CDH = (VECTOR / 'clientDataHash.bin').read_bytes()


def test_genuine_attestation():
    result = verify(ATT, KEY, CDH, APP, ROOT)
    assert result['aaguid'] == 'appattest'
    assert CDH == hashlib.sha256((VECTOR / 'challenge.bin').read_bytes()).digest()


@pytest.mark.parametrize('field, kwargs', [
    ('nonce', dict(client_data_hash=hashlib.sha256(b'other challenge').digest())),
    ('key id', dict(key_id=bytes(32))),
    ('app id', dict(app_id='DC9JH5DRMY.dev.dsmack.other')),
])
def test_rejects(field, kwargs):
    args = dict(attestation=ATT, key_id=KEY, client_data_hash=CDH, app_id=APP, root_pem=ROOT) | kwargs
    with pytest.raises(AssertionError, match=field):
        verify(**args)


def test_rejects_other_root():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Apple App Attestation Root CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    fake = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=3650)).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA384()))
    with pytest.raises(Exception):
        verify(ATT, KEY, CDH, APP, fake.public_bytes(serialization.Encoding.PEM))
