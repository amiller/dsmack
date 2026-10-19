"""Published independent vectors; historical enrollment is NOT a fresh attestation."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from verifier.core import Policy, Reject, b64, unb64, verify_assertion, verify_attestation
from verifier.server import ROOT

FIXTURES = Path(__file__).parent / 'fixtures'
APP = 'V8H6LQ9448.io.uebelacker.AppAttestExample'


def test_independent_enrollment():
    fixture = json.loads((FIXTURES / 'uebelack-development.json').read_text())
    result = verify_attestation(unb64(fixture['attestation']), fixture['keyId'], unb64(fixture['challenge']),
                               Policy(APP), ROOT.read_bytes(),
                               at_time=datetime(2024, 6, 1, tzinfo=timezone.utc).timestamp())
    assert result['receipt_status'] == 'retained_not_validated'


def test_independent_assertion():
    fixture = json.loads((FIXTURES / 'uebelack-assertion.json').read_text())
    key = serialization.load_pem_public_key(fixture['public_key_pem'].encode())
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    result = verify_assertion(unb64(fixture['assertion']), fixture['payload'].encode(), b64(point), 0, Policy(APP))
    assert result['counter'] == 1
    with pytest.raises(Reject):
        verify_assertion(unb64(fixture['assertion']), b'{}', b64(point), 0, Policy(APP))


def test_historical_enrollment_not_current():
    fixture = json.loads((FIXTURES / 'uebelack-development.json').read_text())
    with pytest.raises(Reject, match='certificate_chain_failed'):
        verify_attestation(unb64(fixture['attestation']), fixture['keyId'], unb64(fixture['challenge']),
                           Policy(APP), ROOT.read_bytes(),
                           at_time=datetime(2026, 9, 9, tzinfo=timezone.utc).timestamp())
