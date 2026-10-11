"""Real Mac custody transcripts; historical replay, not fresh admission."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import pytest

CUSTODY = Path(__file__).resolve().parents[1] / 'app/macos/custody'
sys.path.insert(0, str(CUSTODY))
from verify_evidence import verify
from verifier.core import Reject

DATA = CUSTODY / 'custody-20260916T173508Z'
AT_TIME = 1789581600


def update_manifest(folder, name):
    path = folder / 'manifest.json'
    obj = json.loads(path.read_text())
    obj[name] = hashlib.sha256((folder / name).read_bytes()).hexdigest()
    path.write_text(json.dumps(obj))


def test_real_custody_transcripts():
    result = verify(DATA, AT_TIME)
    assert result['persistent_replacement_signature'] == 'valid_under_original_key'
    assert result['volatile_fresh_checkin_signature'] == 'valid_under_same_category_key'
    failure = json.loads((DATA / 'volatile-restart/result-1.json').read_text())
    assert failure['stage'] == 'transport_decryption'
    assert failure['category_key_present'] is False


def test_receiver_key_substitution_breaks_attestation(tmp_path):
    folder = tmp_path / 'evidence'; shutil.copytree(DATA, folder)
    name = 'volatile-restart/clientData.bin'
    obj = json.loads((folder / name).read_bytes())
    obj['ephemeral_public_key'] = json.loads((DATA / 'volatile-first/clientData.bin').read_bytes())['ephemeral_public_key']
    (folder / name).write_text(json.dumps(obj, sort_keys=True))
    update_manifest(folder, name)
    with pytest.raises(Reject, match='attestation_nonce_mismatch'):
        verify(folder, AT_TIME)


def test_different_claimed_network_authority_is_not_accepted(tmp_path):
    folder = tmp_path / 'evidence'; shutil.copytree(DATA, folder)
    name = 'summary.json'
    summary = json.loads((folder / name).read_text())
    summary['authority_public_key'] = summary['category_public_key']
    (folder / name).write_text(json.dumps(summary))
    update_manifest(folder, name)
    with pytest.raises(AssertionError):
        verify(folder, AT_TIME)
