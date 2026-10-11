"""Independent public-transcript checks for a completed custody experiment."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_evidence import code_directory_hash, policy, root
from verifier.core import verify_attestation


def verify(folder, at_time=None):
    summary = json.loads((folder / 'summary.json').read_text())
    manifest = json.loads((folder / 'manifest.json').read_text())
    for name, digest in manifest.items():
        path = (folder / name).resolve()
        if not path.is_relative_to(folder.resolve()): raise ValueError('manifest path escape')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest: raise ValueError('manifest mismatch: ' + name)
    fields, digests, configs = {}, {}, {}
    for step in ('persist-store', 'persist-replaced', 'volatile-first', 'volatile-restart', 'volatile-modified'):
        capture = folder / step
        configs[step] = json.loads((folder / (step + '.config.json')).read_text())
        data = (capture / 'clientData.bin').read_bytes()
        fields[step] = json.loads(data)
        assert fields[step]['session'] == configs[step]['session']
        assert fields[step]['nonce'] == configs[step]['nonce']
        digests[step] = code_directory_hash((capture / 'probe').read_bytes())
        verify_attestation((capture / 'attestation.cbor').read_bytes(),
            (capture / 'keyId.txt').read_text(), data, policy(digests[step]), root(), at_time)
    assert digests['persist-store'] != digests['persist-replaced']
    assert digests['volatile-first'] == digests['volatile-restart'] != digests['volatile-modified']
    assert fields['volatile-first']['ephemeral_public_key'] != fields['volatile-restart']['ephemeral_public_key']
    assert fields['persist-store']['public_key'] == fields['persist-replaced']['public_key']
    persistent = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(fields['persist-store']['public_key']))
    for step in ('persist-store', 'persist-replaced'):
        persistent.verify((folder / step / 'signature.der').read_bytes(), configs[step]['nonce'].encode(), ec.ECDSA(hashes.SHA256()))
    category = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(summary['category_public_key']))
    authority = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(summary['authority_public_key']))
    # This probe embeds the authority as an ASCII Base64 constant. Check it is
    # in the page-hash-verified executable, rather than trusting summary metadata.
    for step in ('volatile-first', 'volatile-restart', 'volatile-modified'):
        assert summary['authority_public_key'].encode() in (folder / step / 'probe').read_bytes()
    for step, index in (('volatile-first', 1), ('volatile-restart', 2)):
        result = json.loads((folder / step / ('result-' + str(index) + '.json')).read_text())
        assert result['accepted'] and result['public_key'] == summary['category_public_key']
        category.verify(base64.b64decode(result['signature']), configs[step]['nonce'].encode(), ec.ECDSA(hashes.SHA256()))
        parcel = json.loads((folder / (step + '-parcel-' + str(index) + '.json')).read_text())
        signed = ('custody-parcel/v1.' + parcel['sender_public_key'] + '.' + parcel['ciphertext'] + '.' + fields[step]['session']).encode()
        authority.verify(base64.b64decode(parcel['authorization']), signed, ec.ECDSA(hashes.SHA256()))
    for step in ('volatile-restart', 'volatile-modified'):
        result = json.loads((folder / step / 'result-1.json').read_text())
        assert not result['accepted'] and not result['category_key_present']
        replay = json.loads((folder / (step + '-parcel-1.json')).read_text())
        original = json.loads((folder / 'volatile-first-parcel-1.json').read_text())
        assert replay['sender_public_key'] == original['sender_public_key']
        assert replay['ciphertext'] == original['ciphertext']
        if step == 'volatile-restart' and summary.get('old_ciphertext_reauthorized_for_new_session_still_rejected'):
            assert result['stage'] == 'transport_decryption'
            signed = ('custody-parcel/v1.' + replay['sender_public_key'] + '.' + replay['ciphertext'] + '.' + fields[step]['session']).encode()
            authority.verify(base64.b64decode(replay['authorization']), signed, ec.ECDSA(hashes.SHA256()))
        else:
            assert replay == original
    return {'status': 'public_transcript_verified', 'captures': 5,
            'persistent_replacement_signature': 'valid_under_original_key',
            'volatile_fresh_checkin_signature': 'valid_under_same_category_key',
            'restart_and_denied_release': 'recorded_lab_observations_not_cryptographic_erasure_proof'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--at-time', type=int)
    args = parser.parse_args()
    print(json.dumps(verify(args.folder, args.at_time), indent=2))
