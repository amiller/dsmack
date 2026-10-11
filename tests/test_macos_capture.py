"""Historical real Apple capture plus adversarial modifications of its evidence."""
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sys

import cbor2
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app/macos'))
from check_evidence import code_directory_hash, policy, root
from verifier.core import CBOR, Reject, verify_attestation
from test_verifier import Rig

DATA = Path(__file__).resolve().parents[1] / 'app/macos/evidence-20260916/original'
AT_TIME = int(datetime(2026, 9, 16, 14, 0, tzinfo=timezone.utc).timestamp())
DIGEST = bytes.fromhex('e7009ad9e7bea17cbaf40d94d0779d14217f56617160711c7fef37abc23382ed')


def check(raw=None, key=None, challenge=None, accepted=None):
    return verify_attestation(raw or (DATA / 'attestation.cbor').read_bytes(),
        key or (DATA / 'keyId.txt').read_text().strip(),
        challenge or (DATA / 'challenge.bin').read_bytes(), accepted or policy(DIGEST), root(), AT_TIME)


def test_real_capture_complete_binding_and_acl():
    assert code_directory_hash((DATA / 'probe').read_bytes()) == DIGEST
    assert check()['signals']['cdhash'] == DIGEST.hex()


def test_different_expected_binary_rejected():
    with pytest.raises(Reject, match='cdhash_policy_failed'):
        check(accepted=policy(bytes(32)))


def test_mac_validation_category_is_enforced():
    # The real capture reports category 3, so the default Mac policy accepts it.
    assert check()['signals']['validation_category'] == 3
    # A policy demanding any other category rejects the same authentic evidence,
    # proving the Mac category is an enforced admission requirement, not just parsed.
    with pytest.raises(Reject, match='category_policy_failed'):
        check(accepted=replace(policy(DIGEST), categories=(4,)))


def test_altered_executable_page_rejected():
    binary = bytearray((DATA / 'probe').read_bytes())
    binary[4096] ^= 1
    with pytest.raises(ValueError, match='code page hash mismatch'):
        code_directory_hash(bytes(binary))


def test_wrong_fresh_challenge_rejected():
    with pytest.raises(Reject, match='attestation_nonce_mismatch'):
        check(challenge=b'different verifier challenge')


def test_wrong_app_identity_rejected():
    with pytest.raises(Reject, match='wrong_app_id'):
        check(accepted=replace(policy(DIGEST), app_id='OTHERTEAM0.dev.dsmack.provider'))


def test_tampered_cdhash_cannot_be_made_valid_by_changing_allowlist():
    obj = cbor2.loads((DATA / 'attestation.cbor').read_bytes())
    auth = obj['authData']
    parser = CBOR(auth[87:]); parser.read()
    offset = 87 + parser.pos
    extensions = cbor2.loads(auth[offset:])
    extensions['apple_cd_hash_hash_01'] = bytes(32)
    obj['authData'] = auth[:offset] + cbor2.dumps(extensions)
    with pytest.raises(Reject, match='attestation_nonce_mismatch'):
        check(raw=cbor2.dumps(obj), accepted=policy(bytes(32)))


def test_supplied_untrusted_intermediate_is_not_a_trust_anchor():
    rig = Rig()
    fake = rig.attestation(b'challenge')
    with pytest.raises(Reject, match='certificate_chain_failed'):
        check(raw=fake, key=rig.key_id, challenge=b'challenge')


def test_mac_requires_acl_even_with_otherwise_valid_synthetic_chain():
    rig = Rig()
    from verifier.core import Policy
    with pytest.raises(Reject, match='missing_macos_acl'):
        verify_attestation(rig.attestation(b'challenge'), rig.key_id, b'challenge',
            Policy('TESTTEAM01.org.example.AppAttestLab', require_macos_acl=True), rig.root_pem)


def test_real_six_step_substitution_and_restoration():
    from replay_matrix import replay
    result = replay(DATA.parent, AT_TIME)
    old_key = next(x for x in result['results'] if x['step'] == 'b-old-key')
    assert old_key['signature'] == 'valid_enrolled_key'
    assert old_key['decision'] == 'cdhash_policy_failed'
    assert old_key['identity_only_policy'] == 'accept'


def test_mac_policy_persists_without_silent_allowlist_change(tmp_path):
    from verifier.server import create_app
    database = tmp_path / 'mac.sqlite'
    app = create_app(policy(DIGEST), database)
    assert app.test_client().get('/health').json['policy']['cdhashes'] == [DIGEST.hex()]
    create_app(policy(DIGEST), database)
    with pytest.raises(Reject, match='database_policy_mismatch'):
        create_app(policy(bytes(32)), database)


@pytest.mark.parametrize('mutation', ['challenge', 'counter', 'signature', 'cdhash'])
def test_real_assertion_adversarial_inputs(mutation):
    from verifier.core import verify_assertion
    captures = DATA.parent / 'captures'
    enrollment = captures / 'a-enroll'
    digest = code_directory_hash((enrollment / 'probe').read_bytes())
    approved = policy(digest)
    verified = verify_attestation((enrollment / 'attestation.cbor').read_bytes(),
        (enrollment / 'keyId.txt').read_text().strip(), (enrollment / 'clientData.bin').read_bytes(),
        approved, root(), AT_TIME)
    folder = captures / 'a-assert'
    obj = cbor2.loads((folder / 'assertion.cbor').read_bytes())
    data, previous = (folder / 'clientData.bin').read_bytes(), 0
    if mutation == 'challenge':
        data = b'wrong challenge'
    elif mutation == 'counter':
        previous = 1
    elif mutation == 'signature':
        signature = bytearray(obj['signature']); signature[-1] ^= 1
        obj['signature'] = bytes(signature)
    else:
        auth = obj['authenticatorData']
        extensions = cbor2.loads(auth[37:])
        extensions['apple_cd_hash_hash_01'] = bytes(32)
        obj['authenticatorData'] = auth[:37] + cbor2.dumps(extensions)
        # Even allowing the attacker-selected digest cannot repair the signature.
        approved = policy(bytes(32))
    with pytest.raises(Reject, match='counter_replay' if mutation == 'counter' else 'invalid_assertion_signature'):
        verify_assertion(cbor2.dumps(obj), data, verified['public_key'], previous, approved)
