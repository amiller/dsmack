"""Verify the six-step real-device experiment and its expected policy decisions."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
from check_evidence import code_directory_hash, policy, root
from verifier.core import Reject, verify_attestation, verify_assertion


def replay(base, at_time=None):
    captures = base / 'captures'
    digests = {step: code_directory_hash((captures / step / 'probe').read_bytes())
               for step in ('a-enroll', 'a-assert', 'b-old-key', 'b-enroll', 'b-assert', 'a-restored')}
    assert len({digests[x] for x in ('a-enroll', 'a-assert', 'a-restored')}) == 1
    assert len({digests[x] for x in ('b-enroll', 'b-assert', 'b-old-key')}) == 1
    assert digests['a-enroll'] != digests['b-enroll']
    approved = policy(digests['a-enroll'])
    pem = root()
    results, keys = [], {}

    def inputs(step):
        folder = captures / step
        data = (folder / 'clientData.bin').read_bytes()
        assert data == (base / (step + '.challenge')).read_bytes(), 'verifier challenge mismatch'
        return folder, data

    for step in ('a-enroll', 'b-enroll'):
        folder, data = inputs(step)
        raw = (folder / 'attestation.cbor').read_bytes()
        key_id = (folder / 'keyId.txt').read_text().strip()
        # Establish authentic evidence first, then evaluate the approved-code policy.
        verified = verify_attestation(raw, key_id, data, policy(digests[step]), pem, at_time)
        keys[step[0]] = (key_id, verified['public_key'])
        try:
            verify_attestation(raw, key_id, data, approved, pem, at_time)
            decision = 'accept'
        except Reject as exc:
            decision = str(exc)
        assert decision == ('accept' if step == 'a-enroll' else 'cdhash_policy_failed')
        results.append(dict(step=step, signature='valid_Apple_rooted', cdhash=digests[step].hex(), decision=decision))

    for step, key_name, previous, expected_counter in (
        ('a-assert', 'a', 0, 1), ('b-old-key', 'a', 1, 2),
        ('b-assert', 'b', 0, 1), ('a-restored', 'a', 2, 3)):
        folder, data = inputs(step)
        raw = (folder / 'assertion.cbor').read_bytes()
        key_id, public_key = keys[key_name]
        assert (folder / 'keyId.txt').read_text().strip() == key_id
        verified = verify_assertion(raw, data, public_key, previous, policy(digests[step]))
        assert verified['counter'] == expected_counter
        try:
            verify_assertion(raw, data, public_key, previous, approved)
            decision = 'accept'
        except Reject as exc:
            decision = str(exc)
        assert decision == ('accept' if step.startswith('a-') else 'cdhash_policy_failed')
        # An enrollment-only policy would accept this modified app's old-key signature.
        without_hash = verify_assertion(raw, data, public_key, previous, replace(approved, cdhashes=()))
        results.append(dict(step=step, signature='valid_enrolled_key', counter=verified['counter'],
            cdhash=digests[step].hex(), decision=decision,
            identity_only_policy='accept' if without_hash else 'reject'))
    return dict(status='six_step_hardware_experiment_verified',
                verification_time=at_time or 'current', results=results,
                membership_admission='not_implemented', iOS_cdhash='see_iphone-20260923',
                independent_developer_team='not_tested')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).parent / 'evidence-20260916')
    parser.add_argument('--at-time', type=int, help='Explicit historical replay time; not fresh admission')
    args = parser.parse_args()
    print(json.dumps(replay(args.evidence, args.at_time), indent=2, sort_keys=True))
