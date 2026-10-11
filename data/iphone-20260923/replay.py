"""Offline replay of papi's iPhone App Attest session against CodeDirectory hashes recomputed from the IPAs."""
import argparse
import json
import sqlite3
import sys
import zipfile
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parents[1] / 'app/macos')]
from check_evidence import code_directory_hash, root  # noqa: E402
from verifier.core import Policy, Reject, unb64, verify_assertion, verify_attestation  # noqa: E402

APP_ID = 'DC9JH5DRMY.dev.dsmack.provider'
# (row, key label, running build, counter) as observed. Row 12 is the attack: honest-enrolled key E, modified code.
EXPECTED = [(1, 'A', 'honest', None), (2, 'A', 'honest', 1), (3, 'B', 'modified', None), (4, 'B', 'modified', 1),
            (5, 'B', 'honest', 2), (6, 'C', 'honest', None), (7, 'C', 'honest', 1), (8, 'D', 'modified', None),
            (9, 'D', 'modified', 1), (10, 'E', 'honest', None), (11, 'E', 'honest', 1),
            (12, 'E', 'modified', 2)]


def digest(variant):
    with zipfile.ZipFile(HERE / variant / 'export/AppAttestLab.ipa') as z:
        return code_directory_hash(z.read('Payload/AppAttestLab.app/AppAttestLab'))


def decide(fn, *args):
    try:
        fn(*args)
        return 'accept'
    except Reject as exc:
        return str(exc)


def replay(database, at_time):
    digests = {v: digest(v) for v in ('honest', 'modified')}
    assert digests['honest'] != digests['modified']
    identity = Policy(APP_ID, environment='production', categories=(5,))
    approved = replace(identity, cdhashes=(digests['honest'],))
    pem = root()
    con = sqlite3.connect(database)
    nonces = dict(con.execute('SELECT id, nonce FROM challenges'))
    rows = list(con.execute('SELECT id, endpoint, request_json FROM evidence ORDER BY id'))
    assert [r[0] for r in rows] == [e[0] for e in EXPECTED], 'unexpected evidence rows'
    keys, counters, results = {}, {}, []
    for (row, endpoint, request), (_, label, build, counter) in zip(rows, EXPECTED):
        body = json.loads(request)
        if endpoint == 'attestation':
            args = (unb64(body['attestation']), body['key_id'], unb64(nonces[body['challenge_id']]))
            verified = verify_attestation(*args, identity, pem, at_time)
            keys[label], counters[label] = verified['public_key'], 0
            decision = decide(verify_attestation, *args, approved, pem, at_time)
        else:
            args = (unb64(body['assertion']), unb64(body['client_data']), keys[label], counters[label])
            verified = verify_assertion(*args, identity)
            assert verified['counter'] == counter
            decision = decide(verify_assertion, *args, approved)
            counters[label] = verified['counter']
        cdhash = verified['signals']['cdhash']
        assert cdhash == digests[build].hex(), f'row {row}: attested cdhash is not the running build'
        assert decision == ('accept' if build == 'honest' else 'cdhash_policy_failed')
        results.append(dict(row=row, evidence=endpoint, key=label, running_build=build,
                            counter=verified.get('counter'), cdhash=cdhash, identity_only='accept',
                            approved_cdhash=decision, validation_category=verified['signals']['validation_category']))
    return dict(status='iphone_session_verified', verification_time=at_time or 'current',
                reference_cdhashes={k: v.hex() for k, v in digests.items()}, results=results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=HERE / 'captures/papi-20260923-snapshot.sqlite')
    parser.add_argument('--at-time', type=int, help='Explicit historical replay time; not fresh admission')
    args = parser.parse_args()
    print(json.dumps(replay(args.database, args.at_time), indent=2))
