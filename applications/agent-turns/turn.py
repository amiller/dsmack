"""Read agent turns from execution evidence and check that they form a chain (README.md).

from_receipt takes a compose receipt v4 that the run-result verifier already accepted.
from_mac_compose takes the mac-compose runner's /attest evidence, checks it itself, and finds the
state blob by its hash in a content-addressed directory.
from_guest_attest takes the `attestation` a v0.2 guest made with /v1/Attest and checks it itself.
"""
import base64
import hashlib
import json
from pathlib import Path
import sys

from cryptography import x509

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib'), str(ROOT/'dstack-compat'),
                str(Path(__file__).resolve().parent)]
from dsmack_compose_contract.runtime_inputs import TASK_COMMITMENT_ALG, compute_commitment
import find
import guest_attest
from verifier.core import decode, require, unb64, unique_json, verify_assertion, verify_attestation
from verifier.macos_policy import policy, root

SCOPE = {'include': ['files'], 'file_slots': ['turn']}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bound_artifacts(receipt, outputs):
    artifacts = {a['name']: a['sha256'] for a in receipt['outputs']['artifacts']}
    for name, digest in artifacts.items():
        require(sha((outputs/name).read_bytes()) == digest, 'artifact does not match the receipt: ' + name)
    return artifacts


def from_receipt(receipt, request_bytes, outputs):
    commitment = receipt['runtime_inputs_commitment']
    require(commitment['alg'] == TASK_COMMITMENT_ALG and commitment['scope'] == SCOPE,
            'the commitment must cover exactly the turn request')
    envelope = {'manifest_sha256': receipt['manifest_sha256'], 'commitments': commitment,
                'files': [{'slot': 'turn', 'content_base64': base64.b64encode(request_bytes).decode()}]}
    require(compute_commitment(envelope, {}) == commitment['inputs_sha256'], 'request is not the committed input')
    require(receipt['outputs']['status'] == 'completed', 'run did not complete')
    artifacts = bound_artifacts(receipt, outputs)
    request = json.loads(request_bytes)
    require(request['schema'] == 'dsmack-agent-turn/1', 'not a turn request')
    verdict = json.loads((outputs/'verdict').read_bytes())['answer'] if 'verdict' in artifacts else None
    return {'agent_sha256': sha(canonical(request['agent'])), 'manifest_sha256': receipt['manifest_sha256'],
            'images': sorted(s['resolved_manifest_digest'] for s in receipt['observed']['services']),
            'commitment': commitment['inputs_sha256'], 'inputs_sha256': request['inputs_sha256'],
            'prompt_sha256': sha(request['prompt'].encode()), 'state_in': request['state_in'],
            'state_out': artifacts.get('state'), 'outputs': artifacts,
            'transcripts': [artifacts[n] for n in sorted(artifacts) if n.endswith('-transcript')],
            'verdict': verdict,
            'dashcam': (outputs/'dashcam-head').read_text().strip() if 'dashcam-head' in artifacts else None}


def from_mac_compose(evidence, compose_bytes, cdhash, blobs):
    boot, signed = unb64(evidence['bootClientData']), unb64(evidence['assertClientData'])
    enroll, assertion = unique_json(boot), unique_json(signed)
    rule = policy(bytes.fromhex(cdhash))
    key = verify_attestation(unb64(evidence['attestation']), evidence['keyId'], boot, rule, root(),
                             at_time=enroll['enrolled_at'])['public_key']
    verify_assertion(unb64(evidence['assertion']), signed, key, 0, rule)
    compose_hash = sha(compose_bytes)
    require(assertion['domain'] == 'mac-compose-assert/1'
            and enroll['compose_hash'] == assertion['compose_hash'] == compose_hash, 'evidence is not for this compose')
    transition = json.loads(assertion['data'])
    service, = json.loads(json.loads(compose_bytes)['docker_compose_file'])['services'].values()
    require(service['environment']['STATE_IN'] == transition['state_in'], 'compose does not commit state_in')
    require(sha((blobs/transition['state_out']).read_bytes()) == transition['state_out'], 'state blob does not match state_out')
    return {'agent_sha256': None, 'manifest_sha256': compose_hash, 'images': [service['image']],
            'commitment': compose_hash, 'inputs_sha256': None, 'prompt_sha256': None,
            'state_in': transition['state_in'], 'state_out': transition['state_out'],
            'outputs': {'state': transition['state_out']}, 'transcripts': [], 'verdict': None, 'dashcam': None}


def from_guest_attest(blob, request_bytes, outputs, run, enrollment, cdhash, os_image_hash):
    """Check the turn's guest Attest: the App Attest key and launch, the sealed event log and report_data.

    run holds the runner's launch-client-data.bin, launch-assertion.cbor and compose-manifest.bin;
    enrollment holds the key's attestation.cbor, clientData.bin and keyId.txt.
    """
    a = guest_attest.verify(blob)
    rule = policy(bytes.fromhex(cdhash))
    attestation = (enrollment/'attestation.cbor').read_bytes()
    key_id = (enrollment/'keyId.txt').read_text().strip()
    leaf = x509.load_der_x509_certificate(decode(attestation)['attStmt']['x5c'][0])
    key = verify_attestation(attestation, key_id, (enrollment/'clientData.bin').read_bytes(), rule, root(),
                             at_time=leaf.not_valid_before_utc.timestamp() + 60)['public_key']
    require(a['key_id'] == unb64(key_id), 'Attest key is not the enrolled key')
    signed = verify_assertion(a['assertion'], guest_attest.client_data(a['os_image_hash'], a['manifest_sha256'], a['run'],
                              a['head'], a['caller'], a['report_data']), key, 0, rule)
    launch_data = (run/'launch-client-data.bin').read_bytes()
    launch = verify_assertion((run/'launch-assertion.cbor').read_bytes(), launch_data, key, signed['counter'], rule)
    compose = (run/'compose-manifest.bin').read_bytes()
    require(a['run'] == hashlib.sha256(launch_data).digest(), 'Attest is not from this launch')
    require(a['manifest_sha256'].hex() == sha(compose) and a['os_image_hash'].hex() == os_image_hash,
            'Attest is not for this compose and image')
    service, = json.loads(json.loads(compose)['docker_compose_file'])['services']
    require(a['caller'] == hashlib.sha256(service.encode()).digest(), 'Attest caller is not the workload service')
    require(a['report_data'] == find.report(request_bytes, outputs).ljust(64, b'\0'), 'report_data does not bind these results')
    request = json.loads(request_bytes)
    require(request['schema'] == 'dsmack-agent-turn/1', 'not a turn request')
    names = ['patch', 'verdict', 'state', *sorted(p.name for p in outputs.glob('run-*-transcript'))]
    artifacts = {n: sha((outputs/n).read_bytes()) for n in names if (outputs/n).exists()}
    head = outputs/'dashcam-head'
    return {'agent_sha256': sha(canonical(request['agent'])), 'manifest_sha256': sha(compose),
            'images': [json.loads(json.loads(compose)['docker_compose_file'])['services'][service]['image']],
            'commitment': None, 'inputs_sha256': request['inputs_sha256'],
            'prompt_sha256': sha(request['prompt'].encode()), 'state_in': request['state_in'],
            'state_out': artifacts.get('state'), 'outputs': artifacts,
            'transcripts': [artifacts[n] for n in names if n.endswith('-transcript')],
            'verdict': json.loads((outputs/'verdict').read_bytes())['answer'] if 'verdict' in artifacts else None,
            'dashcam': head.read_text().strip() if head.exists() else None,
            'attest': {'head': a['head'].hex(), 'events': [[n, p.hex()] for n, p in a['system_events']],
                       'counter': signed['counter'], 'launch_counter': launch['counter']}}


def check_chain(turns, genesis=None):
    """Each turn starts from the previous turn's state_out. Returns the head."""
    require(turns[0]['state_in'] == genesis, 'first turn does not start at genesis')
    for previous, turn in zip(turns, turns[1:]):
        require(previous['state_out'] is not None and turn['state_in'] == previous['state_out'],
                'turn does not continue from the previous state')
    return turns[-1]['state_out']
