"""personal-agent/: the turn's state chain and commit signature, and that its manifest passes the runner's contract."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

import pytest
from cryptography.exceptions import InvalidTag

HERE = Path(__file__).parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE/'personal-agent'), str(HERE/'personal-agent/guest'), str(ROOT/'dstack-compat'),
                str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib')]
import agent_turn as turn
import workload
from dsmack_dstack import recover, secp256k1_public
from dsmack_compose_contract.manifest import validate_manifest_bytes

SECRET = bytes(range(32))
AT = ('31337', '0x' + '00'*18 + '7e4d')


def test_two_turns_chain_and_sign_as_the_agent():
    blob1, c1 = turn.step(SECRET, *AT, 0, '00'*32, b'')
    blob2, c2 = turn.step(SECRET, *AT, 1, c1['state_out'], blob1)
    assert (c2['turn'], c2['state_in']) == (1, c1['state_out'])
    key, agent = turn.agent_key(SECRET)
    assert c1['agent'] == c2['agent'] == agent
    sig = bytes.fromhex(c2['r'] + c2['s']) + bytes([c2['v'] - 27])
    assert recover(sig, turn.digest(*AT, 1, c2['state_in'], c2['state_out'])) == secp256k1_public(key)
    _, c3 = turn.step(SECRET, *AT, 2, c2['state_out'], blob2)
    assert c3['turn'] == 2


def test_blob_that_is_not_the_head_is_refused():
    blob1, c1 = turn.step(SECRET, *AT, 0, '00'*32, b'')
    with pytest.raises(AssertionError, match='does not match the head'):
        turn.step(SECRET, *AT, 1, '11'*32, blob1)


# The state opens only under the agent's secret, which only its attested turns get.
def test_state_does_not_open_under_another_secret():
    blob1, c1 = turn.step(SECRET, *AT, 0, '00'*32, b'')
    with pytest.raises(InvalidTag):
        turn.step(bytes(32), *AT, 1, c1['state_out'], blob1)


def test_manifest_passes_the_compose_contract(tmp_path):
    layout = tmp_path/'oci-layout'
    (layout/'blobs/sha256').mkdir(parents=True)

    def blob(raw):
        d = hashlib.sha256(raw).hexdigest()
        (layout/'blobs/sha256'/d).write_bytes(raw)
        return 'sha256:' + d
    tar_raw = io.BytesIO()
    with tarfile.open(fileobj=tar_raw, mode='w') as tar:
        info = tarfile.TarInfo('usr/bin/python3.12')
        info.size = 6
        tar.addfile(info, io.BytesIO(b'python'))
    top = blob(json.dumps({'layers': [{'digest': blob(gzip.compress(tar_raw.getvalue()))}]}).encode())
    (layout/'index.json').write_text(json.dumps({'manifests': [{'digest': top}]}))
    template = tmp_path/'canary.json'
    template.write_bytes((HERE/'testdata/v02-turn/run/compose-manifest.bin').read_bytes())
    mb = workload.manifest(template, layout, 'personal-agent/a', 'http://192.168.127.254:8787', 'http://192.168.127.254:8788',
                           AT[1], '84532')
    validate_manifest_bytes(mb)
    m = json.loads(mb)
    assert m['harness']['sha256'] == hashlib.sha256(b'python').hexdigest()
    assert json.loads(m['docker_compose_file'])['services']['turn']['image'].endswith('@' + top)
