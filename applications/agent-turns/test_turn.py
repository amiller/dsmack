"""testdata/ holds real outputs. personal-agent/: the keeper state from the two-turn spike of
25 October 2026 (worktree personal-agent-turns-20261025, 64d3bc6), without master.key.
finding/: find.py's fake-CLI run in the agent image, flattened to artifact names
(run-1/transcript.jsonl is run-1-transcript, finding.json is verdict). That run had no receipt,
so the finding test builds the receipt's commitment and artifact list over those files.
v02-turn/: the release-b7d1 run-v02 turn of 25 October 2026 (image b7d1a8a5): its request, artifacts,
the runner's launch files and compose-manifest.bin, and the runner key's enrollment."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import turn
from verifier.core import Reject

DATA = Path(__file__).parent/'testdata'
AGENT = DATA/'personal-agent'
V02 = DATA/'v02-turn'


def mac_turn(n):
    return turn.from_mac_compose(json.loads((AGENT/f'evidence-turn-{n}.json').read_bytes()),
                                 (AGENT/f'compose-turn-{n}.json').read_bytes(),
                                 (AGENT/'cdhash').read_text().strip(), AGENT)


class TurnTest(unittest.TestCase):
    def test_personal_agent_chain(self):
        turns = [mac_turn(1), mac_turn(2)]
        genesis = turns[0]['state_in']
        self.assertTrue((AGENT/genesis).is_file())
        head = turn.check_chain(turns, genesis)
        self.assertEqual(head, json.loads((AGENT/'head.json').read_bytes())['head'])

    def test_replayed_turn_breaks_chain(self):
        t1, t2 = mac_turn(1), mac_turn(2)
        with self.assertRaisesRegex(Reject, 'does not continue'):
            turn.check_chain([t1, t2, t2], t1['state_in'])

    def test_finding_is_one_stateless_turn(self):
        spec = json.loads((DATA/'finding'/'spec.json').read_bytes())
        request = {k: v for k, v in spec.items() if k != 'question'}
        request = turn.canonical(request | {'schema': 'dsmack-agent-turn/1', 'prompt': spec['question'], 'state_in': None})
        outputs = DATA/'finding'
        commitment = {'alg': turn.TASK_COMMITMENT_ALG, 'scope': turn.SCOPE}
        manifest_sha256 = '0'*64
        envelope = {'manifest_sha256': manifest_sha256, 'commitments': commitment,
                    'files': [{'slot': 'turn', 'content_base64': base64.b64encode(request).decode()}]}
        receipt = {'manifest_sha256': manifest_sha256, 'observed': {'services': []},
                   'runtime_inputs_commitment': commitment | {'inputs_sha256': turn.compute_commitment(envelope, {})},
                   'outputs': {'status': 'completed', 'artifacts': [
                       {'name': p.name, 'sha256': turn.sha(p.read_bytes())} for p in outputs.iterdir() if p.name != 'spec.json']}}
        t = turn.from_receipt(receipt, request, outputs)
        self.assertEqual((t['verdict'], t['state_in'], t['state_out'], len(t['transcripts'])), ('yes', None, None, 3))
        self.assertEqual(t['inputs_sha256'], spec['inputs_sha256'])
        self.assertIsNone(turn.check_chain([t]))
        with self.assertRaisesRegex(Reject, 'committed input'):
            turn.from_receipt(receipt, request.replace(b'unanimous', b'majority'), outputs)

    def test_guest_attest_needs_the_admitted_manifest(self):
        def check(manifest_sha256):
            return turn.from_guest_attest((V02/'artifacts/attestation').read_bytes(), (V02/'request.json').read_bytes(),
                                          V02/'artifacts', V02/'run', V02/'enrollment',
                                          '7011178cdb7a92bac0c28faa651ba54d20470a8057c569b2afe55dbf8b467970',
                                          'b7d1a8a5cb57e56bdd118540858c747861ce22b35190aec3e6e6d10a08dacda5', manifest_sha256)
        admitted = turn.sha((V02/'run/compose-manifest.bin').read_bytes())
        self.assertEqual(check(admitted)['manifest_sha256'], admitted)
        with self.assertRaisesRegex(Reject, 'not the admitted manifest'):
            check(turn.sha(b'another manifest'))


if __name__ == '__main__':
    unittest.main()
