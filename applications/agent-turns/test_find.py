import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import find

FAKE_CLI = '''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == '--version':
    print('2.1.187 (Claude Code)'); sys.exit()
mode = 'MODE'
model = 'claude-other' if mode == 'swap' else sys.argv[sys.argv.index('--model') + 1]
tool = 'Bash' if mode == 'bash' else 'Grep'
line = 99 if mode == 'badline' else 2
verdict = {'answer': 'yes', 'rationale': 'checked', 'citations': [{'path': 'src/a.py', 'line': line}]}
for event in [{'type': 'system', 'subtype': 'init', 'model': model},
              {'type': 'assistant', 'message': {'model': model, 'content': [{'type': 'tool_use', 'name': tool}]}},
              {'type': 'assistant', 'message': {'model': model, 'content': [{'type': 'text', 'text': 'x'}]}},
              {'type': 'result', 'subtype': 'success', 'is_error': False, 'num_turns': 2,
               'result': json.dumps(verdict)}]:
    print(json.dumps(event))
'''


class FindTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cli = self.tmp/'claude'
        self.inputs = self.tmp/'inputs'
        (self.inputs/'src').mkdir(parents=True)
        (self.inputs/'src'/'a.py').write_text('def f():\n    return 1\n')
        os.environ['DSMACK_SENTINEL_ENDPOINT'] = 'http://10.0.2.2:8100/tok'
        self.spec = {'schema': 'dsmack-agent-turn/1', 'prompt': 'Does f return 1?', 'state_in': None,
                     'answers': ['yes', 'no', 'unclear'], 'runs': 3, 'aggregate': 'unanimous',
                     'agent': {'cli_version': '2.1.187', 'cli_sha256': None,
                               'model': 'claude-opus-4-8', 'tools': ['Read', 'Grep', 'Glob'],
                               'max_turns': 20, 'wall_seconds': 30, 'settings': {'disableAllHooks': True}},
                     'inputs_sha256': find.tree_digest(self.inputs)}

    def run_mode(self, mode):
        self.cli.write_text(FAKE_CLI.replace('MODE', mode))
        self.cli.chmod(0o755)
        self.spec['agent']['cli_sha256'] = find.file_sha(self.cli)
        return find.run(self.spec, self.inputs, self.tmp/('out-' + mode), self.cli)

    def test_unanimous_finding(self):
        verdict = self.run_mode('ok')
        self.assertEqual((verdict['answer'], verdict['run_answers']), ('yes', ['yes']*3))
        self.assertEqual(verdict['observed_models'], ['claude-opus-4-8'])
        self.assertEqual(sorted(p.name for p in (self.tmp/'out-ok').iterdir()),
                         sorted(['verdict'] + [f'run-{n}-{k}' for n in (1, 2, 3) for k in ('transcript', 'stderr', 'verdict')]))

    def test_substituted_model_refused(self):
        with self.assertRaisesRegex(ValueError, 'model mismatch'):
            self.run_mode('swap')

    def test_tool_outside_allowlist_refused(self):
        with self.assertRaisesRegex(ValueError, 'Bash'):
            self.run_mode('bash')

    def test_fabricated_citation_refused(self):
        with self.assertRaisesRegex(ValueError, 'citation line'):
            self.run_mode('badline')

    def test_changed_inputs_refused(self):
        (self.inputs/'src'/'a.py').write_text('def f():\n    return 2\n')
        with self.assertRaisesRegex(ValueError, 'inputs digest'):
            self.run_mode('ok')

    def test_check_digest_ignores_inputs(self):
        other = self.spec | {'inputs_sha256': '0'*64, 'state_in': '1'*64}
        self.assertEqual(find.check_digest(self.spec), find.check_digest(other))

    def test_aggregation(self):
        self.assertIsNone(find.aggregate(['yes', 'no', 'yes'], 'unanimous'))
        self.assertEqual(find.aggregate(['yes', 'no', 'yes'], 'majority'), 'yes')


if __name__ == '__main__':
    unittest.main()
