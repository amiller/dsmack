import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import find

FAKE_CLI = '''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == '--version':
    print('2.1.187 (Claude Code)'); sys.exit()
mode = 'MODE'
if mode == 'oauth':
    assert os.environ.get('CLAUDE_CODE_OAUTH_TOKEN') == 'tok'
    assert 'ANTHROPIC_AUTH_TOKEN' not in os.environ
if mode == 'direct-oauth':
    assert os.environ['CLAUDE_CODE_OAUTH_TOKEN'] == 'DUMMY-INFERENCE'
    assert os.environ['ANTHROPIC_BASE_URL'] == 'https://api.anthropic.com'
    assert os.environ['HTTPS_PROXY'] == 'http://192.0.2.3:18443'
    assert 'ANTHROPIC_AUTH_TOKEN' not in os.environ
model = 'claude-other' if mode == 'swap' else sys.argv[sys.argv.index('--model') + 1]
tool = {'bash': 'Bash', 'edit': 'Edit'}.get(mode, 'Grep')
if mode == 'edit':
    with open('src/a.py') as f: text = f.read()
    with open('src/a.py', 'w') as f: f.write(text.replace('return 1', 'return 2'))
    with open('NOTES.md', 'w') as f: f.write('f returns 2\\n')
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
                         sorted(['verdict'] + [f'run-{n}-{k}' for n in (1, 2, 3) for k in ('transcript', 'verdict')]))

    def test_cli_uses_oauth_mode_through_local_sentinel(self):
        self.assertEqual(self.run_mode('oauth')['answer'], 'yes')

    def test_inference_cli_preserves_native_oauth_and_proxy(self):
        with mock.patch.dict(os.environ, {'DSMACK_SENTINEL_ENDPOINT': 'https://api.anthropic.com',
                                         'CLAUDE_CODE_OAUTH_TOKEN': 'DUMMY-INFERENCE',
                                         'HTTPS_PROXY': 'http://192.0.2.3:18443'}):
            self.assertEqual(self.run_mode('direct-oauth')['answer'], 'yes')

    def test_edit_turn_patch_applies(self):
        for key in ('answers', 'runs', 'aggregate'):
            del self.spec[key]
        self.spec['agent']['tools'] = ['Read', 'Edit', 'Write']
        self.assertEqual(self.run_mode('edit')['answer'], None)
        out = self.tmp/'out-edit'
        self.assertEqual(sorted(p.name for p in out.iterdir()), ['patch', 'run-1-transcript', 'verdict'])
        local = self.tmp/'local'
        shutil.copytree(self.inputs, local)
        subprocess.run(['git', 'apply', str(out/'patch')], cwd=local, check=True)
        self.assertEqual((local/'src'/'a.py').read_text(), 'def f():\n    return 2\n')
        self.assertEqual((local/'NOTES.md').read_text(), 'f returns 2\n')

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
