"""Fake CLI controls only: no real model, auth, browser, VM or network."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import generate as g
import closure as c
from test_closure import fixture, rewrite_output

MODEL = 'explicit-opus-4-8-fixture'
SUITE = {'schema': 'dsmack-bounty-browser-suite/1', 'tests': [{'id': 'search-behavior', 'steps': [
    {'op': 'navigate', 'path': '/apps/board/'},
    {'op': 'assert_count', 'selector': '[data-testid="search"]', 'value': 1}]}]}


def transcript(suite=SUITE, model=MODEL):
    return b'\n'.join(g.canonical(e) for e in [
        {'type': 'system', 'subtype': 'init', 'model': model},
        {'type': 'assistant', 'message': {'model': model, 'content': [{'type': 'text', 'text': 'suite'}]}},
        {'type': 'result', 'subtype': 'success', 'is_error': False, 'num_turns': 1,
         'result': g.canonical(suite).decode()}])+b'\n'


class GenerationControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.public = self.root/'public'; self.public.mkdir()
        self.base = {'schema': 'dsmack-bounty-base-snapshot/1',
                     'files': [{'path': 'apps/board/index.html', 'content': '<main>BASE ONLY</main>'}]}
        (self.public/'base.json').write_bytes(g.canonical(self.base))
        (self.public/'spec.txt').write_text('Add cross-column case-insensitive board search.')
        self.base_digest = g.sha(b'base')  # same synthetic base as closure controls
        self.snapshot = {'schema': 'dsmack-bounty-generator-input/1', 'base_tree_sha256': self.base_digest,
                         'files': [{'name': name, 'size': len((self.public/name).read_bytes()),
                                    'sha256': g.sha((self.public/name).read_bytes())} for name in g.PUBLIC_NAMES]}
        self.snapshot_digest = g.sha(g.canonical(self.snapshot))
        self.cli = self.root/'fake-claude'
        state = self.root/'state'; state.mkdir()
        self.patches = [mock.patch.object(g, 'NODE_BINARY', shutil.which('node')),
                        mock.patch.object(g, 'STATE_ROOT', state),
                        mock.patch.dict(os.environ, {'ANTHROPIC_BASE_URL': 'http://must-not-inherit.invalid/',
                                                    'ANTHROPIC_API_KEY': 'must-not-inherit',
                                                    'CLAUDE_CODE_OAUTH_TOKEN': 'must-not-inherit',
                                                    'CLAUDE_CONFIG_DIR': '/must-not-inherit',
                                                    'DSMACK_SENTINEL_ENDPOINT': 'http://127.0.0.1:9456/synthetic_run_capability',
                                                    'MCP_SECRET': 'must-not-inherit'})]
        for patch in self.patches:
            patch.start(); self.addCleanup(patch.stop)
        self.make_cli(transcript())

    def make_cli(self, raw):
        # Fake child asserts sandbox inputs instead of reading any credentials.
        source = '#!'+sys.executable+'\n'+f'''
import os,sys
from pathlib import Path
if '--version' in sys.argv:
    print('2.1.187 (Claude Code)'); raise SystemExit(0)
assert not list(Path.cwd().iterdir())
assert not list(Path(os.environ['HOME']).iterdir())
assert not list(Path(os.environ['CLAUDE_CONFIG_DIR']).iterdir())
assert os.environ['CLAUDE_CONFIG_DIR'] != '/must-not-inherit'
assert os.environ['ANTHROPIC_BASE_URL'] == 'http://127.0.0.1:9456/synthetic_run_capability'
assert os.environ['ANTHROPIC_AUTH_TOKEN'] == 'synthetic_run_capability'
assert 'ANTHROPIC_API_KEY' not in os.environ and 'CLAUDE_CODE_OAUTH_TOKEN' not in os.environ
assert 'MCP_SECRET' not in os.environ
assert sys.argv[sys.argv.index('--model')+1] == {MODEL!r}
assert sys.argv[sys.argv.index('--max-turns')+1] == '2'
assert sys.argv[sys.argv.index('--tools')+1] == ''
assert '--strict-mcp-config' in sys.argv and '--no-session-persistence' in sys.argv
assert sys.argv[sys.argv.index('--setting-sources')+1] == 'user'
assert sys.stdin.read() == ''
prompt = sys.argv[sys.argv.index('--print')+1]
assert 'BASE ONLY' in prompt and 'cross-column' in prompt
sys.stdout.buffer.write({raw!r})
'''
        self.cli.write_text(source); self.cli.chmod(0o755)
        self.cli_digest = g.sha(self.cli.read_bytes())

    def run_generate(self, judge=1, **kwargs):
        with mock.patch.object(g, 'CLI_SHA256', self.cli_digest):
            return g.generate(self.public, self.root/f'output-{judge}', self.cli, MODEL, judge,
                              kwargs.get('snapshot', self.snapshot_digest), self.base_digest)

    def test_three_independent_generations_and_closure_byte_contract(self):
        for judge in (1, 2, 3):
            checks, outcome = self.run_generate(judge)
            self.assertTrue(checks['completed'], outcome)
            self.assertEqual(outcome['status'], 'completed')
            self.assertEqual(checks['observed_model'], MODEL)
            output = self.root/f'output-{judge}'
            self.assertEqual((output/'suite.json').read_bytes(), c.canonical(SUITE))
            self.assertEqual(c.parse((output/'checks.json').read_bytes()), checks)
            manifest = c.parse((output/'output-manifest.json').read_bytes())
            self.assertEqual([r['name'] for r in manifest['files']], sorted(p.name for p in output.iterdir() if p.name != 'output-manifest.json'))
            for row in manifest['files']:
                raw = (output/row['name']).read_bytes()
                self.assertEqual((len(raw), c.sha(raw)), (row['size'], row['sha256']))
            identity = c.parse((output/'observed-identity.json').read_bytes())
            self.assertEqual(identity['judge_index'], judge)
            self.assertEqual(identity['cli_sha256'], self.cli_digest)
            self.assertEqual(identity['observed_models'], [MODEL])
            self.assertEqual(identity['node_binary_sha256'], g.file_sha(Path(shutil.which('node'))))
            self.assertEqual(identity['runtime_uid'], 1000)
        self.assertFalse(list(g.STATE_ROOT.iterdir()))
        with self.assertRaisesRegex(ValueError, 'output directory must be empty'):
            self.run_generate()

    def test_model_mismatch_keeps_original_observation_and_transcript(self):
        raw = transcript(model='different-observed-model')
        self.make_cli(raw)
        checks, outcome = self.run_generate()
        self.assertFalse(checks['completed'])
        self.assertEqual(checks['observed_model'], 'different-observed-model')
        self.assertIn('model mismatch', outcome['error'])
        self.assertEqual((self.root/'output-1/transcript.jsonl').read_bytes(), raw)
        self.assertEqual(g.parse((self.root/'output-1/observed-identity.json').read_bytes())['observed_models'], ['different-observed-model'])

    def test_generator_artifacts_feed_unchanged_ten_stage_synthetic_join(self):
        expected, result, verified, verifier = fixture()
        expected['requested_model'] = MODEL
        suite_digest = c.sha(c.canonical(SUITE))
        for judge in (1, 2, 3):
            checks, outcome = self.run_generate(judge)
            self.assertTrue(checks['completed'], outcome)
            output = self.root/f'output-{judge}'
            row = next(row for row in result['stages'] if row['stage_id'] == f'generate-{judge}')
            manifest = (output/'output-manifest.json').read_bytes()
            files = {p.name:p.read_bytes() for p in output.iterdir() if p.name != 'output-manifest.json'}
            row['output_manifest_sha256'] = c.sha(manifest)
            row['checks_sha256'] = c.sha(files['checks.json'])
            verified[row['execution_evidence_sha256']] = c.VerifiedOutputs(manifest, files, 'completed')
            for role in ('base', 'candidate'):
                ci = next(r for r in result['stages'] if r['stage_id'] == f'{role}-{judge}')
                ci['input_suite_sha256'] = suite_digest
                rewrite_output(result, verified, ci['stage_id'], lambda check: check.update(
                    suite_sha256=suite_digest, tests=[{'id':'search-behavior', 'status': 'assertion_failed' if role == 'base' else 'passed'}]))
        self.assertTrue(c.join(c.canonical(result), expected, verifier)['accepted'])
        # This is a simulated verifier only, never genuine child execution proof.
        rewrite_output(result, verified, 'candidate-2', lambda check: check.update(suite_sha256='0'*64))
        with self.assertRaisesRegex(ValueError, 'suite substitution'):
            c.join(c.canonical(result), expected, verifier)

    def test_generation_timeout_and_truncated_transcript_are_retained(self):
        with mock.patch.object(g, 'MAX_STDOUT', 128):
            checks, outcome = self.run_generate()
        self.assertFalse(checks['completed']); self.assertIn('output bound', outcome['error'])
        self.assertEqual(len((self.root/'output-1/transcript.jsonl').read_bytes()), 128)
        source = self.cli.read_text().replace('sys.stdout.buffer.write(', 'import time; time.sleep(3)\nsys.stdout.buffer.write(')
        self.cli.write_text(source); self.cli_digest = g.sha(self.cli.read_bytes())
        with mock.patch.object(g, 'WALL_SECONDS', .1):
            checks, outcome = self.run_generate(2)
        self.assertFalse(checks['completed']); self.assertIn('deadline', outcome['error'])
        self.assertTrue((self.root/'output-2/transcript.jsonl').exists())

    def test_remote_exec_duplicate_id_and_truthy_schema_refuse(self):
        for index, mutate in enumerate((
            lambda s: s['tests'][0]['steps'].append({'op': 'eval', 'code': 'process.exit(0)'}),
            lambda s: s['tests'][0]['steps'][0].update(path='https://evil.invalid/'),
            lambda s: s['tests'].append(copy.deepcopy(s['tests'][0])),
            lambda s: s['tests'][0]['steps'][1].update(value=True))):
            value = copy.deepcopy(SUITE); mutate(value); self.make_cli(transcript(value))
            with mock.patch.object(g, 'CLI_SHA256', self.cli_digest):
                checks, outcome = g.generate(self.public, self.root/f'refused-{index}', self.cli, MODEL, 1,
                                             self.snapshot_digest, self.base_digest)
            self.assertFalse(checks['completed'])
            self.assertIn('strict declarative suite', outcome['error'])
            self.assertTrue((self.root/f'refused-{index}/transcript.jsonl').exists())
            self.assertFalse((self.root/f'refused-{index}/suite.json').exists())

    def test_public_inputs_substitution_extra_candidate_and_other_judge_refuse(self):
        (self.public/'candidate.json').write_text('candidate must not enter context')
        checks, outcome = self.run_generate()
        self.assertFalse(checks['completed']); self.assertIn('closed public', outcome['error'])
        (self.public/'candidate.json').unlink()
        (self.public/'spec.txt').write_text('substituted spec')
        checks, outcome = self.run_generate(2)
        self.assertFalse(checks['completed']); self.assertIn('snapshot digest', outcome['error'])
        (self.public/'other-suite.json').write_text('{}')
        checks, outcome = self.run_generate(3)
        self.assertFalse(checks['completed']); self.assertIn('closed public', outcome['error'])

    def test_fixed_binary_mismatch_never_executes_cli(self):
        with mock.patch.object(g, 'CLI_SHA256', '0'*64):
            checks, outcome = g.generate(self.public, self.root/'bad-binary', self.cli, MODEL, 1,
                                         self.snapshot_digest, self.base_digest)
        self.assertFalse(checks['completed']); self.assertIn('binary digest', outcome['error'])
        self.assertFalse((self.root/'bad-binary/transcript.jsonl').exists())

    def test_missing_sentinel_wrong_uid_missing_node_and_prompt_overflow_fail_closed(self):
        cases = [mock.patch.dict(os.environ, {'DSMACK_SENTINEL_ENDPOINT':''}),
                 mock.patch.object(os, 'getuid', return_value=1001),
                 mock.patch.object(g, 'NODE_BINARY', str(self.root/'absent-node')),
                 mock.patch.object(g, 'MAX_PROMPT', 8)]
        for index, patch in enumerate(cases):
            with patch, mock.patch.object(g, 'CLI_SHA256', self.cli_digest):
                checks, outcome = g.generate(self.public, self.root/f'abi-refused-{index}', self.cli, MODEL, 1,
                                             self.snapshot_digest, self.base_digest)
            self.assertFalse(checks['completed']); self.assertTrue(outcome['error'])
            self.assertFalse((self.root/f'abi-refused-{index}/transcript.jsonl').exists())
        self.assertFalse(list(g.STATE_ROOT.iterdir()))

    def test_sentinel_route_refuses_absent_credential_or_arbitrary_configuration(self):
        for index, endpoint in enumerate((None, '', 'https://example.invalid/token',
                'http://127.0.0.1:123/a/b', 'http://user:password@127.0.0.1:123/token',
                'http://127.0.0.1:123/token?x', 'http://127.0.0.1/token',
                'http://127.0.0.1:123/token#x')):
            context = self.root/f'route-{index}'; context.mkdir()
            with self.assertRaises(ValueError):
                g.runtime_environment(context, endpoint)
            self.assertFalse(list(context.iterdir()))

    def test_output_and_time_limits_kill_reap_and_preserve(self):
        env = {'PATH': '/usr/bin:/bin'}
        for script, timeout, expected in [("import time; print('partial',flush=True); time.sleep(3)", .1, 'deadline'),
                                          ("import sys; sys.stdout.write('x'*100000)", 2, 'output bound'),
                                          ("import sys; sys.stderr.write('e'*100000)", 2, 'output bound')]:
            out, err, code, failure = g.bounded_process([sys.executable, '-c', script], b'', self.root, env, timeout, 1024, 1024)
            self.assertEqual(failure, expected); self.assertLessEqual(len(out), 1024); self.assertLessEqual(len(err), 1024)
            if expected == 'deadline':
                self.assertLess(code, 0)
                self.assertIn(b'partial', out)

    def test_incomplete_error_excess_turns_and_stdout_only_success_refuse(self):
        valid = [g.parse(line) for line in transcript().splitlines()]
        for change in (lambda e: e.pop(1), lambda e: e[-1].update(is_error='false'),
                       lambda e: e[-1].update(num_turns=3), lambda e: e[-1].update(subtype='error_max_turns'),
                       lambda e: e[1]['message']['content'].append({'type': 'tool_use'})):
            events = copy.deepcopy(valid); change(events)
            with self.assertRaises(ValueError):
                g.observe(b'\n'.join(g.canonical(e) for e in events))
        with self.assertRaises(ValueError):
            g.observe(b'{"completed":true}')

    def test_duplicate_provider_json_keys_and_symlink_inputs_refuse(self):
        with self.assertRaises(ValueError):
            g.parse(b'{"x":1,"x":2}')
        (self.public/'spec.txt').unlink()
        (self.public/'spec.txt').symlink_to(self.root/'outside')
        (self.root/'outside').write_text('outside')
        checks, outcome = self.run_generate()
        self.assertFalse(checks['completed']); self.assertIn('type/size', outcome['error'])

    def test_named_pipe_public_input_is_refused_without_blocking(self):
        (self.public/'spec.txt').unlink()
        os.mkfifo(self.public/'spec.txt')
        checks, outcome = self.run_generate()
        self.assertFalse(checks['completed']); self.assertIn('type/size', outcome['error'])


if __name__ == '__main__':
    unittest.main()
