"""The sealed delegated key stays in headers; model tools only modify the repo."""
import json
from pathlib import Path
import tempfile
import unittest

import inference_provider as model

CONFIG = {'schema': 'dsmack-tee-model/1', 'base_url': 'https://model.example/v1', 'model': 'test-model'}
CREDENTIAL = {'schema': 'dsmack-delegated-inference/1', 'api_key': 'test-delegated-key'}


class ProviderTests(unittest.TestCase):
    def test_tool_turn_produces_patch_without_credential_in_transcript(self):
        calls = []
        def request(config, key, messages):
            calls.append(json.loads(json.dumps(messages)))
            self.assertEqual(key, CREDENTIAL['api_key'])
            message = {'role': 'assistant', 'content': 'done'} if len(calls) == 2 else {
                'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'write-1', 'type': 'function',
                    'function': {'name': 'write_file', 'arguments': json.dumps({'path': 'toy.py', 'content': 'print(2)\n'})}}]}
            return {'model': config['model'], 'choices': [{'message': message}], 'usage': {'total_tokens': 12}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root/'inputs'; inputs.mkdir(); (inputs/'toy.py').write_text('print(1)\n')
            model.run(CONFIG, CREDENTIAL, 'Change one to two', inputs, root/'outputs', request)
            self.assertIn('+print(2)', (root/'outputs/patch').read_text())
            self.assertEqual((inputs/'toy.py').read_text(), 'print(1)\n')
            self.assertNotIn(CREDENTIAL['api_key'], (root/'outputs/run-1-transcript').read_text())
            self.assertEqual(len(calls), 2)

    def test_model_tool_cannot_escape_repo_or_modify_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for path in ('../outside', '.git/config'):
                with self.assertRaises(ValueError):
                    model.apply_tool(root, 'write_file', {'path': path, 'content': 'bad'})

    def test_measured_gateway_rule_contains_only_model_hostname(self):
        rule, = model.gateway_policy(CONFIG)['rules']
        self.assertEqual(rule['name'], 'model.example')
        self.assertEqual(rule['paths'], ['/v1/chat/completions'])
        self.assertEqual(rule['methods'], ['POST'])
        with self.assertRaises(ValueError):
            model.validate_config(CONFIG | {'base_url': 'http://model.example/v1'})
