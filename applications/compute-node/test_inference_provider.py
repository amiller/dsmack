"""A job capability reaches only its broker; signed provider evidence gates model tools."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import inference_provider as model

SIGNER = Ed25519PrivateKey.generate()
CONFIG = {'schema': 'dsmack-broker-model/1', 'base_url': 'https://broker.example/relay-broker', 'model': 'test-model',
          'broker_key': SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
CREDENTIAL = {'schema': 'dsmack-broker-inference/1', 'token': 'test-scoped-job-capability-0123456789', 'job_id': '01'*16}


def evidence(request, verified_at=None):
    at = time.time() if verified_at is None else verified_at
    return {'verified': True, 'verification': 'verified', 'mode': 'broker-proxy', 'provider': 'near',
            'model': CONFIG['model'], 'nonce': request['nonce'], 'privacy': model.PRIVACY,
            'verifiedAt': int(at), 'expires_at': int(at)+60,
            'gateway': {'tcbStatus': 'UpToDate', 'tlsFingerprint': 'ab'*32},
            'models': [{'model': CONFIG['model'], 'tcbStatus': 'UpToDate', 'gpu_evidence': 'verified'}],
            'tls': {'checkedBy': 'broker', 'binding': 'spki', 'status': 'verified-by-broker', 'spki_sha256': 'ab'*32}}


def signed(request, message, *, signer=SIGNER, attestation=None):
    payload = {'schema': 'dsmack-broker-inference-response/1', 'job_id': CREDENTIAL['job_id'],
               'nonce': request['nonce'], 'request_sha256': hashlib.sha256(model.canonical(request)).hexdigest(),
               'model': CONFIG['model'], 'attestation': attestation or evidence(request),
               'result': {'model': CONFIG['model'], 'choices': [{'message': message}], 'usage': {'total_tokens': 12}}}
    return {'payload': payload, 'signature': signer.sign(model.canonical(payload)).hex()}


def request_body():
    return {'job_id': CREDENTIAL['job_id'], 'nonce': '02'*32, 'model': CONFIG['model'],
            'messages': [{'role': 'user', 'content': 'hello'}], 'tools': model.TOOLS, 'max_tokens': 4096, 'stream': False}


class ProviderTests(unittest.TestCase):
    def test_signed_tool_turn_produces_patch_without_capability_in_transcript(self):
        calls = []
        def request(config, credential, messages):
            self.assertEqual(credential, CREDENTIAL)
            calls.append(json.loads(json.dumps(messages)))
            message = {'role': 'assistant', 'content': 'done'} if len(calls) == 2 else {
                'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'write-1', 'type': 'function',
                    'function': {'name': 'write_file', 'arguments': json.dumps({'path': 'toy.py', 'content': 'print(2)\n'})}}]}
            body = request_body() | {'messages': messages}
            return model.verify_response(config, credential, body, signed(body, message), time.time())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root/'inputs'; inputs.mkdir(); (inputs/'toy.py').write_text('print(1)\n')
            model.run(CONFIG, CREDENTIAL, 'Change one to two', inputs, root/'outputs', request)
            self.assertIn('+print(2)', (root/'outputs/patch').read_text())
            self.assertEqual((inputs/'toy.py').read_text(), 'print(1)\n')
            transcript = (root/'outputs/run-1-transcript').read_text()
            self.assertNotIn(CREDENTIAL['token'], transcript)
            self.assertIn(model.PRIVACY, transcript)
            self.assertEqual(len(calls), 2)

    def test_completion_sends_only_scoped_capability_to_measured_broker(self):
        connection = Mock()
        def reply():
            args = connection.request.call_args.args
            self.assertEqual(args[0:2], ('POST', '/relay-broker/sandbox/inference'))
            request = json.loads(args[2])
            self.assertEqual(request['job_id'], CREDENTIAL['job_id'])
            self.assertNotIn('token', request)
            self.assertEqual(args[3]['Authorization'], 'Bearer '+CREDENTIAL['token'])
            self.assertEqual(args[3]['Host'], 'broker.example:8080')
            response = Mock(status=200)
            response.read.return_value = model.canonical(signed(request, {'role': 'assistant', 'content': 'done'}))
            return response
        connection.getresponse.side_effect = reply
        with patch.object(model.http.client, 'HTTPConnection', return_value=connection) as connect:
            actual = model.completion(CONFIG, CREDENTIAL, [{'role': 'user', 'content': 'hello'}])
        connect.assert_called_once_with('127.0.0.1', 8080, timeout=180)
        self.assertEqual(actual['choices'][0]['message']['content'], 'done')
        connection.close.assert_called_once()

    def test_wrong_broker_signature_refuses_model_result(self):
        body = request_body()
        envelope = signed(body, {'role': 'assistant', 'content': 'bad'}, signer=Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(ValueError, 'signature rejected'):
            model.verify_response(CONFIG, CREDENTIAL, body, envelope, time.time())

    def test_signed_replayed_response_cannot_answer_a_new_request(self):
        body = request_body()
        envelope = signed(body, {'role': 'assistant', 'content': 'old'})
        fresh = body | {'nonce': '03'*32}
        with self.assertRaisesRegex(ValueError, 'response binding'):
            model.verify_response(CONFIG, CREDENTIAL, fresh, envelope, time.time())

    def test_stale_attestation_is_rejected_even_with_valid_broker_signature(self):
        body = request_body()
        envelope = signed(body, {'role': 'assistant', 'content': 'bad'}, attestation=evidence(body, time.time()-120))
        with self.assertRaisesRegex(ValueError, 'attestation evidence'):
            model.verify_response(CONFIG, CREDENTIAL, body, envelope, time.time())

    def test_missing_gpu_verification_is_rejected_even_with_valid_broker_signature(self):
        body = request_body(); report = evidence(body)
        report['models'] = [{'model': CONFIG['model'], 'tcbStatus': 'UpToDate'}]
        envelope = signed(body, {'role': 'assistant', 'content': 'bad'}, attestation=report)
        with self.assertRaisesRegex(ValueError, 'per-model attestation'):
            model.verify_response(CONFIG, CREDENTIAL, body, envelope, time.time())

    def test_capability_is_bound_to_the_sealed_job(self):
        with self.assertRaisesRegex(ValueError, 'job-scoped'):
            model.validate_credential(CREDENTIAL, '04'*16)
        with self.assertRaisesRegex(ValueError, 'job-scoped'):
            model.validate_credential({'schema': 'dsmack-delegated-inference/1', 'api_key': 'no-provider-key-in-guest'})

    def test_model_tool_cannot_escape_repo_or_modify_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.assertRaises(ValueError):
                model.apply_tool(root, 'write_file', {'path': '../outside', 'content': 'bad'})
            with self.assertRaises(ValueError):
                model.apply_tool(root, 'write_file', {'path': '.git/config', 'content': 'bad'})

    def test_measured_gateway_rule_contains_only_broker_model_endpoint(self):
        rule, = model.gateway_policy(CONFIG)['rules']
        self.assertEqual(rule['name'], 'broker.example')
        self.assertEqual(rule['paths'], ['/relay-broker/sandbox/inference'])
        self.assertEqual(rule['methods'], ['POST'])
        with self.assertRaises(ValueError):
            model.validate_config(CONFIG | {'base_url': 'http://broker.example/relay-broker'})

class HttpFailureTests(unittest.TestCase):
    def test_broker_http_failure_identifies_status_without_private_body(self):
        response = Mock(status=403)
        response.read.return_value = b'{"error":"capability_auth","private":"do-not-copy"}'
        conn = Mock(); conn.getresponse.return_value = response
        with patch.object(model.http.client, 'HTTPConnection', return_value=conn):
            with self.assertRaises(model.ProviderError) as caught:
                model.completion(CONFIG, CREDENTIAL, [{'role':'user','content':'private prompt'}])
        self.assertEqual(caught.exception.code, 'broker_http_403_capability_auth')
        self.assertNotIn('do-not-copy', str(caught.exception))
