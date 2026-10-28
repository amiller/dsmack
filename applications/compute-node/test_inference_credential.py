"""Inference-only credentials must cross the sealed job and sentinel without refresh."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import client

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'base-vm/browser-sandbox-v1/source/guest/sentinel'))
from harness.adapter import claude_subscription_document as guest_validator
from harness.sentinel import sentinel_oauth as sentinel

TOKEN = 'sk-ant-oat01-DUMMY-INFERENCE-ONLY'
OAUTH = {'accessToken': TOKEN, 'scopes': ['user:inference']}

class InferenceCredentialTests(unittest.TestCase):
    def test_document_and_bare_token_reach_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'credential'
            for raw in (TOKEN.encode()+b'\n', client.canonical({'claudeAiOauth': OAUTH})):
                path.write_bytes(raw)
                doc = client.read_credential(path)
                self.assertEqual(doc, {'claudeAiOauth': OAUTH})
                self.assertEqual(guest_validator.parse_subscription_document(client.canonical(doc)), OAUTH)
            path.write_bytes(client.canonical(doc)); path.chmod(0o400)
            args = SimpleNamespace(credential_fd=None, credential_file=str(path), allow_group_readable_credential_file=False, provider_route='https://api.anthropic.com', ca_bundle=None)
            loaded = sentinel.load_subscription_credential(args, lambda _: None)
            self.assertEqual(loaded.access_token, TOKEN)
            self.assertFalse(loaded.refreshable)

    def test_preferred_token_and_old_document_selection(self):
        validator = client.export_subscription.validator()
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            self.assertEqual(validator.default_credential_path(parent), parent/'claude-subscription.json')
            token = parent/'claude-oauth-token'; token.write_text('malformed')
            self.assertEqual(validator.default_credential_path(parent), token)
            with self.assertRaises(ValueError):
                client.read_credential(token)

    def test_incomplete_refresh_credentials_are_rejected(self):
        for validator in (guest_validator, client.export_subscription.validator()):
            for extra in ({'refreshToken': 'dummy'}, {'expiresAt': 1}):
                with self.assertRaises(ValueError):
                    validator.validate_subscription_object(OAUTH | extra)
            for raw in (TOKEN.encode()+b' injected', b'sk-ant-oat01-'):
                with self.assertRaises(ValueError):
                    validator.parse_credential_source(raw)

    def test_inference_requests_use_bearer_beta_and_never_refresh_even_on_401(self):
        for status in (200, 401, 429):
            credential = sentinel.SubscriptionCredential(dict(OAUTH), 'https://api.anthropic.com', None)
            self.assertIsNone(credential.expires_at_ms)
            self.assertFalse(credential.needs_refresh(now_ms=4102444800000))
            conn = Mock(); response = conn.getresponse.return_value
            response.status = status; response.read.return_value = b'{}'
            response.getheaders.return_value = [('WWW-Authenticate', 'Bearer error="invalid_token"')]
            run = sentinel.SubscriptionSentinel('test', 'local-token', 'https://api.anthropic.com', None, credential)
            run.log = lambda _: None
            with patch.object(sentinel, 'provider_connection', return_value=conn) as upstream, patch.object(credential, 'refresh', wraps=credential.refresh) as refresh:
                actual, _, _ = run._upstream_request('POST', '/v1/messages', {'x-api-key':'discard'}, b'{}')
                self.assertEqual(actual, status)
                refresh.assert_not_called(); upstream.assert_called_once()
                headers = conn.request.call_args.kwargs['headers']
                self.assertEqual(headers['Authorization'], 'Bearer '+TOKEN)
                self.assertIn(sentinel.OAUTH_BETA, headers['anthropic-beta'])
                self.assertNotIn('x-api-key', headers)
            with patch.object(sentinel, 'provider_connection') as upstream:
                with self.assertRaises(sentinel.SentinelError):
                    credential.refresh()
                upstream.assert_not_called()

    def test_refreshable_document_still_refreshes_before_request(self):
        credential = sentinel.SubscriptionCredential(OAUTH | {'refreshToken':'dummy', 'expiresAt':1}, 'https://api.anthropic.com', None)
        self.assertTrue(credential.needs_refresh())
        with patch.object(credential, 'refresh') as refresh:
            credential.get_access_token_for_request()
            refresh.assert_called_once()
