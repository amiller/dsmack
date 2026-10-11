import json
import multiprocessing
import ssl
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .transport import NearHTTPS, TransportError, _perform_http


def _slow_worker(pipe, *args):
    time.sleep(10)


class FakeResponse:
    status = 200
    headers = {}
    data = b'{"ok":true}'

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, size):
        return self.data[:size]


class FakeConnection:
    response = FakeResponse()
    calls = []
    fail = False

    def __init__(self, host, port, timeout, context):
        self.__class__.calls.append((host, port, timeout, context))

    def request(self, method, target, body, headers):
        self.__class__.calls.append((method, target, body, headers))
        if self.fail:
            raise RuntimeError('Bearer sensitive-token private-upstream-body')

    def getresponse(self):
        return self.response

    def close(self):
        pass


class TransportTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.calls = []
        FakeConnection.fail = False
        FakeConnection.response = FakeResponse()

    def perform(self):
        with patch('http.client.HTTPSConnection', FakeConnection):
            return _perform_http('POST', '/v1/workspaces/test/api-keys', 'sensitive-token', b'{}', 2, 100)

    def test_fixed_tls_origin_and_certificate_validation(self):
        with patch.dict('os.environ', {'HTTPS_PROXY': 'https://evil.invalid', 'HTTP_PROXY': 'http://evil.invalid'}):
            self.assertEqual(self.perform(), ('ok', {'ok': True}))
        host, port, timeout, context = FakeConnection.calls[0]
        self.assertEqual((host, port, timeout), ('cloud-api.near.ai', 443, 2))
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(FakeConnection.calls[1][3]['Authorization'], 'Bearer sensitive-token')

    def test_redirect_errors_not_followed_and_no_retry(self):
        for status in (301, 307, 401, 429, 500):
            FakeConnection.calls = []
            FakeConnection.response.status = status
            FakeConnection.response.headers = {'Location': 'https://evil.invalid'}
            result = self.perform()
            self.assertEqual(result[0], 'error')
            self.assertEqual(len(FakeConnection.calls), 2)
            self.assertNotIn('sensitive-token', str(result))

    def test_exception_sanitized_and_no_retry(self):
        FakeConnection.fail = True
        result = self.perform()
        self.assertEqual(result, ('error', 'provider HTTPS or JSON request failed'))
        self.assertEqual(len(FakeConnection.calls), 2)

    def test_response_bounds_and_strict_json(self):
        for data in [b'x' * 101, b'not-json', b'{"x":NaN}', b'{"x":1e999}', b'{"x":-1e999}',
                     b'{"x":1,"x":2}', b'[]']:
            FakeConnection.response.data = data
            self.assertEqual(self.perform()[0], 'error')

        FakeConnection.response.data = b'{}'
        for headers in [{'Content-Encoding': 'gzip'}, {'Content-Length': '101'}, {'Content-Length': '-1'}]:
            FakeConnection.response.headers = headers
            self.assertEqual(self.perform()[0], 'error')

    def test_environment_cannot_enable_tls_key_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / 'traffic-secrets.log'
            with patch.dict('os.environ', {'SSLKEYLOGFILE': str(keylog)}):
                self.assertEqual(self.perform()[0], 'ok')
            context = FakeConnection.calls[0][3]
            self.assertIsNone(context.keylog_filename)
            self.assertFalse(keylog.exists())

    def test_reject_origin_header_injection_and_payload_before_network(self):
        transport = NearHTTPS()
        for url in ['http://cloud-api.near.ai/v1/health', 'https://evil.invalid/v1/health',
                    'https://cloud-api.near.ai.evil.invalid/v1/health',
                    'https://cloud-api.near.ai:443/v1/health',
                    'https://user@cloud-api.near.ai/v1/health',
                    'https://cloud-api.near.ai/v1/health#x',
                    'https://cloud-api.near.ai/v1/health\r\nX: evil']:
            with self.assertRaises(TransportError):
                transport('GET', url, 'token', None)
        with self.assertRaises(TransportError):
            transport('GET', 'https://cloud-api.near.ai/v1/health', 'token\nX: evil', None)
        with self.assertRaises(TransportError):
            transport('POST', 'https://cloud-api.near.ai/v1/health', 'token', {'huge': 'x' * 65536})

    def test_total_deadline_kills_worker(self):
        before = {p.pid for p in multiprocessing.active_children()}
        started = time.monotonic()
        with patch('experiments.coupon_redemption.transport._worker', _slow_worker):
            with self.assertRaises(TransportError) as error:
                NearHTTPS(deadline=0.15, socket_timeout=0.1)(
                    'POST', 'https://cloud-api.near.ai/v1/workspaces/test/api-keys', 'secret', {})
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn('ambiguous', str(error.exception))
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)


if __name__ == '__main__':
    unittest.main()
