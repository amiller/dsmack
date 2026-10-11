import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('checker', Path(__file__).with_name('check_participation_release.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

class FakeReader:
    def __init__(self):
        self.calls = []
        self.chain_id = '0x14a34'
        self.code = '0x6000'
        self.paused = '0x' + '0' * 64
        self.relay_chain = 84532
        self.sponsor_paused = False
        self.pending = []
        self.rpc_error = False
    def read(self, url, payload=None):
        self.calls.append((url, payload))
        return b'package'
    def json(self, url, payload=None):
        self.calls.append((url, payload))
        if payload:
            if self.rpc_error:
                return {'jsonrpc': '2.0', 'id': 1, 'error': {'message': 'private upstream detail'}}
            value = {'eth_chainId': self.chain_id, 'eth_blockNumber': '0x123',
                     'eth_getCode': self.code, 'eth_call': self.paused}[payload['method']]
            return {'jsonrpc': '2.0', 'id': 1, 'result': value}
        if url.endswith('/info'):
            return {'chainId': self.relay_chain, 'registry': '0x123', 'protocolVersion': 2}
        return {'sponsorWritesPaused': self.sponsor_paused, 'pending': self.pending}

class Checks(unittest.TestCase):
    def setUp(self):
        self.reader = FakeReader()
        self.manifest = {'release': 'test', 'protocolVersion': 2,
            'asset': {'url': 'https://example.test/package', 'bytes': 7,
                      'sha256': hashlib.sha256(b'package').hexdigest()},
            'chain': {'id': 84532, 'rpc': 'https://example.test/rpc', 'registry': '0x123', 'receipts': '0x456'},
            'relay': 'https://example.test/relay'}
    def run_check(self):
        return checker.check(self.manifest, self.reader)
    def test_success_still_does_not_claim_peer_acceptance(self):
        result = self.run_check()
        self.assertTrue(result['passed'])
        for key in ('nodeStarted','enrollmentSent','transactionsSent','freshPeerAdmission','independentDeviceAcceptance'):
            self.assertIs(result[key], False)
        methods = {payload['method'] for _, payload in self.reader.calls if payload}
        self.assertEqual(methods, {'eth_chainId','eth_blockNumber','eth_getCode','eth_call'})
        for _, payload in self.reader.calls:
            if payload and payload['method'] in ('eth_getCode', 'eth_call'):
                self.assertEqual(payload['params'][-1], '0x123')
    def test_bad_package(self):
        for field, value in [('sha256','0'*64),('bytes',8)]:
            with self.subTest(field=field):
                old = self.manifest['asset'][field]
                self.manifest['asset'][field] = value
                self.assertFalse(self.run_check()['checks'][0]['passed'])
                self.manifest['asset'][field] = old
    def test_wrong_network_missing_code_pause_and_malformed_are_refused(self):
        for field, value in [('chain_id','0x1'),('code','0x'),('code','0xzz'),('paused','0x01'),
                             ('relay_chain',1),('sponsor_paused',True),('pending',None),('rpc_error',True)]:
            with self.subTest(field=field):
                self.reader = FakeReader()
                setattr(self.reader, field, value)
                result = self.run_check()
                self.assertFalse(result['passed'])
                self.assertNotIn('private upstream detail', json.dumps(result))
    def test_http_error_does_not_echo_url(self):
        with patch.object(checker.urllib.request, 'urlopen', side_effect=OSError('secret URL')):
            with self.assertRaisesRegex(checker.CheckFailure, '^HTTP request failed$'):
                checker.Reader().read('https://example.test/')
    def test_response_size_bound(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'x' * limit
        with patch.object(checker.urllib.request, 'urlopen', return_value=Response()):
            with self.assertRaisesRegex(checker.CheckFailure, 'byte limit'):
                checker.Reader().read('https://example.test/')
    def test_deadline_and_https_required(self):
        with self.assertRaisesRegex(checker.CheckFailure, 'deadline'):
            checker.Reader(duration=-1).read('https://example.test/')
        with self.assertRaisesRegex(checker.CheckFailure, 'HTTPS'):
            checker.Reader().read('http://example.test/')

if __name__ == '__main__':
    unittest.main()
