import contextlib
import io
import json
import unittest

from publication_rpc import OrderedRPC


class PublicationRPCTests(unittest.TestCase):
    def test_ambiguous_submission_retries_identical_signed_transaction_and_checks_receipt(self):
        calls = []
        def call(url, method, params):
            calls.append((url, method, params))
            if method == 'eth_chainId': return '0x14a34'
            if url == 'https://one.example': raise TimeoutError('response lost')
            if method == 'eth_sendRawTransaction': return 'hash'
            return {'transactionHash': 'hash', 'status': '0x1'}
        rpc = OrderedRPC(['https://one.example', 'https://two.example'], call)
        with contextlib.redirect_stdout(io.StringIO()) as log:
            self.assertEqual(rpc(None, 'eth_sendRawTransaction', ['signed-bytes']), 'hash')
            self.assertEqual(rpc(None, 'eth_getTransactionReceipt', ['hash'])['status'], '0x1')
        submissions = [params for _, method, params in calls if method == 'eth_sendRawTransaction']
        self.assertEqual(submissions, [['signed-bytes'], ['signed-bytes']])
        self.assertEqual(json.loads(log.getvalue().splitlines()[0])['provider'], 'one.example')

    def test_all_failed_providers_remain_an_error(self):
        def call(*_): raise TimeoutError()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'all publication RPC providers failed'):
            OrderedRPC(['https://one.example', 'https://two.example'], call)(None, 'eth_getTransactionCount', [])
