"""Broker retries retain HTTP diagnostics without rerunning chain publication."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from eth_abi import decode
from eth_account import Account
from eth_account.messages import encode_defunct
from unittest.mock import patch


class BrokerPublicationTests(unittest.TestCase):
    def run_publication(self, replies, root):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])))
                status, body = replies[len(received)-1]
                self.send_response(status); self.end_headers(); self.wfile.write(body)
            def log_message(self, *_): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        (root/'entries.json').write_text('[]'); (root/'token').write_text('unit-test-token')
        args = ['publish.py','broker','--broker',f'http://127.0.0.1:{server.server_port}/tunnels',
                '--entries',str(root/'entries.json'),'--operator-token',str(root/'token'),'--evidence',str(root)]
        output = io.StringIO()
        try:
            with patch.object(sys, 'argv', args), patch('time.sleep') as sleep, contextlib.redirect_stdout(output):
                try:
                    runpy.run_path(str(Path(__file__).with_name('publish.py')), run_name='__main__')
                except SystemExit as exit:
                    self.assertIsNone(exit.code)
            return received, sleep.call_args_list, output.getvalue()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_two_transient_failures_then_success_keep_each_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            received, sleeps, output = self.run_publication([(500,b'promotion one'),(500,b'promotion two'),(200,b'{"published":true}')],root)
            self.assertEqual(received,[b'[]']*3)
            self.assertEqual([call.args for call in sleeps],[(5,),(5,)])
            self.assertEqual(json.loads((root/'broker-error-1.json').read_text())['body'],'promotion one')
            self.assertEqual(json.loads((root/'broker-error-2.json').read_text())['body'],'promotion two')
            self.assertEqual(json.loads((root/'broker-published.json').read_text()),{'published':True})
            self.assertIn('broker_publication',output)
            self.assertFalse((root/'publish-transaction.json').exists())

    def test_three_failures_raise_with_last_status_and_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError,'last promotion'):
                self.run_publication([(500,b'first'),(503,b'second'),(500,b'last promotion')],root)
            final = json.loads((root/'broker-error-3.json').read_text())
            self.assertEqual(final['status'],500); self.assertEqual(final['body'],'last promotion')
            self.assertFalse(final['retrying']); self.assertEqual(final['stage'],'broker_publication')
            self.assertFalse((root/'broker-published.json').exists())

    def test_permanent_http_error_stops_immediately_and_bounds_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError,'HTTP Error 403'):
                self.run_publication([(403,b'x'*5000)],root)
            error=json.loads((root/'broker-error-1.json').read_text())
            self.assertEqual(len(error['body']),4096); self.assertTrue(error['body_truncated'])
            self.assertFalse(error['retrying']); self.assertFalse((root/'broker-error-2.json').exists())


class ChainPublicationTests(unittest.TestCase):
    def test_chain_only_signs_guest_envelope_without_contacting_broker(self):
        account = Account.create()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'publisher.key').write_text(account.key.hex())
            entries = [{'url': 'wss://guest.trycloudflare.com/', 'relayPeer': 'relay',
                        'guestPeer': 'guest', 'expiresAt': 1600}]
            (root/'entries.json').write_text(json.dumps(entries))
            captured = []
            def send(*args, **kwargs):
                captured.append(kwargs)
                return {'transactionHash': '0xpublication'}
            args = ['publish.py', 'chain', '--key', str(root/'publisher.key'),
                    '--publisher-address', account.address, '--entries', str(root/'entries.json'),
                    '--registry', '0x'+'12'*20, '--rpc', 'https://publication.example',
                    '--evidence', str(root)]
            with patch.object(sys, 'argv', args), patch('time.time', return_value=1000), \
                    patch.dict(sys.modules, {'deploy': SimpleNamespace(load_owner=None, send=send, wait_receipt=None)}), \
                    patch('urllib.request.urlopen', side_effect=AssertionError('chain publication contacted HTTP broker')), \
                    contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(Path(__file__).with_name('publish.py')), run_name='__main__')
            body = json.loads(decode(['string'], bytes.fromhex(captured[0]['data'][10:]))[0])
            self.assertEqual(body, json.loads((root/'signed-publication.json').read_text()))
            signature = body.pop('signature')
            self.assertEqual(body['entries'], entries)
            self.assertEqual(body['expiresAt'], 1600)
            message = 'dsmack-tunnels/1\n' + json.dumps(body, sort_keys=True, separators=(',', ':'))
            self.assertEqual(Account.recover_message(encode_defunct(text=message), signature=signature), account.address)
            self.assertFalse((root/'broker-published.json').exists())


    def test_lost_submission_response_reconciles_saved_hash_without_sending_again(self):
        account = Account.create()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'publisher.key').write_text(account.key.hex())
            entries = [{'expiresAt': 1600, 'guestPeer': 'guest'}]
            (root/'entries.json').write_text(json.dumps(entries))
            accepted = '0xaccepted'
            def send(account, quorum, output, label, **kwargs):
                (output/'publish-transaction.json').write_text(json.dumps({
                    'hash': accepted, 'from': account.address, 'to': kwargs['to']}))
                raise TimeoutError('submission response lost after RPC accepted transaction')
            from unittest.mock import Mock
            submit = Mock(side_effect=send)
            reconcile = Mock(return_value={'transactionHash': accepted, 'status': '0x1'})
            args = ['publish.py', 'chain', '--key', str(root/'publisher.key'),
                    '--publisher-address', account.address, '--entries', str(root/'entries.json'),
                    '--registry', '0x'+'12'*20, '--rpc', 'https://publication.example',
                    '--evidence', str(root)]
            with patch.object(sys, 'argv', args), patch('time.time', return_value=1000), \
                    patch.dict(sys.modules, {'deploy': SimpleNamespace(load_owner=None, send=submit, wait_receipt=reconcile)}), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(TimeoutError, 'submission response lost'):
                    runpy.run_path(str(Path(__file__).with_name('publish.py')), run_name='__main__')
                signed = (root/'signed-publication.json').read_bytes()
                runpy.run_path(str(Path(__file__).with_name('publish.py')), run_name='__main__')
                self.assertEqual((root/'signed-publication.json').read_bytes(), signed)
                submit.assert_called_once()
                self.assertEqual(reconcile.call_args.args[1], accepted)
                self.assertEqual(json.loads((root/'publish-receipt.json').read_text())['transactionHash'], accepted)
                (root/'entries.json').write_text(json.dumps([{'expiresAt': 1700, 'guestPeer': 'new-guest'}]))
                with self.assertRaisesRegex(ValueError, 'pending publication differs'):
                    runpy.run_path(str(Path(__file__).with_name('publish.py')), run_name='__main__')
                submit.assert_called_once()
