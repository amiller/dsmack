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
