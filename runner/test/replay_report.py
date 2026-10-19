"""Serves one recorded attestation report body, byte for byte, for any GET on 127.0.0.1:PORT. Its nonce is stale, so
the provider-quote helper must refuse it. usage: replay_report.py FILE PORT"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

body = Path(sys.argv[1]).read_bytes()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(('127.0.0.1', int(sys.argv[2])), H).serve_forever()
