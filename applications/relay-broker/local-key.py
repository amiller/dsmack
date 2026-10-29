#!/usr/bin/env python3
"""Local GetKey service for the standalone broker: SOCKET SEED_FILE.

The seed is created on this machine and stays here. Production uses dstack GetKey.
"""
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socketserver
import sys
from urllib.parse import urlsplit

socket_path, seed_path = map(Path, sys.argv[1:3])
seed_path.parent.mkdir(parents=True, exist_ok=True)
if not seed_path.exists():
    with open(seed_path, 'xb', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        stream.write(os.urandom(32))
seed = seed_path.read_bytes()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        name = request['name']
        if urlsplit(self.path).path != '/GetKey' or name not in ('egress-grants-v1', 'payments-grants-v1'):
            self.send_error(403)
            return
        key = hashlib.sha256(seed + request['path'].encode() + name.encode()).hexdigest()
        result = json.dumps({'key': key}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)

with socketserver.UnixStreamServer(str(socket_path), Handler) as server:
    os.chmod(socket_path, 0o600)
    server.serve_forever()
