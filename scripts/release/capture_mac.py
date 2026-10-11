#!/usr/bin/env python3
"""Capture real App Attest from a signed candidate without submitting transactions.

This local HTTP endpoint saves enrollment evidence and deliberately refuses
enrollment. It is not a mock verifier or a successful network join.
"""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import threading


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', type=Path, required=True)
    p.add_argument('--deploy', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    deploy = json.loads(args.deploy.read_text())
    received = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, data):
            raw = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != '/info':
                return self.respond(404, {'error': 'unknown path'})
            self.respond(200, {'owner': deploy['admin'], 'chainId': 84532})

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            if self.path != '/enroll' or not 0 < length <= 100000:
                return self.respond(400, {'error': 'invalid capture request'})
            value = json.loads(self.rfile.read(length))
            (out / 'enrollment-request.json').write_text(json.dumps(value, indent=2) + '\n')
            self.respond(503, {'error': 'capture only: no enrollment transaction was submitted'})
            received.set()

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    config = {'rpc': 'https://sepolia.base.org', 'registry': deploy['DemoV1'], 'chainId': 84532,
              'category': deploy['macCategory'], 'relay': f'http://127.0.0.1:{server.server_port}',
              'name': 'release-capture', 'peer': ''}
    path = out / 'config.json'
    path.write_text(json.dumps(config))
    try:
        subprocess.run(['open', '-n', '--stdout', str(out / 'stdout.log'), '--stderr', str(out / 'stderr.log'),
                        str(args.app.resolve()), '--args', str(path), 'connect'], check=True)
        if not received.wait(120):
            raise SystemExit('No evidence captured within 120 seconds; inspect stdout/stderr logs')
    finally:
        server.shutdown()
        server.server_close()
    print('Captured real App Attest enrollment; deliberately not submitted to the chain')


if __name__ == '__main__':
    main()
