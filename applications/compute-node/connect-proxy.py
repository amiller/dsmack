#!/usr/bin/env python3
"""CONNECT one configured model hostname:443; TLS stays between guest and provider."""
import argparse
import select
import re
import socket
import socketserver
import time

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        line = self.rfile.readline(4097)
        allowed = self.server.allowed_hosts or {self.server.model_host}
        match = re.fullmatch(rb'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]\r\n', line)
        host = match[1].decode() if match else ''
        if host not in allowed:
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
            return
        size = len(line)
        while True:
            line = self.rfile.readline(4097)
            size += len(line)
            if not line or size > 8192:
                return
            if line == b'\r\n':
                break
        with socket.create_connection((host, 443), timeout=10) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
            # Unbuffered input avoids consuming the first TLS bytes with the headers.
            self.connection.settimeout(30); upstream.settimeout(30)
            deadline = time.monotonic() + self.server.connection_seconds
            while time.monotonic() < deadline:
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                for source in ready:
                    raw = source.recv(65536)
                    if not raw:
                        return
                    (upstream if source is self.connection else self.connection).sendall(raw)
    rbufsize = 0

class Server(socketserver.ThreadingTCPServer):
    model_host = 'api.anthropic.com'
    allowed_hosts = None
    connection_seconds = 240
    allow_reuse_address = True
    daemon_threads = True

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--listen', required=True)
    p.add_argument('--port', type=int, default=18443)
    p.add_argument('--model-host', default='api.anthropic.com')
    p.add_argument('--allow-host', action='append', help='exact CONNECT hostname; repeat for broker and quick tunnel')
    p.add_argument('--connection-seconds', type=int, default=240)
    a = p.parse_args()
    if not 1 <= a.connection_seconds <= 3600:
        p.error('connection lifetime must be 1..3600 seconds')
    if any(not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}', host) for host in (a.allow_host or [a.model_host])):
        p.error('one exact lowercase model DNS hostname required')
    with Server((a.listen, a.port), Handler) as server:
        server.model_host = a.model_host
        server.allowed_hosts = frozenset(a.allow_host or [a.model_host])
        server.connection_seconds = a.connection_seconds
        server.serve_forever()
