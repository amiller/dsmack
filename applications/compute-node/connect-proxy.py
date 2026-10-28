#!/usr/bin/env python3
"""CONNECT api.anthropic.com:443 only; TLS is terminated by the guest sentinel."""
import argparse
import select
import socket
import socketserver
import time

TARGET = 'api.anthropic.com:443'

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        line = self.rfile.readline(4097)
        if line not in (f'CONNECT {TARGET} HTTP/1.1\r\n'.encode(), f'CONNECT {TARGET} HTTP/1.0\r\n'.encode()):
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
        with socket.create_connection(('api.anthropic.com', 443), timeout=10) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
            # Unbuffered input avoids consuming the first TLS bytes with the headers.
            self.connection.settimeout(30); upstream.settimeout(30)
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                for source in ready:
                    raw = source.recv(65536)
                    if not raw:
                        return
                    (upstream if source is self.connection else self.connection).sendall(raw)
    rbufsize = 0

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--listen', required=True)
    p.add_argument('--port', type=int, default=18443)
    a = p.parse_args()
    with Server((a.listen, a.port), Handler) as server:
        server.serve_forever()
