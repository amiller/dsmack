#!/usr/bin/env python3
"""IPv4 CONNECT transport for the three Base Sepolia RPCs; no TLS termination."""
import http.server
import select
import socket
import sys

HOSTS={'sepolia.base.org','base-sepolia-rpc.publicnode.com','base-sepolia.drpc.org'}
class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_CONNECT(self):
        host,_,port=self.path.rpartition(':')
        if host not in HOSTS or port!='443':
            self.send_error(403);return
        try:
            address=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)[0][4]
            remote=socket.socket(socket.AF_INET,socket.SOCK_STREAM);remote.settimeout(15);remote.connect(address)
        except OSError:
            self.send_error(502);return
        self.send_response(200);self.end_headers()
        try:
            sockets=[self.connection,remote]
            while True:
                ready,_,_=select.select(sockets,[],[],60)
                if not ready:return
                for source in ready:
                    raw=source.recv(65536)
                    if not raw:return
                    (remote if source is self.connection else self.connection).sendall(raw)
        except OSError: pass
        finally:remote.close()
http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),Proxy).serve_forever()
