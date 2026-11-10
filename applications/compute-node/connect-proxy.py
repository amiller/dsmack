#!/usr/bin/env python3
"""CONNECT on port 443 to the operator hosts, the package hosts, and whatever the stay's browse policy allows.

The policy is runtime input. The guest sends `Proxy-Authorization: Basic base64("browse:"+token)`, and the
proxy looks the token up at the broker, which recorded {mode, hosts, expires_at} from the accepted terms.
none: nothing more. named: exactly `hosts`. open: any host whose every IPv4 address is public (is_global),
which keeps loopback, the LAN, link-local and CGNAT out. `GET /browse` returns the policy the proxy applies to the presented token. TLS stays between guest and destination."""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import select
import re
import socket
import socketserver
import time
import urllib.request

HOST_RE = r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}'
PACKAGE_HOSTS = Path(__file__).with_name('package-hosts.json')
POLICY_TTL = 10

def public_address(host):
    """Resolve once and dial the checked address, so DNS cannot rebind to the LAN or the Mac."""
    addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
    if not addresses or not all(ipaddress.ip_address(a).is_global for a in addresses):
        raise PermissionError('non-public address')
    return sorted(addresses)[0]

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        line = self.rfile.readline(4097)
        match = re.fullmatch(rb'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]\r\n', line)
        host = match[1].decode() if match else ''
        report = re.fullmatch(rb'GET /browse HTTP/1\.[01]\r\n', line)
        size, token = len(line), None
        while True:
            line = self.rfile.readline(4097)
            size += len(line)
            if not line or size > 8192:
                return
            if line == b'\r\n':
                break
            name, _, value = line.decode('latin-1').partition(':')
            if name.strip().lower() == 'proxy-authorization' and value.strip().startswith('Basic '):
                user, _, secret = base64.b64decode(value.strip()[6:]).decode('latin-1').partition(':')
                token = secret if user == 'browse' else None
        server = self.server
        if report:
            try:
                body = json.dumps(server.policy(token) if token else {'mode': 'none', 'hosts': []}).encode()
            except (PermissionError, OSError) as error:
                print(json.dumps({'report': True, 'refused': str(error)}), flush=True)
                self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                return
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
            return
        address = server.resolved_hosts.get(host, host)
        if host in server.allowed_hosts or host in server.package_hosts:
            rule = 'operator' if host in server.allowed_hosts else 'package'
        else:
            try:
                policy = server.policy(token) if token else None
                rule = policy['mode'] if policy else 'none'
                if not host or rule == 'none' or (rule == 'named' and host not in policy['hosts']):
                    raise PermissionError('not in policy')
                address = public_address(host)
            except (PermissionError, OSError) as error:
                print(json.dumps({'host': host, 'token': bool(token), 'refused': str(error)}), flush=True)
                self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                return
        print(json.dumps({'host': host, 'rule': rule}), flush=True)
        with socket.create_connection((address, 443), timeout=10) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
            # Unbuffered input avoids consuming the first TLS bytes with the headers.
            self.connection.settimeout(30); upstream.settimeout(30)
            deadline = time.monotonic() + server.connection_seconds
            while time.monotonic() < deadline:
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                for source in ready:
                    raw = source.recv(65536)
                    if not raw:
                        return
                    (upstream if source is self.connection else self.connection).sendall(raw)
    rbufsize = 0

class Server(socketserver.ThreadingTCPServer):
    allowed_hosts = frozenset()
    package_hosts = frozenset()
    resolved_hosts = {}
    connection_seconds = 240
    browse_url = None
    publisher = None
    allow_reuse_address = True
    daemon_threads = True

    def policy(self, token):
        """The broker's record for a stay's browse token on this Mac, rechecked after POLICY_TTL seconds, so a token
        stops working within that long after its stay ends."""
        if not re.fullmatch(r'[0-9a-f]{32}', token) or not self.browse_url:
            raise PermissionError('unknown browse token')
        cache = self.__dict__.setdefault('policies', {})
        if token not in cache or time.monotonic() - cache[token][0] > POLICY_TTL:
            cache.pop(token, None)
            with urllib.request.urlopen(f'{self.browse_url}{token}?publisher={self.publisher}', timeout=10) as response:
                p = json.loads(response.read(65536))
            if (p['mode'] not in ('none', 'named', 'open') or type(p['expires_at']) is not int
                    or not all(re.fullmatch(HOST_RE, h) for h in p['hosts'])):
                raise PermissionError('malformed browse policy')
            cache[token] = (time.monotonic(), p)
        if cache[token][1]['expires_at'] <= time.time():
            raise PermissionError('browse policy expired')
        return cache[token][1]

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--listen', required=True)
    p.add_argument('--port', type=int, default=18443)
    p.add_argument('--allow-host', action='append', required=True, help='exact CONNECT hostname; repeat for broker and quick tunnel')
    p.add_argument('--resolve',action='append',default=[],help='per-process HOST=public IPv4 DNS binding')
    p.add_argument('--connection-seconds', type=int, default=240)
    p.add_argument('--browse-url', help='broker prefix mapping a stay browse token to its policy, e.g. https://pod/relay-broker/agent/browse/')
    p.add_argument('--publisher', help="this Mac's publisher address; the broker answers only for stays placed here")
    a = p.parse_args()
    if not 1 <= a.connection_seconds <= 3600:
        p.error('connection lifetime must be 1..3600 seconds')
    if bool(a.browse_url) != bool(a.publisher) or (a.publisher and not re.fullmatch(r'0x[0-9a-fA-F]{40}', a.publisher)):
        p.error('--browse-url and --publisher (an 0x address) go together')
    if any(not re.fullmatch(HOST_RE, host) for host in a.allow_host):
        p.error('exact lowercase DNS hostnames required')
    bindings={}
    for value in a.resolve:
        host,address=value.split('=',1)
        ip=ipaddress.IPv4Address(address)
        if host not in a.allow_host or not ip.is_global:p.error('resolve requires an allowlisted host and public IPv4 address')
        bindings[host]=str(ip)
    with Server((a.listen, a.port), Handler) as server:
        server.resolved_hosts = bindings
        server.allowed_hosts = frozenset(a.allow_host)
        server.package_hosts = frozenset(json.loads(PACKAGE_HOSTS.read_text()))
        server.browse_url = a.browse_url
        server.publisher = a.publisher.lower() if a.publisher else None
        server.connection_seconds = a.connection_seconds
        server.serve_forever()
