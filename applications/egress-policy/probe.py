"""Credential-free checks, run in the restricted workload namespace."""
import http.client
import json
import socket
import ssl
import struct
import sys


def report(check, **fields):
    print(json.dumps(dict(check=check, **fields)), flush=True)


def dns(gateway, name, tcp=False, kind=1):
    q = b'\x12\x34\x01\x00\x00\x01' + b'\x00' * 6
    q += b''.join(bytes([len(s)]) + s.encode() for s in name.split('.'))
    q += b'\x00' + struct.pack('!HH', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.connect((gateway, 53))
        s.sendall((struct.pack('!H', len(q)) if tcp else b'') + q)
        if tcp:
            size = struct.unpack('!H', s.recv(2))[0]
            data = b''
            while len(data) < size:
                data += s.recv(size - len(data))
        else:
            data = s.recv(512)
    return struct.unpack('!HH', data[2:6])[0] & 15, struct.unpack('!H', data[6:8])[0], data


def request(gateway, host, target='/', method='GET', headers=None):
    c = http.client.HTTPConnection(gateway, 8080, timeout=20)
    c.request(method, target, headers={'Host': host, **(headers or {})})
    r = c.getresponse()
    status = r.status
    size = len(r.read())
    c.close()
    return status, size


def raw(gateway, data):
    with socket.create_connection((gateway, 8080), timeout=3) as s:
        s.sendall(data)
        return int(s.recv(4096).split(b' ')[1])


def workload(gateway, shared_ip, second):
    rc, n, data = dns(gateway, 'api.anthropic.com')
    assert (rc, n) == (0, 1) and socket.inet_ntoa(data[-4:]) == gateway
    report('allowed_dns_synthesized', address=gateway)
    assert socket.gethostbyname('api.anthropic.com') == gateway
    try:
        socket.gethostbyname('blocked.example')
    except socket.gaierror:
        report('system_resolver_denied')
    else:
        raise AssertionError('system resolver escaped')
    for tcp in (False, True):
        for name in ('blocked.example', 'secret.api.anthropic.com'):
            rc, n, _ = dns(gateway, name, tcp)
            assert (rc, n) == (5, 0)
            report('denied_dns', transport='tcp' if tcp else 'udp', rcode=rc)
    assert dns(gateway, 'api.anthropic.com', kind=28)[:2] == (0, 0)
    report('aaaa_has_no_answer')

    # No credential, no model invocation: a single GET / establishes real TLS.
    status, size = request(gateway, 'api.anthropic.com:8080')
    assert status not in (403, 429, 502), (status, size)
    report('allowed_cloudflare_https', hostname='api.anthropic.com', status=status, response_bytes=size)
    for label, host, target, method in (
        ('other_name_same_cloudflare_ip', second, '/', 'GET'),
        ('ipv4_literal', shared_ip, '/', 'GET'),
        ('ipv6_literal', '[2606:4700::1111]:8080', '/', 'GET'),
        ('fronting_allowed_url_blocked_host', second, 'https://api.anthropic.com/', 'GET'),
        ('fronting_blocked_url_allowed_host', 'api.anthropic.com', 'https://' + second + '/', 'GET'),
        ('connect_tunnel', 'api.anthropic.com', '/', 'CONNECT'),
        ('method', 'api.anthropic.com', '/', 'POST'),
        ('path', 'api.anthropic.com', '/v1/messages', 'GET'),
        ('query', 'api.anthropic.com', '/?secret=fixture', 'GET'),
    ):
        status, _ = request(gateway, host, target, method)
        assert status == 403, (label, status)
        report(label, status=status)
    status = raw(gateway, b'GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nHost: blocked.example\r\nConnection: close\r\n\r\n')
    assert status == 400
    report('duplicate_host', status=status)
    status = raw(gateway, b'POST / HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n')
    assert status in (400, 403)
    report('ambiguous_framing', status=status)
    for address, port, label in ((shared_ip, 443, 'direct_ipv4'), ('1.1.1.1', 53, 'direct_dns_tcp'), ('127.0.0.11', 53, 'docker_dns_tcp')):
        try:
            with socket.create_connection((address, port), timeout=1):
                raise AssertionError(label + ' unexpectedly connected')
        except (TimeoutError, OSError):
            report(label, result='blocked')
    for address, label in (('127.0.0.11', 'docker_dns_udp'), ('1.1.1.1', 'external_dns_udp')):
        try:
            dns(address, 'example.com')
        except (TimeoutError, OSError):
            report(label, result='blocked')
        else:
            raise AssertionError(label + ' escaped')
    try:
        socket.create_connection(('2606:4700::1111', 443), timeout=1).close()
    except OSError:
        report('direct_ipv6', result='blocked_or_no_route')
    else:
        raise AssertionError('IPv6 escaped')
    # Use a reachable private address so lack of an Internet route cannot
    # hide whether the UDP/443 firewall rule actually drops the packet.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.sendto(b'quic-fixture', (gateway, 443))
        except PermissionError:
            pass  # Linux may return EPERM for a local nftables output drop.
    report('udp_quic_probe_for_drop_counter')
    report('workload_checks', result='PASS')


def observer():
    ip = socket.gethostbyname('api.anthropic.com')
    # The same Cloudflare IP presents independently authenticated names.
    ctx = ssl.create_default_context()
    for name in ('api.anthropic.com', 'www.cloudflare.com'):
        with socket.create_connection((ip, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=name) as tls:
                report('shared_cloudflare_ip', ip=ip, name=name, tls=tls.version(), certificate_verified=True)
    return ip


if __name__ == '__main__':
    if sys.argv[1] == 'observer':
        observer()
    else:
        workload(*sys.argv[1:])
