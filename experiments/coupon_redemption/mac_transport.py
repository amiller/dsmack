"""TLS-preserving HTTPS over the measured Mac runner CONNECT allowlist.

The host transports ciphertext; credentials stay in the guest TLS connection.
No HTTP forward proxy, redirect, DNS fallback or host-selected destination.
"""
import http.client
import socket
import ssl
import urllib.request

from .transport import HOST, NearHTTPS, _perform_http
from .issuance_guard import BASE_RPC, GuardRPC, NoRedirect

SOCKET = '/run/egress.sock'
HOSTS = frozenset((HOST, 'mainnet.base.org'))


class RunnerHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port=None, *, timeout=10, context=None, **kwargs):
        # urllib supplies host:443; no userinfo or arbitrary ports are admitted.
        if host.endswith(':443'):
            host = host[:-4]
        if host not in HOSTS or port not in (None, 443) or kwargs:
            raise ValueError('Mac HTTPS destination refused')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        super().__init__(host, 443, timeout=timeout, context=context)

    def connect(self):
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect(SOCKET)
            raw.sendall(('CONNECT ' + self.host + ':443 HTTP/1.1\r\nHost: '
                         + self.host + ':443\r\n\r\n').encode('ascii'))
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                byte = raw.recv(1)
                if not byte or len(header) >= 4096:
                    raise ValueError('Mac CONNECT refused')
                header.extend(byte)
            first = bytes(header).split(b'\r\n', 1)[0].split(b' ', 2)
            if len(first) < 2 or first[0] not in (b'HTTP/1.0', b'HTTP/1.1') or first[1] != b'200':
                raise ValueError('Mac CONNECT refused')
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _near_worker(pipe, method, target, bearer, body, socket_timeout, max_response):
    # Existing parser, bounds and failure semantics; explicit child-local factory.
    try:
        pipe.send(_perform_http(method, target, bearer, body, socket_timeout, max_response, RunnerHTTPS))
    except Exception:
        try:
            pipe.send(('error', 'provider worker failed'))
        except Exception:
            pass
    finally:
        pipe.close()


class MacNearHTTPS(NearHTTPS):
    _worker_target = staticmethod(_near_worker)


class GuardRunnerHTTPS(RunnerHTTPS):
    def __init__(self, host, port=None, **kwargs):
        if host not in ('mainnet.base.org', 'mainnet.base.org:443'):
            raise ValueError('Mac Base-only courier required')
        super().__init__(host, port, **kwargs)

    def request(self, method, url, body=None, headers=None, *, encode_chunked=False):
        # urllib forces Connection: close. The admitted Runner path can truncate
        # chunked bodies when the upstream closes; retain it until body completion.
        # urllib/HTTPResponse still closes this one local connection afterwards.
        copied = {key: value for key, value in (headers or {}).items()
                  if key.lower() != 'connection'}
        copied['Connection'] = 'keep-alive'
        return super().request(method, url, body=body, headers=copied,
                               encode_chunked=encode_chunked)


class GuardRunnerHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(GuardRunnerHTTPS, request)


class MacGuardRPC(GuardRPC):
    def __init__(self, url):
        if url != BASE_RPC:
            raise ValueError('Mac Base-only courier required')
        super().__init__(url)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                NoRedirect, GuardRunnerHTTPSHandler())
