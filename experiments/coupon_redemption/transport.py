"""Bounded NEAR HTTPS transport; certificate validation, no redirects or proxies.

Each request runs in a child process so the hard deadline also bounds DNS and
slow-drip responses. Terminating a timed-out POST cannot undo server effects:
issuers must treat ALL transport errors after invocation as ambiguous creation.
No response body, token, URL query, or raw exception is included in errors.
"""

import http.client
import json
import math
import multiprocessing
import ssl
from urllib.parse import urlsplit

from .spike import RedemptionError

HOST = 'cloud-api.near.ai'
MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class TransportError(RedemptionError):
    pass


def _reject_constant(value):
    raise ValueError('nonfinite JSON')


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('nonfinite JSON number')
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _perform_http(method, target, bearer, body, socket_timeout, max_response, connection_factory=None):
    # create_default_context() honors SSLKEYLOGFILE. Constructing the context
    # explicitly avoids ever opening that file or exporting traffic secrets.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    factory = connection_factory or http.client.HTTPSConnection
    connection = factory(HOST, 443, timeout=socket_timeout, context=context)
    try:
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
                   'User-Agent': 'dsmack-coupon-spike/1'}
        if bearer is not None:
            headers['Authorization'] = 'Bearer ' + bearer
        if body is not None:
            headers['Content-Type'] = 'application/json'
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            # Never follow Location, and never read/print an error response.
            return ('error', 'provider HTTP request rejected')
        if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
            return ('error', 'unsupported provider response encoding')
        length = response.getheader('Content-Length')
        if length is not None and (not length.isdigit() or int(length) > max_response):
            return ('error', 'provider response exceeds size limit')
        data = response.read(max_response + 1)
        if len(data) > max_response:
            return ('error', 'provider response exceeds size limit')
        value = json.loads(data.decode('utf-8'), parse_constant=_reject_constant, parse_float=_finite_float,
                           object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            return ('error', 'invalid provider JSON response')
        return ('ok', value)
    except Exception:
        return ('error', 'provider HTTPS or JSON request failed')
    finally:
        connection.close()


def _worker(pipe, method, target, bearer, body, socket_timeout, max_response):
    try:
        pipe.send(_perform_http(method, target, bearer, body, socket_timeout, max_response))
    except Exception:
        # No exception serialization: SSL/HTTP libraries can include secret data.
        try:
            pipe.send(('error', 'provider worker failed'))
        except Exception:
            pass
    finally:
        pipe.close()


class NearHTTPS:
    _worker_target = None
    def __init__(self, deadline=30.0, socket_timeout=10.0, max_response=MAX_RESPONSE_BYTES):
        if (not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or not 0 < deadline <= 120
                or not isinstance(socket_timeout, (int, float)) or not math.isfinite(socket_timeout)
                or not 0 < socket_timeout <= deadline or type(max_response) is not int
                or not 1 <= max_response <= MAX_RESPONSE_BYTES):
            raise ValueError('invalid transport bounds')
        self.deadline = deadline
        self.socket_timeout = socket_timeout
        self.max_response = max_response

    def __call__(self, method, url, bearer, json_body):
        # Validate everything before spawning or opening a socket.
        try:
            parts = urlsplit(url)
            if (method not in ('GET', 'POST') or parts.scheme != 'https'
                    or parts.netloc != HOST or parts.username or parts.password
                    or parts.fragment or not parts.path.startswith('/v1/')
                    or any(ord(c) < 33 or ord(c) > 126 for c in url)):
                raise ValueError()
            if bearer is not None and (not isinstance(bearer, str) or not bearer
                    or len(bearer) > 16384 or any(ord(c) < 33 or ord(c) > 126 for c in bearer)):
                raise ValueError()
            if method == 'GET' and json_body is not None:
                raise ValueError()
            body = None if json_body is None else json.dumps(json_body, allow_nan=False).encode()
            if body is not None and len(body) > MAX_REQUEST_BYTES:
                raise ValueError()
            target = parts.path + ('?' + parts.query if parts.query else '')
        except Exception:
            raise TransportError('invalid NEAR request configuration') from None
        context = multiprocessing.get_context('spawn')
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=self._worker_target or _worker, args=(sender, method, target, bearer, body,
                                                       self.socket_timeout, self.max_response))
        try:
            process.start()
            sender.close()
            if not receiver.poll(self.deadline):
                raise TransportError('provider request deadline exceeded; outcome may be ambiguous')
            status, result = receiver.recv()
            if status != 'ok':
                raise TransportError(result)
            return result
        except TransportError:
            raise
        except Exception:
            raise TransportError('provider worker failed; outcome may be ambiguous') from None
        finally:
            sender.close()
            receiver.close()
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1)
                process.close()
