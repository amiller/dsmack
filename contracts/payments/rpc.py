"""Base Sepolia reads with ordered failover and per-provider quota backoff."""
import json
import time
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

CHAIN_ID = 84532
URLS = (
    "https://sepolia.base.org",
    "https://base-sepolia-rpc.publicnode.com",
    "https://base-sepolia.drpc.org",
)


class RPCError(RuntimeError):
    def __init__(self, method, error):
        super().__init__(f"{method}: RPC error {error.get('message', 'missing result')}")
        self.throttled = error.get('code') in (-32005, -32007) or any(
            word in str(error.get('message', '')).lower()
            for word in ('rate limit', 'request limit', 'too many requests', '429'))
        self.reverted = error.get('code') == 3 or 'revert' in str(error.get('message', '')).lower()


def call(url, method, params):
    request = Request(url, json.dumps({"jsonrpc": "2.0", "id": 1,
                                      "method": method, "params": params}).encode(),
                      {"Content-Type": "application/json", "User-Agent": "dsmack-payments/1"})
    with urlopen(request, timeout=20) as response:
        result = json.load(response)
    if "error" in result or "result" not in result:
        raise RPCError(method, result.get("error", {}))
    return result["result"]


class ChainReader:
    def __init__(self, urls=URLS, *, clock=time.time):
        if not urls:
            raise ValueError("RPC URLs required")
        self.urls = tuple(dict.fromkeys(urls))
        self.clock = clock
        self.verified = set()
        self.backoff = {url: (0, 0) for url in self.urls}

    def perform(self, operation):
        errors = []
        for url in self.urls:
            strikes, until = self.backoff[url]
            if until > self.clock():
                errors.append(f"{urlsplit(url).hostname}: cooling down")
                continue
            try:
                if url not in self.verified:
                    if int(call(url, 'eth_chainId', []), 16) != CHAIN_ID:
                        raise ValueError('Base Sepolia required')
                    self.verified.add(url)
                value = operation(url)
                self.backoff[url] = (0, 0)
                return value
            except Exception as error:
                if getattr(error, 'reverted', False):
                    raise
                if getattr(error, 'code', None) == 429 or getattr(error, 'throttled', False):
                    delay = 0
                    retry = error.headers.get('Retry-After') if isinstance(error, HTTPError) and error.headers else None
                    if retry:
                        try:
                            delay = float(retry) if retry.isdecimal() else parsedate_to_datetime(retry).timestamp() - self.clock()
                        except (ValueError, TypeError, OverflowError):
                            pass
                    self.backoff[url] = (strikes + 1, self.clock() + max(min(2 ** strikes, 60), delay))
                # Keep keyed URLs and signed transaction bytes out of diagnostics.
                reason = str(error) if isinstance(error, InvalidHeader) else type(error).__name__
                errors.append(f"{urlsplit(url).hostname}: {reason}")
                if isinstance(error, HTTPError):
                    error.close()
        raise RuntimeError('RPC unavailable (Base Sepolia): ' + '; '.join(errors))

    def read(self, method, params):
        return self.perform(lambda url: call(url, method, params))

    def request(self, _url, method, params):
        return self.read(method, params)

    def finalized(self):
        def head(url):
            header = call(url, 'eth_getBlockByNumber', ['finalized', False])
            if not header or int(header['number'], 16) < 0 or len(header['hash']) != 66:
                raise InvalidHeader('missing finalized block')
            age = self.clock() - int(header['timestamp'], 16)
            if age < -30 or age > 1800:
                raise InvalidHeader(f'finalized block stale or future: age {age:.0f}s')
            pinned = call(url, 'eth_getBlockByNumber', [header['number'], False])
            if not pinned or pinned['hash'].lower() != header['hash'].lower() or int(pinned['number'], 16) != int(header['number'], 16):
                raise InvalidHeader('snapshot block changed')
            return {key: header[key] for key in ('number', 'hash', 'timestamp')}
        return self.perform(head)

    def at(self, method, args, header):
        def pinned(url):
            if 'number' in header:
                block = call(url, 'eth_getBlockByNumber', [header['number'], False])
                if not block or block['hash'].lower() != header['hash'].lower() or int(block['number'], 16) != int(header['number'], 16):
                    raise InvalidHeader('snapshot block changed')
            return call(url, method, [*args, {'blockHash': header['hash'], 'requireCanonical': True}])
        return self.perform(pinned)


class InvalidHeader(RuntimeError):
    pass
