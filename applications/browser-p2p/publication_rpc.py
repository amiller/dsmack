"""Ordered transport retries for one signed, receipt-checked locator transaction."""
import json
from urllib.parse import urlsplit


class OrderedRPC:
    def __init__(self, urls, call):
        self.urls, self.call = urls, call
        self.verified = set()

    def __call__(self, _url, method, params):
        for url in self.urls:
            try:
                if url not in self.verified:
                    if self.call(url, 'eth_chainId', []) != '0x14a34':
                        raise ValueError('publication RPC is not Base Sepolia')
                    self.verified.add(url)
                return self.call(url, method, params)
            except Exception as error:
                # Host and error class identify failed providers without exposing
                # a keyed URL or raw transaction reflected by a transport error.
                print(json.dumps(dict(event='publication_rpc_failed', provider=urlsplit(url).hostname,
                                      method=method, error=type(error).__name__, status=getattr(error, 'code', None))), flush=True)
        raise RuntimeError('all publication RPC providers failed for '+method)
