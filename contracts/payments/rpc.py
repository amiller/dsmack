"""Base Sepolia finalized 2-of-3 RPC reads. No signing or submission."""
import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen

CHAIN_ID = 84532
URLS = (
    "https://sepolia.base.org",
    "https://base-sepolia-rpc.publicnode.com",
    "https://base-sepolia.drpc.org",
)


def call(url, method, params):
    request = Request(url, json.dumps({"jsonrpc": "2.0", "id": 1,
                                      "method": method, "params": params}).encode(),
                      {"Content-Type": "application/json", "User-Agent": "dsmack-payments/1"})
    with urlopen(request, timeout=20) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: RPC error {result['error']}")
    return result["result"]


class Quorum:
    def __init__(self, urls=URLS):
        if len(urls) != 3 or len(set(urls)) != 3:
            raise ValueError("three distinct independent RPC URLs required")
        self.urls = tuple(urls)

    def collect(self, method, params):
        def query(url):
            try:
                return url, call(url, method, params), None
            except Exception as exc:
                return url, None, f"{type(exc).__name__}: {exc}"
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(query, self.urls))
        return results

    @staticmethod
    def majority(results):
        votes = Counter(json.dumps(value, sort_keys=True) for _, value, error in results if not error)
        if not votes or votes.most_common(1)[0][1] < 2:
            failures = [error for _, _, error in results if error]
            raise RuntimeError(f"RPC quorum missing/disagrees; provider errors: {failures}")
        encoded = votes.most_common(1)[0][0]
        return json.loads(encoded), tuple(url for url, value, error in results
                                          if not error and json.dumps(value, sort_keys=True) == encoded)

    def read(self, method, params):
        return self.majority(self.collect(method, params))[0]

    def finalized(self):
        # A wrong-chain provider is excluded before it can vote on state.
        chains = self.collect("eth_chainId", [])
        good = tuple(url for url, value, error in chains if not error and value == hex(CHAIN_ID))
        if len(good) < 2:
            raise RuntimeError("fewer than two Base Sepolia RPCs")
        self.urls = good
        heads = self.collect("eth_getBlockByNumber", ["finalized", False])
        heights = [int(value["number"], 16) for _, value, error in heads if not error and value]
        if len(heights) < 2:
            raise RuntimeError("fewer than two finalized heads")
        # Read one common finalized height, never moving 'latest' state.
        height = min(heights)
        headers = self.collect("eth_getBlockByNumber", [hex(height), False])
        normalized = [(url, {k: value[k] for k in ("number", "hash", "timestamp")} if value else None, error)
                      for url, value, error in headers]
        header, voters = self.majority(normalized)
        if not header:
            raise RuntimeError("missing common finalized block")
        age = time.time() - int(header["timestamp"], 16)
        if age < -30 or age > 1800:
            raise RuntimeError(f"finalized block stale or future: age {age:.0f}s")
        self.urls = voters
        return header

    def at(self, method, args, header):
        return self.read(method, [*args, {"blockHash": header["hash"], "requireCanonical": True}])
