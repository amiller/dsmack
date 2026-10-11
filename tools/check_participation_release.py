#!/usr/bin/env python3
"""Bounded, read-only checks for the published participation release. No enrollment."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "packaging/participation/release-v0.1.0-rc.3.json"
MAX_BYTES = 8 * 1024 * 1024

class CheckFailure(Exception):
    pass

class Reader:
    def __init__(self, timeout=15, duration=90):
        self.timeout = timeout
        self.deadline = time.monotonic() + duration

    def read(self, url, payload=None):
        if not url.startswith("https://"):
            raise CheckFailure("HTTPS required")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CheckFailure("overall deadline exceeded")
        req = urllib.request.Request(url, data=None if payload is None else json.dumps(payload).encode(),
            headers={"User-Agent": "Dsmack-release-check/1", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=min(self.timeout, remaining)) as response:
                data = response.read(MAX_BYTES + 1)
        except (OSError, urllib.error.URLError):
            raise CheckFailure("HTTP request failed") from None
        if len(data) > MAX_BYTES:
            raise CheckFailure("response exceeds byte limit")
        if time.monotonic() > self.deadline:
            raise CheckFailure("overall deadline exceeded")
        return data

    def json(self, url, payload=None):
        try:
            return json.loads(self.read(url, payload))
        except (ValueError, UnicodeError):
            raise CheckFailure("invalid JSON") from None

def need(condition, reason):
    if not condition:
        raise CheckFailure(reason)

def check(manifest, reader):
    results = []
    def record(name, fn):
        try:
            details = fn()
            results.append({"check": name, "passed": True, **details})
        except (CheckFailure, KeyError, TypeError, ValueError) as error:
            # Fixed errors only; no response bodies, query strings or credentials.
            reason = str(error) if isinstance(error, CheckFailure) else "malformed response"
            results.append({"check": name, "passed": False, "reason": reason})
    asset = manifest["asset"]
    def package():
        data = reader.read(asset["url"])
        need(len(data) == asset["bytes"], "package size mismatch")
        digest = hashlib.sha256(data).hexdigest()
        need(digest == asset["sha256"], "package hash mismatch")
        return {"sha256": digest, "bytes": len(data)}
    record("published-package", package)
    chain = manifest["chain"]
    def rpc(method, params):
        data = reader.json(chain["rpc"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        need(isinstance(data, dict) and data.get("jsonrpc") == "2.0" and data.get("id") == 1
             and "error" not in data and "result" in data, "RPC refused or malformed")
        return data["result"]
    def chain_check():
        need(int(rpc("eth_chainId", []), 16) == chain["id"], "chain ID mismatch")
        block = rpc("eth_blockNumber", [])
        int(block, 16)
        code_sizes = {}
        for name in ("registry", "receipts"):
            code = rpc("eth_getCode", [chain[name], block])
            need(isinstance(code, str) and code.startswith("0x"), "malformed contract code")
            raw = bytes.fromhex(code[2:])
            need(bool(raw), "contract code missing")
            code_sizes[name] = len(raw)
        paused = rpc("eth_call", [{"to": chain["registry"], "data": "0x5c975abb"}, block])
        need(paused == "0x" + "0" * 64, "network paused or malformed pause state")
        return {"chainId": chain["id"], "block": block, "contractCodeBytes": code_sizes, "paused": False}
    record("chain-readiness", chain_check)
    def relay_check():
        info = reader.json(manifest["relay"] + "/info")
        need(isinstance(info, dict) and info.get("chainId") == chain["id"] and info.get("protocolVersion") == manifest["protocolVersion"]
             and str(info.get("registry")).lower() == chain["registry"].lower(), "relay network mismatch")
        status = reader.json(manifest["relay"] + "/status")
        need(isinstance(status, dict) and status.get("sponsorWritesPaused") is False, "relay sponsor paused or unknown")
        need(isinstance(status.get("pending"), list), "relay pending state malformed")
        return {"protocolVersion": info["protocolVersion"], "sponsorWritesPaused": False,
                "pendingSponsorTransactions": len(status["pending"])}
    record("relay-readiness", relay_check)
    return {"schemaVersion": 1, "release": manifest["release"], "observedAtUnix": int(time.time()),
        "passed": all(item["passed"] for item in results), "checks": results,
        "scope": "Public package integrity and read-only relay/chain readiness only",
        "nodeStarted": False, "enrollmentSent": False, "transactionsSent": False,
        "freshPeerAdmission": False, "independentDeviceAcceptance": False,
        "couponReadiness": "not checked"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = check(json.loads(args.manifest.read_text()), Reader())
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(2, "Invalid or unreadable release manifest.\n")
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
