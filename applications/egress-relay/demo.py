#!/usr/bin/env python3
"""Fetch test credit, attest the relay, curl over local SOCKS, and verify its receipt."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--peer", required=True)
    p.add_argument("--broker-url")
    p.add_argument("--signer-key", type=Path, default=Path("test-broker.key"))
    p.add_argument("--client-key", type=Path, default=Path("test-client.key"))
    p.add_argument("--grant", type=Path, help="use an existing signed grant")
    p.add_argument("--bytes", type=int, default=1024*1024)
    p.add_argument("--ttl", type=int, default=300)
    p.add_argument("--url", default="https://ip.me")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--listen", default="127.0.0.1:1080")
    p.add_argument("verifier", nargs=argparse.REMAINDER, help="-- python3 verify.py --enrollment ... --manifest ... --cdhash ... --os-image ...")
    a = p.parse_args()
    binary = str(a.binary.resolve())
    verifier = a.verifier[1:] if a.verifier[:1] == ["--"] else a.verifier
    if not verifier:
        p.error("a verifier command is required after --")
    a.out.mkdir(parents=True, exist_ok=False)
    if not a.client_key.exists():
        subprocess.run([binary, "keygen", str(a.client_key)], check=True)
    client = subprocess.check_output([binary, "id", str(a.client_key)], text=True).strip()
    relay = a.peer.rsplit("/p2p/", 1)[1]
    if a.broker_url:
        base = a.broker_url.rstrip("/")
        with urlopen(base + "/key", timeout=30) as response:
            broker_key = json.load(response)["public_key"]
    else:
        if not a.signer_key.exists():
            subprocess.run([sys.executable, str(HERE/"signer.py"), "keygen", str(a.signer_key)], check=True)
        broker_key = subprocess.check_output([sys.executable, str(HERE/"signer.py"), "key", str(a.signer_key)], text=True).strip()
    grant_path = a.out/"grant.json"
    if a.grant:
        raw = a.grant.read_bytes().strip()
    elif a.broker_url:
        request = Request(base + "/grant", data=json.dumps(dict(relay_peer=relay, client_peer=client, bytes=a.bytes)).encode(),
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=30) as response:
            raw = response.read()
    else:
        raw = subprocess.check_output([sys.executable, str(HERE/"signer.py"), "grant", str(a.signer_key), relay, client,
                                       str(a.bytes), str(int(time.time())+a.ttl)]).strip()
    grant = json.loads(raw)
    grant_path.write_bytes(raw)
    verify = verifier + ["--broker-key", broker_key]
    checked = a.out/"attestation.json"
    # Keep the attestation envelope and authenticated remote id for receipt verification.
    wrapper = a.out/"verify.py"
    wrapper.write_text("import pathlib,shutil,subprocess,sys\n" +
        "out=pathlib.Path(" + repr(str(a.out.resolve())) + ")\n" +
        "shutil.copyfile(sys.argv[1],out/'attestation-envelope.json')\n" +
        "(out/'peer-id.hex').write_text(sys.argv[2])\n" +
        "raise SystemExit(subprocess.call(" + repr(verify+["--output",str(checked.resolve())]) + "+sys.argv[1:]))\n")
    env = os.environ.copy()
    log = (a.out/"recipient.log").open("wb")
    process = subprocess.Popen([binary, "recipient", a.peer, a.listen, str(a.client_key), str(grant_path),
                                sys.executable, str(wrapper)], stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        host, port = a.listen.rsplit(":", 1)
        deadline = time.monotonic()+90
        while True:
            if process.poll() is not None:
                raise RuntimeError("recipient failed: " + (a.out/"recipient.log").read_text())
            try:
                with socket.create_connection((host, int(port)), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("recipient listener")
                time.sleep(0.1)
        result = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "90", "--socks5-hostname", a.listen,
                                 "--output", str(a.out/"response"), a.url], capture_output=True)
        (a.out/"curl-stderr.txt").write_bytes(result.stderr)
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
    receipts = a.out/"receipts.json"
    subprocess.run([binary, "receipt", a.peer, str(a.client_key), str(receipts), *verify], check=True)
    remote = (a.out/"peer-id.hex").read_text().strip()
    subprocess.run([*verify, "--receipts", str(receipts), "--output", str(a.out/"receipt-verification.json"),
                    str(a.out/"attestation-envelope.json"), remote], check=True)
    # Check the receipt belongs to exactly the grant this client presented.
    found = [r for r in json.loads(receipts.read_bytes()) if r["grant_id"] == grant["grant_id"]]
    if result.returncode == 0 and not found:
        raise ValueError("relay returned no receipt for this grant")
    for receipt in found:
        if receipt["client_peer"] != client or receipt["relay_peer"] != relay or not 0 <= receipt["bytes_used"] <= grant["bytes"]:
            raise ValueError("receipt does not match this grant")
    summary = dict(curl_exit=result.returncode, client_peer=client, relay_peer=relay, grant_id=grant["grant_id"],
                   response_bytes=(a.out/"response").stat().st_size if (a.out/"response").exists() else 0,
                   receipts=found, attestation_verified=True, receipts_verified=bool(found))
    (a.out/"check.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
