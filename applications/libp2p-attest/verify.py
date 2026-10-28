#!/usr/bin/env python3
"""Check that a libp2p peer's guest Attest binds its PeerId. Exits nonzero on any mismatch.

verify.py --enrollment DIR --cdhash HEX --os-image HEX --manifest FILE [--run DIR] <attestation> <peer id hex>

enrollment holds the runner key's attestation.cbor, clientData.bin and keyId.txt; manifest is the exact
compose manifest bytes. --run (the runner's launch-client-data.bin and launch-assertion.cbor, written
after the VM halts) also ties the Attest to that launch.
"""
import argparse
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'dstack-compat')]
import guest_attest
from verifier.core import require, unb64, verify_assertion, verify_key
from verifier.macos_policy import policy, root

DOMAIN = b'dsmack-libp2p-peer/1'


def report_data(peer_id, receipt_key=None):
    return hashlib.sha256(DOMAIN + peer_id).digest() + (receipt_key if receipt_key is not None else bytes(32))


def peer_string(raw):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, result = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def check(blob, peer_id, enrollment, cdhash, os_image_hash, manifest, run=None, broker_key=None):
    receipt_key = None
    if broker_key is not None:
        envelope = json.loads(blob)
        receipt_key = bytes.fromhex(envelope["receipt_key"])
        require(len(receipt_key) == 32, "receipt key must be Ed25519")
        blob = bytes.fromhex(envelope["attestation"])
        compose = json.loads(json.loads(manifest)["docker_compose_file"])["services"]
        command = compose["peer"]["command"]
        require(len(bytes.fromhex(broker_key)) == 32 and len(command) == 6 and
                command[0] == "serve" and command[-1] == broker_key, "compose does not measure this broker key")
    a = guest_attest.verify(blob)
    rule = policy(bytes.fromhex(cdhash))
    attestation = (enrollment/'attestation.cbor').read_bytes()
    key_id = (enrollment/'keyId.txt').read_text().strip()
    key = verify_key(attestation, key_id, (enrollment/'clientData.bin').read_bytes(), rule, root(), time.time())['public_key']
    require(a['key_id'] == unb64(key_id), 'Attest key is not the enrolled key')
    signed = verify_assertion(a['assertion'], guest_attest.client_data(a['os_image_hash'], a['manifest_sha256'], a['run'],
                              a['head'], a['caller'], a['report_data']), key, 0, rule)
    require(a['os_image_hash'].hex() == os_image_hash, 'Attest is not for this image')
    require(a['manifest_sha256'] == hashlib.sha256(manifest).digest(), 'Attest is not for this compose')
    service, = json.loads(json.loads(manifest)['docker_compose_file'])['services']
    require(a['caller'] == hashlib.sha256(service.encode()).digest(), 'Attest caller is not the peer service')
    require(a['report_data'] == report_data(peer_id, receipt_key), 'Attest does not bind this PeerId and receipt key')
    out = {'peer_id_hex': peer_id.hex(), 'counter': signed['counter'], 'head': a['head'].hex(), 'run': a['run'].hex()}
    if receipt_key is not None:
        out["receipt_key"] = receipt_key.hex()
        out["broker_key"] = broker_key
    if run:
        launch = (run/'launch-client-data.bin').read_bytes()
        out['launch_counter'] = verify_assertion((run/'launch-assertion.cbor').read_bytes(), launch, key,
                                                 signed['counter'], rule)['counter']
        require(a['run'] == hashlib.sha256(launch).digest(), 'Attest is not from this launch')
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('enrollment', 'manifest', 'run'):
        p.add_argument('--' + name, type=Path, required=name != 'run')
    p.add_argument('--cdhash', required=True)
    p.add_argument('--os-image', required=True)
    p.add_argument("--broker-key", help="require the measured relay broker key and extended receipt binding")
    p.add_argument("--receipts", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument('attestation', type=Path)
    p.add_argument('peer_id')
    a = p.parse_args()
    result = check(a.attestation.read_bytes(), bytes.fromhex(a.peer_id), a.enrollment, a.cdhash, a.os_image,
                   a.manifest.read_bytes(), a.run, a.broker_key)
    if a.receipts:
        require(a.broker_key is not None, "receipts require the attested receipt key")
        receipts = json.loads(a.receipts.read_bytes())
        for receipt in receipts:
            body = {k: v for k, v in receipt.items() if k != "sig"}
            require(set(body) == {"grant_id", "bytes_used", "client_peer", "relay_peer", "run"}, "receipt fields")
            raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(result["receipt_key"])).verify(bytes.fromhex(receipt["sig"]), raw)
            require(body["run"] == result["run"], "receipt is from another run")
            # The string PeerId is checked by the client against its grant; this check
            # also binds its decoded bytes to the authenticated peer passed by libp2p.
            require(body["relay_peer"] == peer_string(bytes.fromhex(a.peer_id)), "receipt relay mismatch")
        result["receipts"] = receipts
    if a.output:
        a.output.write_text(json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
