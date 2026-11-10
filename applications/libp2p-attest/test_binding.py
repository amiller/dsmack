"""The protocol's recorded inputs, consumed by both reference verifiers."""
import importlib.util
import json
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('peer_verify', Path(__file__).with_name('verify.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
from verifier.core import Reject


def peer_bytes(value):
    n = 0
    for c in value:
        n = n * 58 + '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(c)
    return bytes(len(value) - len(value.lstrip('1'))) + n.to_bytes((n.bit_length() + 7) // 8, 'big')


def test_shared_signed_binding_examples():
    f = json.loads((ROOT/'applications/relay-broker/fixtures/bind.json').read_bytes())
    for r in (f['relay'], f['compute'], f['paid']):
        a = v.guest_attest.verify(bytes.fromhex(r['attestation']))
        receipt = bytes.fromhex(r['receipt_key'])
        nonce = bytes(32)
        if 'payments' in r:
            receipt += bytes.fromhex(r['payments']['receiptPublicKey'][2:])
            nonce = bytes.fromhex(r['payments']['challenge'])
        assert a['report_data'] == v.report_data(peer_bytes(r['relay_peer']), bytes.fromhex(r.get('secret_key', '')), receipt, nonce)
        assert a['report_data'] != v.report_data(peer_bytes(r['relay_peer']), bytes.fromhex(r.get('secret_key', '')), bytes.fromhex(r['receipt_key']), bytes([1])*32)


def test_challenge_is_exactly_32_bytes():
    with pytest.raises(Reject, match='32 bytes'):
        v.report_data(b'peer', challenge=b'short')
