"""Synthetic end-to-end journey; no provider network calls or real credentials."""
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .evidence import observe_and_sign, verify_local_signature, authorize_deposit_release
from .spike import Store, RedemptionError, decrypt_secret
from .test_spike import MockProvider, KEY_ID, WS_ID


def main():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'state.sqlite')
        provider = MockProvider()
        coupon = store.issue_coupon(5_000_000_000)
        recipient = X25519PrivateKey.generate()
        public = recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        delivery = store.redeem(coupon, public, provider)
        secret = decrypt_secret(delivery['envelope'], recipient, (Store.digest(coupon) + ':' + KEY_ID).encode())
        assert secret == 'synthetic-private-credential'
        provider.rows = [{'source': 'inference', 'id': 'synthetic-row', 'api_key_id': KEY_ID,
                          'workspace_id': WS_ID, 'total_cost_nano_usd': 5_000_000_001}]
        signer = Ed25519PrivateKey.generate()
        evidence = observe_and_sign(store, coupon, provider, signer,
                                    '2026-10-10T00:00:00Z', '2026-10-11T00:00:00Z', 'synthetic-challenge')
        verify_local_signature(evidence, signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        try:
            authorize_deposit_release(evidence)
        except RedemptionError:
            release = 'blocked: local observer has no attestation'
        print(json.dumps({'mode': 'mock-only', 'encrypted_delivery': 'verified',
                          'creation_calls': provider.calls, 'observation_signature': 'verified',
                          'accounting': store.accounting(coupon, 1, 1000),
                          'deposit_release': release}, indent=2))
        store.close()


if __name__ == '__main__':
    main()
