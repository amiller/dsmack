"""Local signed-observer evidence experiment, deliberately NOT attested.

The observer fetches accounting itself; recipient-uploaded rows cannot be signed
through this entry point. Production needs an attested issuer/observer identity,
approved measurements, freshness and rollback protection, and a contract replay
ledger. Merely whitelisting this Python process's key is not attestation.
"""

import base64
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .spike import RedemptionError


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def observe_and_sign(store, coupon, provider, signing_key, start_time, end_time, challenge,
                     *, accepted_offer=None, recipient_peer=None, environment='local-unattested'):
    """Mock evidence only. Time window/challenge belong to verifier's policy."""
    claim = store.db.execute("SELECT * FROM coupons WHERE digest=?", (store.digest(coupon),)).fetchone()
    if claim is None or claim["state"] != "delivered":
        raise RedemptionError("no delivered key")
    # Never accepts a caller-supplied usage bundle. This provider boundary must
    # be authenticated TLS in the eventual approved TEE deployment.
    rows = provider.usage_rows(claim["key_id"], start_time, end_time)
    store.ingest(coupon, rows)
    observed = store.accounting(coupon, 0, 1)
    if environment not in ('local-unattested', 'debug-staging-operator-readable'):
        raise RedemptionError('unsupported observation environment')
    payload = {"domain": "dsmack-coupon-observation-v1", "environment": environment,
               "evidence_id": secrets.token_hex(32), "challenge": challenge,
               "coupon_digest": claim["digest"], "key_id": claim["key_id"],
               "provider": "near", "threshold_nano_usd": claim["budget"],
               "provider_reported_nano_usd": observed["provider_reported_nano_usd"],
               "start_time": start_time, "end_time": end_time,
               "delivery_sha256": hashlib.sha256(claim["envelope"].encode()).hexdigest(),
               "recipient_sha256": hashlib.sha256(claim["recipient"]).hexdigest()}
    if accepted_offer is not None:
        from .offer_v2 import offer_hash
        if len(str(observed['provider_reported_nano_usd'])) > 39:
            raise RedemptionError('v2 cumulative observation exceeds decimal domain')
        version = accepted_offer.get('version')
        if version == 4:
            from .offer_v4 import offer_hash_v4, peer_hash
            committed_hash = offer_hash_v4(accepted_offer)
            payload['recipient_peer_sha256'] = peer_hash(recipient_peer)
        elif version == 3:
            from .offer_v3 import offer_hash_v3, peer_hash
            committed_hash = offer_hash_v3(accepted_offer)
            payload['recipient_peer_sha256'] = peer_hash(recipient_peer)
        else:
            committed_hash = offer_hash(accepted_offer)
        payload.update({'domain': f'dsmack-coupon-observation-v{version}', 'version': version,
                        'offer_hash': committed_hash, 'provider': accepted_offer['provider']['id'],
                        'threshold_nano_usd': str(claim['budget']),
                        'provider_reported_nano_usd': str(observed['provider_reported_nano_usd'])})
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"payload": payload, "public_key": base64.b64encode(public).decode(),
            "signature": base64.b64encode(signing_key.sign(canonical(payload))).decode()}


def verify_local_signature(bundle, expected_public_key):
    """Integrity check only. Success does not authorize deposit release."""
    try:
        public = base64.b64decode(bundle["public_key"], validate=True)
        if public != expected_public_key or bundle["payload"]["domain"] != "dsmack-coupon-observation-v1":
            raise RedemptionError("observer identity mismatch")
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(bundle["signature"], validate=True), canonical(bundle["payload"]))
    except (KeyError, ValueError, InvalidSignature):
        raise RedemptionError("invalid observation signature") from None
    return bundle["payload"]


def authorize_deposit_release(bundle):
    """Fail closed until attestation + contract verification are implemented."""
    raise RedemptionError("local observation is not attested; deposit remains locked")
