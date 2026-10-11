"""Durable, fail-closed issuance with recipient-encrypted delivery.

Upstream key creation has no documented idempotency token: once attempted, an
ambiguous outcome must be reconciled manually, never retried automatically.
"""

import base64
import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from fractions import Fraction

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Keep encrypted delivery comfortably below the peer's 64 KiB response bound.
MAX_PROVIDER_SECRET_BYTES = 8192
MAX_PROVIDER_KEY_ID_BYTES = 200


class RedemptionError(Exception):
    """Safe public error: never includes provider response or credentials."""


class UsageConflict(RedemptionError):
    """Provider correction invalidates further observations until reconciliation."""


@dataclass(repr=False)
class IssuedKey:
    key_id: str
    secret: str


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _derive(shared, aad):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"dsmack-coupon-v1\0" + aad).derive(shared)


def encrypt_secret(secret, recipient, aad):
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient))
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_derive(shared, aad)).encrypt(nonce, secret.encode(), aad)
    return json.dumps({"version": 1, "ephemeral": _b64(ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "nonce": _b64(nonce), "ciphertext": _b64(ciphertext), "aad": _b64(aad)}, sort_keys=True)


def decrypt_secret(envelope, private_key, expected_aad):
    """Recipient helper: caller must independently check coupon/key binding."""
    value = json.loads(envelope)
    if value["version"] != 1 or base64.b64decode(value["aad"]) != expected_aad:
        raise RedemptionError("delivery binding mismatch")
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(
        base64.b64decode(value["ephemeral"])))
    return AESGCM(_derive(shared, expected_aad)).decrypt(
        base64.b64decode(value["nonce"]), base64.b64decode(value["ciphertext"]), expected_aad).decode()


class Store:
    def __init__(self, path):
        # State belongs in a private local-data directory. Operator provisions
        # directory permissions and storage encryption; SQLite is not a TEE seal.
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS coupons (
                digest TEXT PRIMARY KEY, budget INTEGER NOT NULL,
                state TEXT NOT NULL, recipient BLOB,
                key_id TEXT UNIQUE, envelope TEXT,
                accounting_blocked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS usage (
                source TEXT NOT NULL, row_id TEXT NOT NULL, key_id TEXT NOT NULL,
                cost INTEGER NOT NULL, PRIMARY KEY (source, row_id));
            CREATE TABLE IF NOT EXISTS issuance_progress (
                digest TEXT PRIMARY KEY REFERENCES coupons(digest),
                stage TEXT NOT NULL, rpc_method TEXT, error_category TEXT);
        """)
        self.effect_observer = None
        if "accounting_blocked" not in {r[1] for r in self.db.execute("PRAGMA table_info(coupons)")}:
            self.db.execute("ALTER TABLE coupons ADD COLUMN accounting_blocked INTEGER NOT NULL DEFAULT 0")

    def close(self):
        self.db.close()

    def note_issuance(self, digest, stage, rpc_method=None, error_category=None):
        """Trusted host diagnostics only; never stores authority or error text."""
        stages = {'guard_entered', 'guard_submit_started', 'guard_submitted',
                  'guard_read', 'guard_confirmed', 'provider_post_started',
                  'provider_return_validated', 'delivery_committed'}
        methods = {'eth_chainId', 'eth_getTransactionReceipt', 'eth_getTransactionByHash',
                   'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getStorageAt',
                   'eth_getTransactionCount', 'eth_sendRawTransaction'}
        errors = {'http_retryable', 'network_unavailable', 'http_terminal',
                  'invalid_response', 'redirect_refused', 'validation_failed',
                  'receipt_indexing', 'rpc_error', 'receipt_invalid', 'receipt_hash_mismatch',
                  'receipt_authority_mismatch', 'receipt_reverted', 'receipt_status_invalid',
                  'receipt_block_invalid', 'receipt_quantity_invalid', 'receipt_hash_invalid',
                  'receipt_preconfirmed', 'timeout', 'provider_error', 'internal_error'}
        if (stage not in stages or rpc_method is not None and rpc_method not in methods
                or error_category is not None and error_category not in errors
                or self.db.execute('SELECT 1 FROM coupons WHERE digest=?', (digest,)).fetchone() is None):
            raise RedemptionError('invalid private issuance diagnostic')
        self.db.execute('INSERT INTO issuance_progress VALUES (?,?,?,?) '
                        'ON CONFLICT(digest) DO UPDATE SET stage=excluded.stage, '
                        'rpc_method=excluded.rpc_method,error_category=excluded.error_category',
                        (digest, stage, rpc_method, error_category))

    @staticmethod
    def digest(coupon):
        return hashlib.sha256(coupon.encode()).hexdigest()

    def issue_coupon(self, budget_nano_usd):
        if type(budget_nano_usd) is not int or not 0 < budget_nano_usd <= 2**63 - 1:
            raise ValueError("positive int64 budget required")
        token = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO coupons(digest,budget,state) VALUES (?,?,'ready')",
                        (self.digest(token), budget_nano_usd))
        return token

    def redeem(self, coupon, recipient, provider, *, accepted_offer_hash=None,
               claim_guard=None, recipient_peer=None, delivery_version=3, before_create=None):
        # Validate low-order/all-zero points before consuming the coupon or
        # issuing a provider key. exchange rejects invalid shared secrets.
        try:
            X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(recipient))
        except (TypeError, ValueError):
            raise RedemptionError("invalid recipient key") from None
        if delivery_version not in (3, 4):
            raise RedemptionError("invalid delivery contract")
        digest = self.digest(coupon)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM coupons WHERE digest=?", (digest,)).fetchone()
            if row is None:
                raise RedemptionError("unknown coupon")
            if row["recipient"] is not None and row["recipient"] != recipient:
                raise RedemptionError("coupon bound to another recipient")
            if claim_guard is not None:
                # Trusted service hook only. It validates and records peer/grant
                # authority inside this same intent transaction, before effects.
                claim_guard(row)
            if row["state"] == "delivered":
                self.db.execute("COMMIT")
                return {"key_id": row["key_id"], "envelope": row["envelope"]}
            if row["state"] != "ready":
                raise RedemptionError("issuance pending or ambiguous; reconcile, do not retry")
            self.db.execute("UPDATE coupons SET state='issuing', recipient=? WHERE digest=?",
                            (recipient, digest))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        # No transaction spans the network call. 'issuing' is durable first.
        # Process death at any following point leaves a non-retryable record.
        try:
            if before_create is not None:
                before_create()
            if self.effect_observer is not None:
                self.effect_observer('provider_post_started')
            issued = provider.create_key("coupon-" + digest, row["budget"])
            if (not isinstance(issued, IssuedKey) or not isinstance(issued.key_id, str)
                    or not issued.key_id or len(issued.key_id.encode()) > MAX_PROVIDER_KEY_ID_BYTES
                    or not isinstance(issued.secret, str) or not issued.secret
                    or len(issued.secret.encode()) > MAX_PROVIDER_SECRET_BYTES):
                raise RedemptionError("invalid issuance result")
            if self.effect_observer is not None:
                self.effect_observer('provider_return_validated')
            if recipient_peer is not None:
                if delivery_version == 4:
                    from .offer_v4 import delivery_aad_v4 as make_aad
                else:
                    from .offer_v3 import delivery_aad_v3 as make_aad
                aad = make_aad(digest, issued.key_id, recipient, accepted_offer_hash, recipient_peer)
            elif accepted_offer_hash is None:
                aad = (digest + ":" + issued.key_id).encode()
            else:
                from .offer_v2 import delivery_aad
                aad = delivery_aad(digest, issued.key_id, recipient, accepted_offer_hash)
            envelope = encrypt_secret(issued.secret, recipient, aad)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute("UPDATE coupons SET state='delivered',key_id=?,envelope=? WHERE digest=?",
                                (issued.key_id, envelope, digest))
                if self.effect_observer is not None:
                    self.effect_observer('delivery_committed')
                self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            return {"key_id": issued.key_id, "envelope": envelope}
        except Exception:
            self.db.execute("UPDATE coupons SET state='quarantined' WHERE digest=?", (digest,))
            raise RedemptionError("issuance ambiguous; reconciliation required") from None

    def pending(self):
        """Safe reconciliation inventory. Never resets or reissues a coupon."""
        return [dict(r) for r in self.db.execute(
            "SELECT digest,state FROM coupons WHERE state IN ('issuing','quarantined')")]

    def ingest(self, coupon, rows):
        """Trusted observer only: rows are provider assertions, not signed proof.

        Caller must fetch authenticated NEAR reporting rows scoped to this key.
        Plain recipient-supplied rows must NEVER enter this trust boundary.
        """
        self.db.execute("BEGIN IMMEDIATE")
        try:
            claim = self.db.execute("SELECT * FROM coupons WHERE digest=?", (self.digest(coupon),)).fetchone()
            if claim is None or claim["state"] != "delivered":
                raise RedemptionError("no delivered key")
            if claim["accounting_blocked"]:
                raise RedemptionError("accounting requires reconciliation")
            self.db.execute("SAVEPOINT usage_batch")
            for row in rows:
                source, row_id = row["source"], row["id"]
                cost, key_id = row.get("total_cost_nano_usd"), row.get("api_key_id")
                if source not in ("inference", "service") or not isinstance(row_id, str) or not row_id:
                    raise RedemptionError("invalid usage attribution")
                old = self.db.execute("SELECT key_id,cost FROM usage WHERE source=? AND row_id=?",
                                      (source, row_id)).fetchone()
                # Recognize corrections before rejecting unsupported negative
                # or malformed costs; stale positive observations must not live
                # on merely because their replacement cannot be ingested.
                if old is not None and (old["key_id"] != key_id or type(cost) is not int or old["cost"] != cost):
                    raise UsageConflict("usage changed; reconcile before rewards")
                if key_id != claim["key_id"] or type(cost) is not int or not 0 <= cost <= 2**63 - 1:
                    raise RedemptionError("invalid usage attribution")
                if old is not None:
                    continue
                else:
                    self.db.execute("INSERT INTO usage VALUES (?,?,?,?)", (source, row_id, key_id, cost))
            self.db.execute("COMMIT")
        except BaseException as error:
            if isinstance(error, UsageConflict):
                self.db.execute("ROLLBACK TO usage_batch")
                self.db.execute("UPDATE coupons SET accounting_blocked=1 WHERE digest=?",
                                (self.digest(coupon),))
                self.db.execute("COMMIT")
            else:
                self.db.execute("ROLLBACK")
            raise

    def accounting(self, coupon, reward_numerator, reward_denominator):
        """Non-settlement preview. Unsigned reports cannot release a deposit."""
        if (type(reward_numerator) is not int or type(reward_denominator) is not int
                or reward_numerator < 0 or reward_denominator <= 0):
            raise ValueError("nonnegative rational reward rate required")
        row = self.db.execute("SELECT * FROM coupons WHERE digest=?", (self.digest(coupon),)).fetchone()
        if row is None or row["state"] != "delivered":
            raise RedemptionError("no delivered key")
        if row["accounting_blocked"]:
            raise RedemptionError("accounting requires reconciliation")
        # Python integer sum avoids SQLite overflow over many valid rows.
        billed = sum(r[0] for r in self.db.execute("SELECT cost FROM usage WHERE key_id=?", (row["key_id"],)))
        eligible = min(billed, row["budget"])
        return {"provider_reported_nano_usd": billed, "reward_eligible_nano_usd": eligible,
                "hypothetical_reward_units": int(eligible * Fraction(reward_numerator, reward_denominator)),
                "overshoot_nano_usd": max(0, billed - row["budget"]),
                "deposit_release_authorized": False,
                "evidence_status": "unsigned_provider_observation"}

    def authorize_deposit_release(self, coupon):
        """Accounting alone is insufficient: use an attested observer verifier."""
        raise RedemptionError("attested observer evidence required; deposit remains locked")
