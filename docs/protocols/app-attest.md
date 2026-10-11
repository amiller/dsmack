# Lab protocol v1

Purpose: measure **app-identity** acceptance for an honest operation returning 4
and a modified operation returning 5. No endpoint grants interop membership.

All requests use JSON over HTTPS; binary fields are canonical padded Base64.
The server owns one explicit App ID/environment policy and pins it into its SQLite
database. Use separate databases for different policies. A challenge lasts 120
seconds and is bound to purpose and key ID; verification spends it. Counters and
challenge consumption update in one database transaction.

1. Generate an App Attest key on the phone. POST `/challenge` with
   `{"purpose":"attestation","key_id":"<Apple key identifier>"}`.
2. Response: `challenge_id`, `challenge` (32 random bytes, Base64), `key_id`,
   `purpose`, `expires_at`. Pass SHA256(decoded challenge) to `attestKey`.
3. POST `/attest`: `challenge_id`, `key_id`, `attestation` (raw object, Base64).
4. For each operation, POST `/challenge` with purpose `assertion` and the key ID.
5. Construct UTF-8 JSON containing exactly the meaning below. The verifier hashes
   the received bytes, not a reserialization; key ordering is irrelevant.

```json
{
  "protocol": "ios-app-attest-sok/v1",
  "challenge_id": "<from server>",
  "challenge": "<from server>",
  "key_id": "<enrolled key>",
  "operation": "double",
  "input": 2,
  "output": 4
}
```

6. Pass SHA256(those exact bytes) to `generateAssertion`. POST `/assert` with
   `challenge_id`, `key_id`, `assertion`, and `client_data` (those bytes, Base64).
7. A valid signature/RP/freshness result is `accepted: true`, even if output is 5.
   `computation_matches` separately records whether output equals 4. All verdicts
   contain `scope: app_identity_only` and `fixed_code_verified: false`.

The counter is scoped to the App Attest key. The separate synthetic test root is
available only by Python dependency injection, never by request or CLI option.
Test-root verdicts say `evidence_origin: synthetic_test_root`. Captures retain
receipts as unvalidated opaque evidence; fraud-receipt verification is not implemented.

Strict parser limits: definite CBOR containers, unique map keys, bounded depth/size,
COSE P-256/ES256, expected two-certificate Apple chain, and no unflagged trailing
authenticator data. Unsupported layouts fail explicitly and retain the raw request
for diagnosis. Current iOS layouts still need physical-device validation.

The service is for a private lab. It has no user accounts, rate limits, or production
deployment hardening. Do not expose it publicly. Normal TLS validation stays enabled
in the app; use a certificate the phone already trusts or install a lab CA explicitly.
