# Read-only NEAR runner

The runner can now contact NEAR through certificate-verified HTTPS. It never
creates a key, purchases credit, changes an account or sends an inference request.
It does not provide TEE attestation or authorize deposit release.

From the repository root, with its Python dependencies installed:

```sh
python3 -m experiments.coupon_redemption.runner --help
python3 -m experiments.coupon_redemption.runner health
```

`health` contacts the public `/v1/health` endpoint without credentials. This command
was successfully checked against the public service during development. All other
runner checks used injected fake transports; no real management/reporting token
was inspected or used.

## Existing account preflight

Provision the existing account's short-lived **management session JWT** via a
secret environment variable. An ordinary inference API key cannot replace it.
Do not pass credentials in CLI arguments, source files, screenshots or chat.
For a local interactive shell, hidden input avoids recording the value in shell
history:

```sh
read -rs -p 'NEAR management JWT: ' NEAR_SESSION_JWT
export NEAR_SESSION_JWT
python3 -m experiments.coupon_redemption.runner preflight
unset NEAR_SESSION_JWT
```

The result contains organization/workspace IDs only, not the user profile or
provider response. In an eventual dstack deployment, provision secrets to the
approved measured service through its secure environment mechanism; this guide
does not establish who else can recover them.

## Observe one existing key

An organization administrator must already have provisioned a read-only reporting
token. The token can read the organization's reporting data; the key filter does
not narrow the token's underlying privileges. The runner does not create it.

```sh
read -rs -p 'NEAR reporting token: ' NEAR_REPORTING_TOKEN
export NEAR_REPORTING_TOKEN
python3 -m experiments.coupon_redemption.runner usage \
  --organization '<organization-uuid>' \
  --workspace '<workspace-uuid>' \
  --key '<api-key-uuid>' \
  --start '2026-10-10T00:00:00Z' \
  --end '2026-10-11T00:00:00Z'
unset NEAR_REPORTING_TOKEN
```

Dates are explicit timezone-aware observation bounds; replace the example with
the intended window. Output contains the key ID, row count and provider-reported
nano-USD total, labeled `unsigned_provider_observation`; release is always false.
No raw usage rows or credential values are printed. The export includes inference
and platform service rows. This does not select the final contract's eligible
categories, correction/finality policy or release predicate. A later attested
observer must make its own authenticated queries and apply that policy.

## Transport limits and issuance integration

`NearHTTPS()` implements the existing adapter transport interface. It accepts
only GET/POST to the exact origin `https://cloud-api.near.ai` under `/v1/`, with
system-CA certificate and hostname verification. It uses no HTTP proxies, follows
no redirects and performs no retries, including after 429, 5xx or a timeout.
Requests are capped at 64 KiB; response bodies at 4 MiB. Compressed responses,
duplicate JSON keys and nonfinite JSON numbers are rejected.

A subprocess bounds each request, including DNS and slow responses, by a default
30-second deadline; individual socket operations have a 10-second timeout. A
worker that misses the deadline is terminated and reaped. Terminating a POST
cannot undo a server-side action: callers must retain the durable `issuing` state
and quarantine/reconcile ambiguous outcomes, never replay creation blindly.
The subprocess receives secrets through multiprocessing IPC, not command-line
arguments. This is not memory sealing or a guarantee against the local operator.

Only the explicit issuance workflow should connect `Near(..., NearHTTPS())` to
`Store.redeem`. This read-only CLI deliberately offers no creation command. Such
an issuer must retain encrypted recipient delivery and must not print the raw
provider creation response. Existing local observer signatures remain
`local-unattested`; successful HTTPS does not change that label.

Run targeted checks:

```sh
python3 -m unittest experiments.coupon_redemption.test_transport \
  experiments.coupon_redemption.test_runner -v
```
