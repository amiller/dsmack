# Dsmack public status view

This static dashboard separates coupon claim readiness, issuer reachability and
network participation. It does not discover peers, verify attestation, accept
coupons or infer a membership census. Missing feeds show **unknown**, not zero
nodes. A reachable issuer does not establish provider admission, successful
redemption or private custody.

## Serve reviewed public copies

Serve `index.html`, `status.mjs`, `participation.mjs`, `directory.mjs`, `capacity.mjs` and three separately validated JSON copies together
over HTTPS. Never mount an operator state directory in the web server. Do not
publish adapter logs, raw probe output, owner plans or credentials. The browser
fetches anonymously without cookies, redirects or caching, limits each response
to 4096 bytes for coupon feeds and 65536 bytes for participation, and polls every 30 seconds. There are no third-party scripts,
fonts or analytics; the epoch link is followed only when clicked. The opt-in node
directory additionally makes a read-only request to the pinned Dsmack relay on
`pod.dstack.soc1024.com`, without credentials, redirects or caching. A dashboard
hosted elsewhere requires the relay to permit this public GET through CORS.

## Joining capacity

The capacity panel reads the pinned relay's `/nft/status` with a five-second
timeout and 32 KiB limit. It requires a fresh Base Sepolia observation, an
unpaused public-pilot budget and a remaining additional enrollment slot. Missing,
malformed or stale observations show unknown; qualification-only, consumed,
paused and expired allowances do not advertise public capacity. The browser
expires the window locally even if polling stops.

An advertised slot is an upper bound, not a reservation for an invited friend,
proof of eligibility or seed readiness. Current fees and admission may still
refuse a request. The panel publishes no participant identities or budget ledger.
Serve the reviewed relay status schema alongside this panel; the older relay
without budget metadata deliberately shows unknown.

## Find your node

The directory panel requests `/apple-attest-p2p-relay/nft/directory` every 30
seconds, with a five-second timeout and 128 KiB response limit. It pins the Base
Sepolia registry, accepts at most 64 public opt-ins and rejects unknown fields.
Unavailable, disabled and empty observations have distinct labels. Failed reads
show unknown rather than retaining a healthy appearance.

Search a public node, membership or account ID to recognize your entry. The search
is local to the browser and is neither sent to the relay nor saved in browser
storage. Versions are signed self-reports; admitted build hashes and account
bindings are attributed to the relay's verification, not reverified in JavaScript.
Freshness expires in the browser even when polling stops. A recent key exchange
requires a current-epoch verified receipt with its actual block time within 120
seconds; rechecking or copying an old receipt cannot renew that clock. Historical
receipts and stale check-ins stay labeled as such. Neither means continuous
online availability or current private-key possession.

The new panel requires the separately deployed and qualified directory endpoint.
Source tests with synthetic records do not establish public service availability
or independent-device acceptance. A public Mac node lists itself by default
([opt-out](../../../docs/native-directory-v1.md#listing-by-default)); registration
alone does not publish a participant in this directory.

- `health.json` contains exactly `state`, `observed_at_unix`,
  `claiming_available` from the [controller](../public-testnet-operations.md).
  Unknown stays unknown; valid unavailable states show unavailable. A report
  older than 90 seconds shows **stale**, with claim readiness unknown.
- `issuer.json` is the small `dsmack-issuer-observation-v1` projection from the
  [issuer exporter](../../../tools/coupon_testnet_status.py). It expires locally
  after 300 seconds. It displays one configured issuer, advertised source
  revision and custody profile, epoch bundle URL/hash and actual UTC deadlines.
  These are operator reports, not browser-verified signatures. Stale advertised
  details remain visible as historical observations; they do not prove liveness.

Create the issuer copy with validated public manifest and effect-free probe:

```sh
python3 tools/coupon_testnet_status.py \
  --manifest /reviewed-public/deployment.json \
  --probe /private-probe/normal-client-report.json \
  --observed-at 2030-01-01T00:00:00Z --dashboard > /staging-public/issuer.json
```

Record the real probe completion time; do not refresh the timestamp by copying
an old probe. Stage outside the web root, require a successful exporter exit,
then atomically replace the public copy. A failed export must never replace it
with raw input or a fabricated healthy report. A retained copy expires in the
browser even if publishing stops. The timestamp above is a documentation
example, not a deployment observation.

The coupon schemas refuse unknown fields; invalid, future-skewed (over 30 seconds) or
failed feeds show unknown independently. Approval expiry overrides a fresh
reachable report. An advertised claiming window is separate from readiness.
Neither feed contains a participant count, service opt-ins or synchronization
lag. Those remain unknown until an actual qualified discovery/observation feed
exists; a single reachable coupon issuer is not a participation network.

## Native participation observations

`participation.json` comes from the separate read-only
[`tools/participation_status.py`](../../../tools/participation_status.py) observer.
It reports Base Sepolia registry state only for an operator-supplied, reviewed
public opt-in roster. The default roster is empty; no historical event IDs or
legacy fixture identities are automatically published. It is not a complete registration census,
peer discovery service or independent-device test. Serve the tool's validated
output directly; do not synthesize rows from relay sponsor-transaction counts.

The panel displays the RPC block/time and roster scope, observed registration
and revocation state, last on-chain check-in, relay pause flag and shared-key
commitment epoch. Every row's online status remains **unknown**. A key commitment
does not prove synchronization, possession or delivery. Operator and device
counts remain unknown, including when multiple member IDs appear. Missing,
failed, malformed or future-skewed reports show unknown; reports expire locally
after 90 seconds. Stale rows are explicitly historical and retain their original
observation timestamp. Maximum 64 distinct records and 64 KiB per feed.

This participation network is separate from the Mac coupon issuer. Its Base
Sepolia observations do not qualify Base-mainnet coupon spending or redemption.
The join link goes to the public repository's canonical guide, so it works when
these static assets are served alone under a separate status URL.

## Selected Mac issuer feed

Use [`tools/mac_coupon_status.py`](../../../tools/mac_coupon_status.py) for the
selected Mac profile, separate from the legacy TDX exporter above:

```sh
python3 tools/mac_coupon_status.py \
  --manifest /reviewed-public/mac-deployment.json \
  --probe /private-probe/coupon-free-mac-admission.json > /staging-public/issuer.json
```

The manifest has exactly `schema=dsmack-mac-issuer-deployment-v1`, `network`,
`peer` (public WSS multiaddress), `source_revision` (40-hex advertised revision),
`trust_profile=operator-readable-debug`, `bundle_url`, `bundle_sha256`,
`approval_expires_at`, `claiming_available_until` (UTC Z timestamps),
`identity_policy_sha256`, `issuance_policy_sha256`, `approval_sha256`,
`apple_app_id=DC9JH5DRMY.dev.dsmack.provider`, `cdhash`, `compose_sha256` and
`runtime_app`. All hashes other than the source revision are 64 lowercase hex.
`runtime_app` is the exact approved runtime string, or explicitly null when the
selected policy does not require that additional runtime-app binding.

The normalizer accepts the existing coupon-free Mac normal-client report:
`profile=mac-appattest-coupon-v1`,
`evidenceStatus=verified-apple-appattest-issuer-identity`,
`custody=operator-kms-readable`, exact peer/Apple app/code/compose/policy/approval
bindings and the probe's own observation timestamp. `runtimeAppAttested` and
optional `runtimeApp` must match the manifest. Synthetic evidence, substituted
pins, added fields, or any coupon/provider effect flag refuse output. There is
no claim-readiness inference. Only the client verifies attestation; this tool
checks a report against operator-supplied pins, not cryptographic evidence.
A stale report remains stale even if copied again. Source revision and bundle
location are advertised deployment metadata, not attestation-derived facts.

The [Mac inventory reader](../../../tools/mac_preview_status.py) and
[operations runbook](../mac-preview-ops-runbook.md) are a separate inventory-only
path. Inventory freshness is not issuer reachability. Its sanitized output is
not accepted as either dashboard feed; do not transform its process observations
into a healthy claim verdict.

This dashboard is an implementation candidate. Its synthetic browser journey
does not qualify a current Mac epoch, public status deployment or independent
Mac acceptance. Keep unsupported or unobserved feeds absent and visibly unknown.

## Checks

```sh
node --test packaging/coupon/status/test-*.mjs
python3 -m unittest tools/test_coupon_testnet_status.py tools/test_mac_coupon_status.py tools/test_mac_preview_status.py
```

The browser journey must exercise the actual static candidate and label any
synthetic public feeds. UI tests do not qualify real peers, redemption or the
public hosting path. See [Join the network](../../../README.md#join-the-network)
for the distinct participation release path.
