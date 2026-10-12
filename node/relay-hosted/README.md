# Durable testnet relay

This untrusted relay sponsors on-chain transactions and carries encrypted parcels.
It never receives the shared signing key. `network.json` pins the test deployment;
`abi.json` and `badge-abi.json` are generated from the checked-in contracts.
Include both ABI files in deployment packages. Dependencies are locked.

The existing root routes keep `network.json` and the original shared-key release.
Optional `network-nft.json` adds `/nft/*` routes for the NFT network. Both must use
the same chain and sponsor, and share a single transaction queue and durable
journal. NFT mailboxes have their own namespace. Include `network-nft.json` when
deploying this dual-network configuration; never replace the legacy deployment
file with the NFT deployment. The Mac app pins the `/nft` endpoint in its executable.

Optional `network-ios.json` enables `/ios/*`. It must contain `iosCategory`,
`iosAdapter`, and `iosCDRegistry`, each distinct from the Mac admission policy,
and share the NFT route's `chainId`, `admin`, and `DemoV1`. iPhone and Mac NFT
routes deliberately share the `nft:` mailbox namespace so iPhones can contact
the existing Mac seed. They share the sponsor transaction queue and journal too.
Enrollment/execution remain restricted to each route's configured category.
An absent iOS file returns 404; inconsistent configured networks fail startup.
The shipped iOS configuration references its deployed **disabled** category.
Installed TestFlight code admission remains pending; route availability is not
proof an iPhone can join.

Compatibility check:
`deno test --config node/relay-hosted/deno.json --frozen --node-modules-dir=none --allow-read --allow-write --allow-net node/relay-hosted/server_test.ts`

The deployed instance uses the existing pod's isolated Deno container runtime,
with persistent `ctx.dataDir` and `ctx.env.PRIVATE_KEY` / `RPC_URL`. The sponsor is
a dedicated Base Sepolia account. Its key is not in source, tarballs or build logs.
No other application or signing account needs that credential.

The relay journals each exact signed transaction before sending it; restarts and
identical retries recover the same transaction hash. Transactions serialize to
avoid sponsor nonce conflicts. Mailboxes have expiry, size and count limits.
The shared key and App Attest identity remain on peers. RPC and relay availability
remain trust/availability assumptions; this is not a light client.

Development command (provide a matching disposable test account and network):

```sh
deno task check
RELAY_DATA=/private/path/to/state deno task start
```

The public service accepts only Join, Bootstrap and Receipt for its configured
category. The legacy sponsor-owned token claim remains disabled. When both
`ResearchBadges` and `PersonalBadgeAccountFactory` are configured, three additional
routes sponsor participant-owned badges: `/personal-account` requires a fresh
admitted receipt bound to the new account key, `/badge-claim` requires the
recipient's signature and matching network receipt, and `/account-handoff`
accepts only factory-created accounts with a participant NFT and both control-key
signatures. `/register-build` sponsors only the configured registry's normalized
code-admission check, enabling a friend to register their own signed copy without
a gas key. Registration is not proof of valid Apple signing. Contract
validation runs during gas estimation and again on chain. Unknown targets and
administrator calls are not exposed. The legacy root configuration has no NFT addresses; these routes are enabled
on the separately configured `/nft` release.
A network file may add measured admission (open-admission design §2, §4) with
all three of `measuredCategory`, `measuredAdapter` (an `AppleAttestMeasuredV1`)
and `measurementRegistry` (a `MeasurementRegistry`); the category and adapter must
differ from `macCategory`/`macAdapter`, which keep working beside it. `/enroll` for
the measured category requires the node's `{cd, page0, ent, L, S}` (base64 blobs,
integer offsets). The relay computes M with the registry's `measure`, refuses
`build not admitted` unless `isAdmitted(M, latest block)`, sponsors
`register(cd, page0, ent, L, S)` unless `measurementOf(sha256(cd))` is already M,
then sends `enroll` to `measuredAdapter`. Without these keys `/enroll` is unchanged
and `/register-build` remains the legacy `registerBuild` path. Bounded sponsor
plans pin the admission baseline with an optional `measured: {registry,
measurement}` (an open window for that M) in place of the legacy `buildId`.
Enrollment tests: `deno test --config node/relay-hosted/deno.json --frozen --node-modules-dir=none --allow-read --allow-write --allow-net --allow-env node/relay-hosted/enroll_test.ts`.
Mailboxes are untrusted and unauthenticated transport: malicious traffic can
still delay or discard delivery. Peers verify chain/session/key bindings.

The transaction journal has a hard 10,000-entry cap; plan maintenance before
reaching it. Do not delete pending entries. RPC failures return retryable errors.


For administrator nonce coordination, `SPONSOR_WRITES_PAUSED=true` blocks every
new sponsor transaction inside the shared queue. `/status` reports this flag;
mailboxes and read-only routes remain available. Drain/reconcile pending entries
before external administrator transactions, then redeploy with the flag false.
This is separate from the on-chain network pause and does not alter admission.


The opt-in native directory candidate adds `directory.ts` to the deployment
package. Its public `GET /nft/directory` permits cross-origin reads without
credentials; check-in and leave POSTs have no CORS grant. It defaults disabled
unless `NATIVE_DIRECTORY_ENABLED=true`. Enabling/redeploying is a separate
operator action, not implied by checking in this source. See
[the signed protocol and evidence limits](../../docs/native-directory-v1.md).
The source tests use synthetic adapter/RPC fixtures and do not qualify Apple
attestation or independent friend acceptance.

```sh
deno test --config node/relay-hosted/deno.json --frozen --node-modules-dir=none --allow-read --allow-write --allow-net --allow-env=CBOR_NATIVE_ACCELERATION_DISABLED node/relay-hosted/directory_test.ts node/relay-hosted/server_test.ts
```
