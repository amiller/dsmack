# Abalone private agent web

The Abalone mark and 256px mascot derivatives come from the project-owned `pages-mascot:assets/` illustrations in Abalone.

The chain directory uses two matching replies from three configured HTTPS RPC
hosts at a pinned block hash. Configure `chainDirectory.rpcs` in `config.json`.

Install the directory and capacity checks on Fractal from the laptop:

```sh
bash applications/private-agent-web/install-fractal-health.sh
```

Directory checks run every five minutes; capacity checks read the public broker
`/network` every minute. Zero ready slots or zero online Macs for three
consecutive minutes sends one Matrix alert, followed by one recovery message.
A missing sample breaks the three-minute streak. State and logs live in
`~/.local/state/dsmack-directory/`. The existing Fractal Hermes credentials stay
on Fractal. Failed notifications remain retryable.
Installation sends a clearly marked failure/recovery test pair to verify Matrix
delivery with the on-host credentials.

Each completed check pings the independent zed watchdog, including observations
that correctly report an outage. Directory heartbeats have a seven-minute
deadline; capacity heartbeats have a three-minute deadline. The watchdog binds
to zed's Nebula interface and uses its existing Alertmanager Telegram receiver
for missing-heartbeat and recovery notifications. Checks arm on their first ping.
Install the watchdog on zed with:

```sh
python3 applications/private-agent-web/install-heartbeat-watch.py
```

To check a separate target:

```sh
deno run --allow-net --allow-read --allow-write --allow-run --allow-env \
  applications/private-agent-web/directory-health.mjs capacity staging NETWORK_URL \
  /absolute/test-state.json /absolute/directory-notify.sh \
  http://192.168.100.3:18766/ping/staging/capacity
```

Abalone is one Pi conversation with `bash`, `read`, `write` and `edit`
running in an attested Mac-hosted Linux guest. Tool calls and results appear
inline. NEAR AI Cloud's model TEE is the default: model requests and responses
remain encrypted between the browser and TEE; the broker forwards ciphertext
and meters usage. In Advanced → Model provider, choose Anthropic or an
OpenAI-compatible HTTPS endpoint, enter a model ID and paste your API key.
The connection check sends a short test request directly from the browser.
Keys stay in Pi's local browser key store. The provider choice is saved on this
browser. Selected providers
receive the conversation directly and bill model tokens to your key; guest
seconds continue to use chat credit. NEAR TEE restores the default credit path.

If a reply loses its connection, its partial text stays in the conversation marked
Interrupted. Retry resends the last user/tool context without adding another
user message. NEAR retries check the broker ledger first, and the page shows
the settled model charge. Retries make a new model request.

Your first message creates a browser wallet and a random data key locally.
The wallet receives $0.25 credit for model tokens and sandbox time. The first
tool call claims a guest, verifies its Apple attestation and
measured compose, and opens a Noise-authenticated libp2p stream to it. The page
shows the guest, its attestation and seconds used. Stop sandbox releases it;
five idle minutes also release it.

The browser and guest use Pi agent-core, pi-ai and pi-coding-agent 1.4.0.
Pi web-ui 0.75.3 supplies AgentInterface, IndexedDB sessions and dialogs. The
upstream Pi prompt builder and tool factories supply the prompt, schemas,
descriptions, truncation and edit behavior. MCP uses the official split SDK
2.4.0 (`@modelcontextprotocol/client`, `server` and `core`) with protocol
2026-07-28, over `/dsmack/agent-mcp/1.0.0`. After authenticated admission, the
stream carries newline-delimited JSON-RPC; cancellation uses MCP notifications.
Bash progress appears inline through MCP progress notifications.

Ask for a single-file browser app to open Pi's Apps panel. HTML apps run in an
opaque iframe served by `../private-agent-artifacts`, with inline styles and
JavaScript and no network access. Apps and console feedback are saved with the
conversation; the Apps button reopens the panel.

Apps receive a frozen `window.dsmack` SDK. Call `await dsmack.ready()` and check
`dsmack.capabilities.has(method)` before using `storage.get/put/list`,
`agent.complete`, `credit.balance` or `diagnostics.log`. Storage values have a
512 KiB UTF-8 quota per app and are encrypted
under a key derived for the conversation and HTML filename, or the ciphertext
CID when viewing a shared app. The viewer grants
each app a model budget once in the host bar, starting at $0.02; the bar shows
its limit, spent amount and pending reservation. Model requests use an isolated
untrusted transcript and the viewer's credit. Amounts use nano-USD strings.

The per-category bridge contracts live in `bridge/Categories/`; the build runs
`node bridge/generate.mjs` to merge them into `bridge/Manifest.json`.

Share app encrypts the original HTML and its functional manifest, pins the
ciphertext, and shows a link to `/a/` with the decryption key in its fragment.
The bundle contains code only. Each viewer chooses their own wallet and uses
their own encrypted storage and model credit. Apps can call `dsmack.guest.run({command,timeoutSeconds:60})` for one fresh empty guest, after an exact-command confirmation in the host card. Each command releases its guest; files belong to that call. The card can finish releasing an interrupted task after reload. Reloading a link preserves that
viewer's state and the budget bound to the ciphertext CID.

Attach your code in the composer accepts a tar or gzipped tar of UTF-8 files,
without `.git`, before the first tool call. The workspace starts empty. Repository
content is marked untrusted in the prompt. The guest workspace persists until
release. The wallet and conversations persist in IndexedDB. At
https://private-agent.dstack.soc1024.com, Use on another device offers passkey
recovery, QR linking and email recovery. Passkeys use WebAuthn PRF and HKDF to
wrap the data key and wallet key. QR linking transfers sealed keys over WebRTC
through the relay with Noise; compare and approve the short code on both devices.
Move from an older origin opens its page and transfers keys through an
origin-bound popup handshake.

Chats sync as AES-GCM encrypted session blobs and an encrypted manifest in the
broker's persistent content-addressed pins. Sessions merge by union, with the
latest counter winning each session. The broker signs the head and commits its
counter and digest to the pinned Base Sepolia SyncHeads contract. Each browser
checks the contract code, on-chain head, signature and ciphertext CID before
loading remote sessions. Refresh loads changes made on another device.

Saved chats offers Export chats for the current conversation or all saved sessions
as JSONL, including messages, tool calls, tool outputs, metadata and feedback.
Use Feedback below a reply to save a note with that conversation.

Email recovery verifies the gate's Intel TDX quote, OS boot measurements, event
log and quoted ECDH key in the browser. It checks the webhost app's live Base
mainnet DstackApp/KMS authorization through two independent public RPCs at one
matching block, caching successful decisions for thirty seconds. The KMS checks
the OS image, registered app, allowed compose and device. Enter your
address and send the prepared recovery email from that account. The page polls
for its headers; the gate verifies the DKIM signature and browser-bound subject
nonce, then enrolls the labelled encrypted recovery wrap or starts a recovery.
The gate persists the request and releases keys sealed to that browser only
after 48 hours. Return to the same browser and choose Check and finish email
recovery. Existing devices query the gate on open, on returning to the tab and
every minute while visible; a prominent notice offers one-click cancellation.
A DK-derived lookup and HMAC authenticate these requests without needing the
email address. Passkey recovery and QR linking remain immediate.

Set EMAIL_RECOVERY_ADDRESS in the project's private deployment environment and
connect an inbound forwarder to POST unchanged raw messages to
`https://private-agent.dstack.soc1024.com/email-recovery/inbound` with Content-Type
`message/rfc822`. The receiver keeps headers for fifteen minutes. The
[email receiver](email-receiver/README.md) also includes a local SMTP path.

The build names JavaScript and CSS assets by their content hash and keeps
`index.html` and `config.json` at stable paths, including in the IPFS release.
The handler revalidates documents/config with ETags and caches hashed assets
as immutable. The main page registers no service worker; isolated apps use a
separate worker on the artifacts origin.

Build on a development host with Node 24 or newer:

```sh
(cd ../compute-node && npm ci --ignore-scripts)
npm ci --ignore-scripts
npm run build
python3 dev.py --port 18731
```

Open `http://127.0.0.1:18731/private-agent/`. `config.json` supplies explicit
broker, RPC and tunnel discovery URLs. `sandbox-policy.json` contains the
approved measured compose and Apple enrollment. The guest's tools run as an
unprivileged user within `/workspace`; the measured firewall and CONNECT proxy
apply the guest's host allowlist to commands.

The saved wallet renders before chat sync, broker checks and RPC calls. A first visit offers the composer and Recover from another device; the first send creates a wallet automatically. After receiving credit or saving a chat, add a passkey or email on the original browser to return on another device.

The build produces `dist/page-bundle.tar`: a deterministic USTAR payload of the
page assets and configuration. Its CIDv1 raw/SHA-256 identifies the payload;
`index.html` adds that CID as a label after archiving to avoid self-reference.
The page compares its label with `PageBundleRegistry.latestCID()` through two
independent Base Sepolia RPCs at a common block, on startup and every minute.
A changed version displays both CIDs without interrupting the chat.

Deploy the registry once from the repository root:

```sh
forge create --root contracts contracts/src/PageBundleRegistry.sol:PageBundleRegistry \
  --rpc-url "$BASE_SEPOLIA_RPC" --account "$DEPLOY_ACCOUNT" --broadcast \
  --constructor-args "$PAGE_PUBLISHER"
```

Set `config.json.pageBundleRegistry` to `{ "registry": "0x…", "rpcs":
["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"] }`.
The browser checks Intel TDX quotes, signer/nonce/SPKI bindings, measured
configuration, RTMR3 events, compose-manager evidence, the E2EE model key, and
NVIDIA's signed NRAS verdict before encrypting the prompt. It applies the NEAR
deployment policy in `../relay-broker/near-policy.mjs`: MRCONFIGID binds
`app_compose`, every pinned image is an approved repository with Rekor
provenance from its expected signer, and MRSEAM, MRTD, RTMR1 and RTMR2 name a
known OS. Verification uses NEAR's public PCCS/NRAS proxies, NVIDIA's JWKS
endpoint and `rekor.sigstore.dev`. Raw NEAR reports travel through
the broker; its verification summary is not an input to the browser's decision.

The page runs in its own container (`isolation: container`). A page deploy
restarts only that container, never the relay broker, so it does not wait for stays to end.

Deploy the built page using its existing private environment JSON and operator-token SHA256:

```sh
python3 deploy.py --target production --evidence /absolute/path/to/local-data/ui/deploy \
  --page-env /absolute/path/to/private/page-env.json \
  --operator-token-sha256 YOUR_EXISTING_OPERATOR_TOKEN_SHA256 \
  --registry-account "$PAGE_PUBLISHER_ACCOUNT"
```

Create or update the separate staging project with the same command and
`--target staging --config /absolute/path/staging-page.json`. Build first with
`PAGE_TARGET=staging PAGE_CONFIG=/absolute/path/staging-page.json npm run build`
so the bundle CID covers the staging configuration. Supply the staged
broker signing identities, escrow and registry in that public config. It uploads `private-agent-staging`, served at
`https://private-agent-staging.dstack.soc1024.com/`, and packages config URLs for
`/relay-broker-staging` and the staging tunnel index. Production requires a clean
source tree and HEAD contained in the locally recorded `origin/main` (or `main`
when no remote main is recorded). Staging accepts topic commits. Both targets
retain the shared-runtime idle guard. The coordinator supplies the staging page
SMTP environment and configures its inbound email routing for that hostname.

To serve staging at `https://pod.dstack.soc1024.com/private-agent-staging/`, build
with `PAGE_STAGING_ORIGIN=https://pod.dstack.soc1024.com` and deploy with
`--staging-origin https://pod.dstack.soc1024.com`. For a staging rehearsal without
on-chain publication, omit `pageBundleRegistry` from the public config and use
`--skip-registry-publication` instead of `--registry-account`.

Run browser boundary checks with an existing browser:

```sh
BASE_URL=http://127.0.0.1:18731/private-agent/ \
CHROMIUM_PATH=/absolute/path/to/chromium \
EVIDENCE=/absolute/path/to/local-data/ui npm run test:browser
```

The deployer validates the archived bytes, uploads the page, then sends
`publish(string)` with its CID using the existing publisher keystore account.
It reads the publication back through both configured RPCs.

Run the recorded NEAR verification and local-chain version-change flow:

```sh
forge build --root ../../contracts
EVIDENCE=/absolute/path/to/local-data/trust node trust-browser.test.mjs
```

This uses Anvil, Chromium and the recorded public NEAR report, Intel collateral,
NVIDIA NRAS token and public signing keys in `test-fixtures/near/`. The test fixes the
clock and challenge to the recording and keeps all inference local.

Run the chat recovery and capacity flows against a local mocked broker (requires
Chromium and `openssl`):

```sh
EVIDENCE=/absolute/path/to/local-data/ux npm run test:ux
```

The test starts its own local HTTPS server and captures phone and desktop views.
Run `EVIDENCE=/absolute/path/to/local-data/recovery node recovery-browser.test.mjs`
for the email recovery notice and cancel flow against a mocked gate.

Run the generated-app boundary checks with Node 24 and an existing browser:

```sh
CHROMIUM_PATH=/absolute/path/to/chromium \
EVIDENCE=/absolute/path/to/local-data/artifacts node artifacts.test.mjs
```

For IPFS, add `dist` with Kubo and serve through a CID subdomain gateway. Assets
use relative paths; the page supplies its CSP. Register each gateway origin in
the broker's `browser_origins`. Wallet and conversation storage belongs to that
origin. Shared `/ipfs/` and `/ipns/` path gateways are rejected to isolate wallets.
A stable DNSLink/IPNS gateway origin preserves browser storage across releases.

## Public IPFS pin on the Mac

Run the publisher independently of the compute pool:

```sh
python3 pin-mac.py --ipfs /absolute/path/to/ipfs \
  --cloudflared /absolute/path/to/cloudflared \
  --car /absolute/path/to/page.car --state /absolute/path/to/retained-ipfs-state
```

The publisher owns Kubo and a quick tunnel exposing only its Bitswap
WebSocket listener. The Kubo API and gateway bind to loopback. NAT port mapping
is disabled. The recursive pin and locally generated `friends-page` IPNS key stay
in the retained state directory; `published.json` records the CID, name and
provider address. Kubo republishes IPNS while running. Compute pools can drain
while this publisher keeps serving pins. `kill -TERM PUBLISHER_PID` stops its
daemon and tunnel, retaining the repository, pins and key for the next launch.
Use the final subdomain gateway origin in the broker allowlist.

The chat header shows available credit and the model provider. While sending, the
message appears immediately with credit, model verification and reply progress.
Choose Add credit beside the balance or an out-of-credit message to open USDC
top-ups and the 14 day account exit. USDC deposits appear in credit once the
broker sees the finalized block,
usually about 15 minutes after the transaction confirms. The page keeps checking
in the background until the credit arrives. Guest
seconds and inference draw from the same broker ledger; an unused guest grant is
free and an admitted S1 stay has a 60 second minimum. To test top-ups, withdrawal
and fleet USDC payouts using a local chain, build the contracts and page, run
`anvil --chain-id 84532 --port 18545 --silent`, then from this directory:

```sh
EVIDENCE=/absolute/path/to/evidence node prepaid.browser.mjs
```

The test serves the built page locally, intercepts service requests, and submits
USDC transactions only to anvil. It writes deposit, withdrawal and fleet screenshots.
