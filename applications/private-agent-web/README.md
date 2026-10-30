# Private agent web

Dsmack Agent is one Pi conversation with `bash`, `read`, `write` and `edit`
running in an attested Mac-hosted Linux guest. Tool calls and results appear
inline. Model requests and responses remain encrypted between the browser and
NEAR AI Cloud's model TEE; the broker forwards ciphertext and meters usage.

Choose Start fresh to generate a browser wallet and a random data key locally.
The wallet receives $0.250000 credit for model tokens and guest seconds. The first
tool call claims a guest, verifies its Apple attestation and
measured compose, and opens a Noise-authenticated libp2p stream to it. The page
shows the guest, its attestation and seconds used. End session releases it;
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
their own encrypted storage and model credit. Reloading a link preserves that
viewer's state and the budget bound to the ciphertext CID.

The included repository contains `greet.txt`. Ask for an edit in chat and choose
Download patch for the workspace diff. Before the first tool call, Choose
repository accepts a tar or gzipped tar of UTF-8 files, without `.git`. Repository
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

Email recovery verifies the gate's Intel TDX quote and approved boot measurements
in the browser before sending keys sealed to its quoted ECDH key. Enter your
address and send the prepared recovery email from that account. The page polls
for its headers; the gate verifies the DKIM signature and browser-bound subject
nonce, then stores or releases the labelled encrypted recovery wrap. Passkeys
remain the primary recovery path.

Set EMAIL_RECOVERY_ADDRESS in the project's private deployment environment and
connect an inbound forwarder to POST unchanged raw messages to
`https://private-agent.dstack.soc1024.com/email-recovery/inbound` with Content-Type
`message/rfc822`. The receiver keeps headers for fifteen minutes. The
[email receiver](email-receiver/README.md) also includes a local SMTP path.
The email-code path remains available under Email code. Configure SMTP_HOST,
SMTP_PORT, SMTP_TLS, SMTP_USER, SMTP_PASSWORD and SMTP_FROM for code delivery;
SMTP_TLS defaults to implicit TLS on port 465.

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

The saved wallet renders before chat sync, broker checks and RPC calls. A first visit offers Start fresh or recovery; creating a wallet is explicit. After receiving credit or saving a chat, add a passkey or email on the original browser to return on another device.

Deploy the built page using its existing private environment JSON and operator-token SHA256:

```sh
python3 deploy.py --evidence /absolute/path/to/local-data/ui/deploy \
  --smtp-env /absolute/path/to/private/page-env.json \
  --operator-token-sha256 YOUR_EXISTING_OPERATOR_TOKEN_SHA256
```

Run browser boundary checks with an existing browser:

```sh
BASE_URL=http://127.0.0.1:18731/private-agent/ \
CHROMIUM_PATH=/absolute/path/to/chromium \
EVIDENCE=/absolute/path/to/local-data/ui npm run test:browser
```

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
