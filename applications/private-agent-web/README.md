# Private agent web

Dsmack Agent is one Pi conversation with `bash`, `read`, `write` and `edit`
running in an attested Mac-hosted Linux guest. Tool calls and results appear
inline. Model requests and responses remain encrypted between the browser and
NEAR AI Cloud's model TEE; the broker forwards ciphertext and meters usage.

Create or connect a wallet to receive $0.250000 credit for model tokens and guest
seconds. The first tool call claims a guest, verifies its Apple attestation and
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

The included repository contains `greet.txt`. Ask for an edit in chat and choose
Download patch for the workspace diff. Before the first tool call, Choose
repository accepts a tar or gzipped tar of UTF-8 files, without `.git`. Repository
content is marked untrusted in the prompt. The guest workspace persists until
release. Wallets and saved conversations stay in this browser's IndexedDB.

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

Deploy the built page to the shared Deno project:

```sh
python3 deploy.py --evidence /absolute/path/to/local-data/ui/deploy
```

Run browser boundary checks with an existing browser:

```sh
BASE_URL=http://127.0.0.1:18731/private-agent/ \
CHROMIUM_PATH=/absolute/path/to/chromium \
EVIDENCE=/absolute/path/to/local-data/ui npm run test:browser
```

For IPFS, add `dist` with Kubo and serve through a CID subdomain gateway. Assets
use relative paths; the page supplies its CSP. Register each gateway origin in
the broker's `browser_origins`. Wallet and conversation storage belongs to that
origin. Shared `/ipfs/` and `/ipns/` path gateways are rejected to isolate wallets.
A stable DNSLink/IPNS gateway origin preserves browser storage across releases.

```sh
PAGE_URL=http://CID.ipfs.localhost:18091/ \
ALT_PAGE_URL=http://CID.ipfs.alt.localhost:18091/ \
EVIDENCE=/absolute/path/to/local-data/ipfs npm run test:ipfs
```

## Public IPFS pin on the Mac

Add `--ipfs-bin /absolute/path/to/ipfs --ipfs-car /absolute/path/to/page.car
--ipfs-state /absolute/path/to/retained-ipfs-state` to `compute-node/mac-pool.py`.
The launcher owns Kubo and a second quick tunnel exposing only its Bitswap
WebSocket listener. The Kubo API and gateway bind to loopback. NAT port mapping
is disabled. The recursive pin and locally generated `friends-page` IPNS key stay
in the retained state directory; `published.json` records the CID, name and
provider address. Kubo republishes IPNS while running. `kill -TERM LAUNCHER_PID`
drains the guests and stops both the compute and IPFS transports, retaining the
pin and key for the next launch. Never move the IPNS signing key between hosts.

Run the public gateway journey in a fresh browser with
`PUBLIC_GATEWAY=1 node ipfs-check.mjs https://NAME.ipns.GATEWAY/ EVIDENCE`.
Use the final subdomain gateway origin in the broker allowlist. The probe creates
a wallet, reloads it, chats and executes tools and downloads a workspace patch without manual settings.
