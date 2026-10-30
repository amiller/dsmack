# Private agent web

A browser app using Pi’s AgentInterface, session storage and dialogs for encrypted NEAR TEE chat and sealed jobs on attested Mac compute
nodes. Create or connect an Ethereum wallet to receive $0.250000 starter chat
credit and a first sandbox job of up to 180 seconds. Sending a first message or
job also creates a browser wallet automatically. The wallet signs credit and job
actions; starter use needs no ETH purchase. Existing Base Sepolia escrow purchases can
still be checked and refunded.

The broker verifies fresh NEAR attestation. Before sending a message, the browser
checks its nonce, model and encryption-key address, then encrypts the conversation
to the model with the NEAR SDK. It decrypts streamed answers in the tab and shows
provider-reported tokens, nanoUSD charges and remaining chat credit. The broker
forwards ciphertext and meters requests with its provider key.

Browser wallets and sandbox buyer keys stay in IndexedDB. Chat sessions and their attestation evidence are saved in this browser using Pi’s
IndexedDB session store. Use Saved chats to reopen a conversation and New chat to
start another. Keep chats on this device requests persistent browser storage.
Repository input and sandbox credentials stay in tab memory. An injected wallet
can sign chat actions and pay for sandbox seconds.

Build on a development host with Node 24 or newer:

```sh
npm ci --ignore-scripts
npm run build
python3 dev.py --port 18731
```

Open `http://127.0.0.1:18731/private-agent/`. Development forwards broker requests
to the existing pod. Set `SANDBOX_SOURCE` to the absolute path of
`applications/compute-node/browser/sandbox.mjs` when building against a separate
sandbox checkout. `config.json` supplies public deployment pins and the RPC.

The approved policy and Apple enrollment ship in the page source as
`sandbox-policy.json`, imported into `cfg.sandboxPolicy`. Run the included task
to use the sample repository. The page discovers a compatible node and verifies
it automatically, obtains a wallet-bound starter grant and job-scoped model
capability, then seals the job to the guest. It verifies the job attestation,
receipt and output hashes before applying the patch to the included repository
in browser memory and displaying the updated files. Provider keys remain in
the broker CVM. Advanced controls support a custom repository snapshot, policy
override, existing credit and patch download. The wallet panel has its address,
a copy button and a Base Sepolia faucet link for additional paid use.

Deploy the built page to the `private-agent` shared Deno project:

```sh
python3 deploy.py --evidence /absolute/path/to/local-data/ui/deploy
```

Run browser boundary checks with an existing Playwright installation and browser:

```sh
BASE_URL=http://127.0.0.1:18731/private-agent/ \
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
CHROMIUM_PATH=/absolute/path/to/chromium \
EVIDENCE=/absolute/path/to/local-data/ui npm run test:browser
```

## Local IPFS serving

`config.json` contains explicit HTTPS broker, RPC and tunnel-index URLs and the
Base Sepolia registry address. Assets stay relative to the CID root. CSP and
referrer controls ship in the HTML as well as the Deno response.

Build on the Linux builder, then use an isolated Kubo repository with
`--offline`, empty `Bootstrap` and `Addresses.Swarm`, and a loopback gateway.
Add the static directory with `ipfs --offline add --cid-version=1 -Qr dist` and
export its CAR with `ipfs --offline dag export CID`. Set
`Gateway.PublicGateways` for `localhost` and `alt.localhost` with paths
`["/ipfs","/ipns"]` and `UseSubdomains:true`; run `ipfs --offline daemon`.
Add each printed CID origin to the broker's exact `browser_origins` allowlist.

```sh
PAGE_URL=http://CID.ipfs.localhost:18091/ \
ALT_PAGE_URL=http://CID.ipfs.alt.localhost:18091/ \
EVIDENCE=/data/private-agent-ipfs npm run test:ipfs
```

The probe creates a wallet, chats, applies a verified sandbox patch and checks
same-origin persistence and isolation on the second gateway origin. Stop the
owned Kubo process afterwards. Offline imports and local recursive pins retain
blocks locally; public announcement and remote pinning are separate operations.

Wallet, buyer identity and purchase storage belong to the browser origin. A new
CID or gateway origin has separate storage; connecting an external wallet also
needs permission for that origin. Shared `/ipfs/` and `/ipns/` path gateways are
refused before wallet storage opens. For updates with one stable wallet origin,
keep the same DNSLink/IPNS name and gateway. Wallet recovery/export is separate
from static hosting.

For a public release, recursively pin on an existing publicly reachable non-zed
Kubo host with persistent storage, plus an independent peer. This needs no new
pinning account; gateway caching alone does not retain a release. Add the final
public gateway origin to the broker’s `browser_origins` before sharing it.
DNSLink on an already-owned domain is the
simplest stable friends link: update one TXT record, with no per-release protocol
fee, and configure a compatible HTTPS gateway. IPNS has no protocol fee either,
but needs regular republication (Kubo defaults to four hours; DHT records expire
after 48 hours). Keep the final gateway hostname stable for wallet storage.
See [persistence](https://docs.ipfs.tech/concepts/persistence/),
[DNSLink](https://docs.ipfs.tech/concepts/dnslink/) and
[IPNS](https://docs.ipfs.tech/concepts/ipns/).
