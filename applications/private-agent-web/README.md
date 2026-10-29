# Private agent web

A browser app for encrypted NEAR TEE chat and sealed jobs on attested Mac compute
nodes. Create or connect an Ethereum wallet to receive $0.010000 starter chat
credit. The wallet signs credit and chat actions; chatting needs no ETH purchase.
Sandbox seconds use the separate Base Sepolia escrow controls.

The broker verifies fresh NEAR attestation. Before sending a message, the browser
checks its nonce, model and encryption-key address, then encrypts the conversation
to the model with the NEAR SDK. It decrypts streamed answers in the tab and shows
provider-reported tokens, nanoUSD charges and remaining chat credit. The broker
forwards ciphertext and meters requests with its provider key.

Browser wallets and sandbox buyer keys stay in IndexedDB. Conversation text,
repository input and sandbox credentials stay in tab memory. An injected wallet
can sign chat actions and pay for sandbox seconds.

Build on a development host with Node 24.22.1 or newer:

```sh
npm ci --ignore-scripts
npm run build
python3 dev.py --port 18731
```

Open `http://127.0.0.1:18731/private-agent/`. Development forwards broker requests
to the existing pod. Set `SANDBOX_SOURCE` to the absolute path of
`applications/compute-node/browser/sandbox.mjs` when building against a separate
sandbox checkout. `config.json` supplies public deployment pins and the RPC.

Load an approved sandbox policy in Trust settings, select a repository snapshot
or the sample, enter a task and capped TEE credential, and verify a fresh node.
The browser seals the job to that node and verifies its attestation and receipt
before decrypting the patch and transcript. Download the diff for `git apply`.

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
