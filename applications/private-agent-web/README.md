# Private agent web

A browser app for encrypted NEAR TEE chat and sealed jobs on attested Mac compute
nodes. Create or connect an Ethereum wallet to receive $0.010000 starter chat
credit and a first sandbox job of up to 180 seconds. Sending a first message or
job also creates a browser wallet automatically. The wallet signs credit and job
actions; starter use needs no ETH purchase. Existing Base Sepolia escrow purchases can
still be checked and refunded.

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

With Playwright and Chromium installed, exercise the deployed first visit with
fresh browser storage, starter credit, a real chat and an automatically verified
sandbox job:

```sh
python3 friend-check.py --url https://pod.dstack.soc1024.com/private-agent/ \
  --out /absolute/path/to/local-data/friend-browser
```

The check uses the visible wallet, chat and sandbox controls. It records
screenshots, the signed job evidence, the applied sample file and a downloaded
patch whose hash matches the attested output statement.
