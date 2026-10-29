# Private agent web

A static browser app for Base Sepolia credit, Pi chat over the attested inference
broker, and encrypted jobs to attested Mac compute nodes. The page displays model
reports, Apple node and job attestations, receipts, decrypted patches and transcripts.
Browser wallets and buyer signing keys stay in IndexedDB; conversations, repository
inputs and sandbox credentials stay in tab memory. An injected wallet can also pay.

Build on the development host with Node 22+:

```sh
npm ci --ignore-scripts
npm run build
python3 dev.py --port 18731
```

Open `http://127.0.0.1:18731/private-agent/`. Development forwards broker requests
to the existing pod. Set `SANDBOX_SOURCE` to the absolute path of
`applications/compute-node/browser/sandbox.mjs` when building against a separate
sandbox worktree. `config.json` supplies public deployment pins and the RPC.

The Trust settings file input accepts an operator-approved JSON policy with
`manifest` (exact manifest bytes as hex), `cdhash`, `brokerKey`, `grantSigner`,
`destinationPolicyHash`, `rpc`, `attest`, `canary`, `registry`, `model`, and
`enrollment: {attestation: <CBOR hex>, keyId, clientData: <hex>}`. It can also be
included as `sandboxPolicy` in the public config. Select a repository tar snapshot
or the sample repo, enter a task and capped delegated TEE credential, verify a
fresh node, then run. Download the verified diff and apply it with `git apply`.

Deploy the build to the `private-agent` project in shared Deno mode:

```sh
python3 deploy.py --evidence /absolute/path/to/local-data/ui/deploy
```

The deployer reads `TEE_DAEMON_TOKEN` from the environment or its existing local
static assignment, packages only the handler and built assets, promotes the
project, and compares public broker and secret-release identities across the update.

Run browser checks using an existing Playwright installation:

```sh
BASE_URL=http://127.0.0.1:18731/private-agent/ \
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
EVIDENCE=/absolute/path/to/local-data/ui npm run test:browser
```
