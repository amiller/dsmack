# Browser sandbox client

`sandbox.mjs` verifies compute-node Apple enrollment chains and assertions,
checks the approved build through Base Sepolia RPC, seals jobs with WebCrypto,
submits ciphertext through the broker and verifies/decrypts the result.
The only bundled library is ethers 6.17.0, distributed under its MIT license.
Its standalone ES module comes from the package's `dist/ethers.min.js`.

Serve the repository root over HTTP on localhost or HTTPS and import:

```js
import {
  createClient, verifyNode, sealJob, submitJob, receive, openOutputs,
} from './applications/compute-node/browser/sandbox.mjs';

const client = await createClient();
const node = await verifyNode(registration, policy);
const job = await sealJob(node, {client, grant, credential, repoTar, prompt});
const result = await receive(await submitJob(brokerUrl, job));
const {patch, transcript, verdict} = await openOutputs(job, result);
```

The policy supplies the exact approved `manifest` bytes, `cdhash`, `brokerKey`,
Base Sepolia `rpc`, and Apple `enrollment` (`attestation` and `clientData` bytes,
base64 `keyId`). Paid discovery also supplies a freshly generated `challenge`,
`grantSigner` and `destinationPolicyHash`. `model` optionally pins the measured
MODEL environment value. The module pins the CDRegistry address. The default enrollment mode is `on-chain`. An operator can explicitly choose
`enrollmentMode: 'apple-root'` to authenticate the provided enrollment directly
against Apple's root while keeping the live build, category and canary checks.
`verifyNode` returns `enrollmentMode` for display by the page. The node is
checked independently of the broker's verification label.

`createClient()` creates a browser Ed25519 identity. `signBrokerRequest(client,
body)` signs canonical discovery/grant/payment requests containing that
`client_peer`. `sealJob` generates a fresh, nonextractable P-256 output key;
retain its context in memory until outputs have opened. `submitJob` signs both
the encrypted bundle and grant hashes so a forwarder cannot substitute either.
`verifyJobAttestation` and `verifyReceipt` expose the verification details for a
UI. `openOutputs` performs both checks before releasing output bytes.

Run the browser/Python wire compatibility check:

```sh
python3 applications/compute-node/browser/interop.py
```

Replay an existing captured node/job with the verification command:

```sh
node applications/compute-node/browser/replay.mjs replay-inputs.json
```

The JSON file names `discovery`, `result`, `grant`, `sealed`, `manifest`,
`enrollment` (directory), and `outputs` (directory). The replay supplies the
historical chain state and checks the original signatures and plaintext hashes.
Live browser calls use the configured RPC.

Run the two-stage browser journey in a Playwright Python container:

```sh
python3 applications/compute-node/browser/e2e.py \
  --url http://127.0.0.1:18481 --config /harness/public/config.json --out /evidence
```

The public config contains `broker`, `policy` (plus `manifestUrl`,
`enrollmentUrl`, `keyIdUrl`, `clientDataUrl`), `repoTarUrl`, `prompt`, `seconds`
and `credentialUrl`. After verifying a live node, the driver writes
`credential-request.json` to its evidence directory. An independent credential
holder seals the credential to that node with label `jobId + '/credential'`
and publishes `{schema:'dsmack-sealed-credential/1',box}` at `credentialUrl`.
The driver seals the complete job and saves the verified patch, transcript,
verdict, signed evidence, screenshots and video. Its browser profile contains
only the encrypted credential envelope.
