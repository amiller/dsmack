# Browser sandbox client

`sandbox.mjs` verifies compute-node Apple enrollment chains and assertions,
checks the approved build through Base Sepolia RPC, seals jobs with WebCrypto,
submits ciphertext through the broker and verifies/decrypts the result.
The only bundled library is ethers 6.17.0, distributed under its MIT license.
Its standalone ES module comes from the package's `dist/ethers.min.js`.

Serve the repository root over HTTP on localhost or HTTPS and import:

```js
import {
  createClient, verifyNode, requestCapability, sealJob, submitJob, receive, openOutputs,
  hex,
} from './applications/compute-node/browser/sandbox.mjs';

const client = await createClient();
const node = await verifyNode(registration, policy);
const jobId = hex(crypto.getRandomValues(new Uint8Array(16)));
const credential = await requestCapability(brokerUrl, {node, client, grant, jobId});
const job = await sealJob(node, {client, grant, jobId, credential, repoTar, prompt});
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
`client_peer`. `requestCapability` verifies the allowance and requests a job-bound
inference capability with that identity. The capability is sealed into the job;
provider keys stay in the broker CVM. `sealJob` generates a fresh, nonextractable P-256 output key;
retain its context in memory until outputs have opened. `submitJob` signs both
the encrypted bundle and grant hashes so a forwarder cannot substitute either.
`verifyJobAttestation` and `verifyReceipt` expose the verification details for a
UI. `openOutputs` performs both checks and verifies each signed broker inference
response against its adjacent assistant event before releasing output bytes.
The measured `dsmack-broker-model/1` configuration pins the broker origin, key
and model. The UI displays: NEAR TEE model via broker CVM; broker handles plaintext.

Run the browser/Python wire compatibility check:

```sh
python3 applications/compute-node/browser/interop.py
```

Replay an existing captured node/job with the verification command:

```sh
node applications/compute-node/browser/replay.mjs replay-inputs.json
```

The JSON file names `discovery`, `result`, `grant`, `sealed`, `manifest`,
`enrollment` (directory), and `outputs` (directory). An optional `paymentsFixture` names the Go payment interoperability JSON
for checking paid-node binding and receipt signatures/digests. The replay supplies the
historical chain state and checks the original signatures and plaintext hashes.
Optional `paidDiscovery` and `paidPolicy` paths replay a real paid registration
with its captured lifetime and chain state. Live browser calls use the configured RPC.

Run the capability and signed response boundary tests:

```sh
node --test applications/compute-node/browser/capability.test.mjs
```

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

HTTP refusals throw an `Error` with numeric `status` and the original JSON
`response`. Keep any usage receipt in that response for payment reconciliation.

Run the deployed page's operator diagnostic in a Playwright Python container:

```sh
python3 applications/compute-node/browser/live-check.py \
  --policy /policy.json --repo /repo.tar --seconds 60 --out /evidence
```

The page bundle exports `sandbox-client.js`. The driver loads the trusted policy,
verifies a live node and writes `operator-grant-request.json`. The operator
obtains the signed diagnostic allowance from the broker using laptop-held
authentication and atomically publishes it as `/evidence/grant.json`. The browser
then requests its inference capability, seals the job and records verified
outputs. It uses a fresh browser context and labels the allowance as an operator
diagnostic. `--inspect-credit-profile /profile` instead records existing credit
cards while refusing broker POSTs and wallet signing or transaction requests.
