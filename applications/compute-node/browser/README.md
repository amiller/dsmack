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

Run the capability and signed response boundary tests:

```sh
node --test applications/compute-node/browser/capability.test.mjs
```

HTTP refusals throw an `Error` with numeric `status` and the original JSON
`response`. Keep any usage receipt in that response for payment reconciliation.
