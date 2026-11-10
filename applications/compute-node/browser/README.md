# Browser compute-node verifier

`sandbox.mjs` verifies a compute node's Apple enrollment chain and assertion,
checks the approved build through Base Sepolia RPC, and checks that the
attestation binds the node's PeerId and keys. The only bundled library is ethers
6.17.0, distributed under its MIT license. Its standalone ES module comes from the
package's `dist/ethers.min.js`.

```js
import { createClient, verifyNode } from './applications/compute-node/browser/sandbox.mjs';

const client = await createClient();
const node = await verifyNode(registration, policy);
```

The policy supplies the exact approved `manifest` bytes, `cdhash`, `brokerKey`,
Base Sepolia `rpc`, and Apple `enrollment` (`attestation` and `clientData` bytes,
base64 `keyId`). Paid discovery also supplies a freshly generated `challenge` and
`grantSigner`. The module pins the CDRegistry address. The default enrollment mode
is `on-chain`. An operator can explicitly choose `enrollmentMode: 'apple-root'` to
authenticate the provided enrollment directly against Apple's root while keeping
the live build, category and canary checks. `verifyNode` returns `enrollmentMode`
for display by the page.

`cdhash` names the approved build. In `on-chain` mode a node may run any copy of
it that `CDRegistry` resolves, such as one re-signed under its host's own Apple
team: `rpIdHash` must resolve the policy's `cdhash` and the assertion's CDHash,
and the assertion's RP ID must be the one its CDHash was registered with.
`verifyNode` returns the assertion's CDHash as `cdhash`. In `apple-root` mode the
enrollment and the assertion carry the policy's exact `cdhash`.

`createClient()` creates a browser Ed25519 identity used as the libp2p client
peer for agent sessions.
