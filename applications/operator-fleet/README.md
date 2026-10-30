# Operator fleet

A static, view-only fleet page. Open `?operator=0xADDRESS` or connect your operator
wallet to see linked Macs, reported capacity, rotating guest slots, attestation
evidence and errors.
Earnings and recent jobs come from finalized Base Sepolia escrow settlements.
Signed guest receipts and broker run bindings are recovered from settlement
transactions. Daily earnings use the settlement block time.

Build on a Linux development host using the private-agent page's existing install:

```sh
WEB_NODE_MODULES=/absolute/path/to/private-agent-web/node_modules node build.mjs
```

Serve `dist/` directly, or copy it into `fleet/` in the friends' IPFS page before
adding and publishing that static directory with the existing Mac Kubo service.
All assets are relative to the page. `config.json` contains the public broker,
escrow, deployment block and RPC pins. `classesByPublisher` associates previous
node classes with their Mac publisher so historical earnings survive a class change.

Run the model checks with `node --test model.test.mjs`. A fresh public gateway
browser check uses the existing Playwright installation:

```sh
OPERATOR_ADDRESS=0xYourOperatorAddress PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
  node browser-check.mjs https://NAME.ipns.GATEWAY/fleet/ /absolute/path/to/evidence
```

The browser check opens the supplied public operator address without connecting
a wallet. It reads the live broker and chain, opens Mac details and saves a
screenshot and result JSON. The operator comes from the Mac’s signed ownership
link. Changing capacity means editing
`~/.dsmack/operator.json` on the Mac and restarting its pool.
