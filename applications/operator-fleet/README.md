# Operator fleet

A static, view-only fleet page. Connect the wallet that receives your operator
payouts to see Mac capacity, rotating guest slots, attestation evidence and errors.
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

Run the model checks with `node --test model.test.mjs`. Changing capacity means editing
`~/.dsmack/operator.json` on the Mac and restarting its pool.
