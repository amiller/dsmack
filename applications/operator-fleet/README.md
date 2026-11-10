# Operator fleet

A static, view-only fleet page. Open `?operator=0xADDRESS` or connect your operator
wallet to see linked Macs, reported capacity, rotating guest slots, attestation
evidence and errors.
Earnings come from finalized Base Sepolia cumulative USDC claims. The reader
computes each claim increment per user/operator, and daily earnings use the
payout block time. Payouts cover all Macs linked to the operator wallet.

Build on a Linux development host using the private-agent page's existing install:

```sh
WEB_NODE_MODULES=/absolute/path/to/private-agent-web/node_modules node build.mjs
```

Set `FLEET_CONFIG=/absolute/path/to/public-config.json` to build with a separate
broker and escrow configuration. The staging agent-page build supplies its own
generated configuration for the included fleet page.

Serve `dist/` directly, or copy it into `fleet/` in the friends' IPFS page before
adding and publishing that static directory with the existing Mac Kubo service.
All assets are relative to the page. `config.json` contains the public broker,
escrow, deployment block and RPC pins. Operator earnings remain attached to the paid wallet when a Mac changes owners.

Run the model checks with `node --test model.test.mjs`.
The operator comes from the Mac’s signed ownership link. Changing capacity means
editing `~/.dsmack/operator.json` on the Mac and restarting its pool.
