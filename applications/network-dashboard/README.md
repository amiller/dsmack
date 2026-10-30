# Network dashboard

A public view of signed Mac capacity, opted-in coarse regions, the broker’s
per-minute utilization history, and UsageEscrow compute settlements on Base Sepolia.
The page uses native SVG and two public CORS RPC providers. It needs no wallet,
API key, CDN library or build dependencies.

Run `node build.mjs`, then serve `dist/` with a static HTTP server. Configure the
broker, escrow and RPC endpoints in `config.json`. The private-agent page build
also copies the dashboard into `dist/network/`; publish that directory with the
rest of the IPFS app. Operator links use the sibling `fleet/` page.

Run `node --test chain.test.mjs` for settlement accounting and RPC agreement tests.
