# Network dashboard

A public view of signed Mac capacity, opted-in coarse regions, the broker’s
per-minute utilization history, and UsageEscrow compute settlements on Base Sepolia.
The page uses native SVG and two public CORS RPC providers. It needs no wallet,
API key or CDN library. Its published HTML contains the styles, JavaScript and
public configuration, so opening it requires just one IPFS asset.

Run `node build.mjs` using the existing private-agent page’s esbuild installation,
then serve `dist/` with a static HTTP server. Set `WEB_NODE_MODULES` to reuse an
installation elsewhere. Configure the broker, escrow and RPC endpoints in
`config.json`. The private-agent page build also includes the dashboard in
`dist/network/`; publish that directory with the rest of the IPFS app.
Operator links use the sibling `fleet/` page.

Run `node --test chain.test.mjs` for settlement accounting and RPC agreement tests.
