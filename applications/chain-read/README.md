# chain-read

A browser module that reads Base through a Helios light client running in the page, plus a small Cloudflare
Worker that keeps an RPC API key off the page.

Helios (OP-stack mode) follows Base's sequencer-signed head and checks every read against it with Merkle proofs.
The JSON-RPC sources and the head relays are untrusted. A source that answers wrongly fails Helios's proof check,
and the read moves on to the next source; a relay can withhold heads but cannot forge the sequencer signature. So a
bad source or relay can make reads slow or fail, but cannot make them return wrong values.

## Use

```js
import { chainRead } from "./chain-read.mjs";

const cr = await chainRead({ network: "base-sepolia" });
const s = await cr.snapshot();                        // { block, call, multicall }, pinned to one block hash
const [a, b] = await s.multicall([[to1, data1], [to2, data2]]);   // one Multicall3 eth_call, results as Uint8Array
const c = await s.call(to1, data1);                   // cached per (block, call)
cr.diagnostics.reads;  // [{ method, source, failures: [{ source, error }], ms }] for the last 100 reads
```

With no arguments the page uses, in order:

1. the site's own Worker at `/chain-read/rpc`, with head relay `/chain-read/latest`;
2. the public RPC for the network (`https://sepolia.base.org` or `https://mainnet.base.org`);
3. `window.ethereum`, if a wallet is injected and already on the right chain. The loader only asks it for
   `eth_chainId` and the read methods Helios needs; it never asks for accounts or a chain switch.

Each read tries the sources in that order. The source that served it and every failure before it are in
`cr.diagnostics.reads`; a wallet that was left out is in `cr.diagnostics.skipped`; per-relay counts and the last
relay error are in `cr.diagnostics.relays`. A read that fails on every source rejects with all of the failures.

Helios is handed the newest head that is `lagSeconds` (default 3) old, because hosted RPCs often lack state for the
newest one or two blocks.

Other configurations:

```js
chainRead({ worker: "/api/chain" });                                  // Worker at /api/chain/rpc and /api/chain/latest
chainRead({ relays: ["https://relay.example"], sources: [{ url: "https://sepolia.base.org" }] });
chainRead({ sources: [{ name: "wallet", provider: window.ethereum }, { url: "https://chain.example/rpc" }] });
```

`vendor/helios-0.12.0.mjs` is `dist/lib.mjs` from npm `@a16z/helios@0.12.0` (4.4 MB, WASM inlined).

## Worker

`worker/worker.mjs` forwards JSON-RPC (single or batch) to `RPC_URL` for `eth_chainId`, `eth_blockNumber`,
`eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getCode`, `eth_getProof`, `eth_createAccessList` and `eth_call`,
and answers any other method with a JSON-RPC error. `GET .../latest` proxies `RELAY_URL/latest`. Requests are rate
limited per client IP (600 a minute, set in `wrangler.toml`). Route it at `<site>/chain-read/*` to match the loader's
default.

```sh
cd worker
wrangler secret put RPC_URL      # e.g. an Alchemy Base Sepolia URL with its key
wrangler secret put RELAY_URL    # a Helios opstack-server serving GET /latest
wrangler deploy
```

## Relay

Helios's OP-stack client takes its head from a server answering `GET /latest` with the newest sequencer-signed
block, such as Helios's `opstack-server`, which follows the sequencer's gossip. Point `relays` or `RELAY_URL` at
it. Helios's built-in host, `https://<network>.operationsolarstorm.org`, is the last default relay. `chainRead`
rejects when no relay answers its first `/latest`.

## Test

```sh
node --test chain-read.test.mjs worker/worker.test.mjs
node check.mjs <relay URL> https://sepolia.base.org    # dsmack's 11 reads as one Multicall3, verified, with timings
```

## In a browser

- A page with a Content-Security-Policy needs `'wasm-unsafe-eval'` in `script-src`.
- A relay used directly needs CORS headers; the Worker's `/latest` adds them.
- The source must serve `eth_getProof` a few blocks behind head. sepolia.base.org does (rate-limited); publicnode refuses ("maximum proof window").
