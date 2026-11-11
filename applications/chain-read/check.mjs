// usage: node check.mjs <relay base URL> <rpc URL>... : dsmack's 11 Base Sepolia reads as one Multicall3 per snapshot,
// verified by Helios, with timings and the per-read source diagnostics.
import { chainRead } from "./chain-read.mjs";

const CALLS = [
  ["attest.cds", "0x04f57D219B1CEaE7f000C2a3360Ce49CffF3162e", "0xb4eb10ce"],
  ["attest.validationCategory", "0x04f57D219B1CEaE7f000C2a3360Ce49CffF3162e", "0x5523509a"],
  ["attest.keys", "0x04f57D219B1CEaE7f000C2a3360Ce49CffF3162e", "0xdde5b7a1fb56ea95d8301fafdef1d3eef6751be2983af556f3e4ceb97d1365c5816cf7bf"],
  ["registry.rpIdHash", "0x14b569c5D81d42621c5C0d4d62185239C86D8d20", "0x65f4df9c0c3d3c90bb26fa01d01aff1fba61f83d395bc8e2df29d2ec5b95acff2c75969f"],
  ["registry.buildId", "0x14b569c5D81d42621c5C0d4d62185239C86D8d20", "0xb7b014b6"],
  ["canary.burnedImage", "0x95afFDb230772F350dF71d1DF5597FCC69a690D3", "0xe62b7cbd7c1ebf67bcc78f16cea9d729c6e636c10a814a3b5e89e3fa7528b5d59c16033c"],
  ["canary.burnedBuild", "0x95afFDb230772F350dF71d1DF5597FCC69a690D3", "0xda746951df2cc3ef35273367f60416dda9e7a7a7066eac24d306932b5ec74dcdbcf4b127"],
  ["escrow.brokerSigner", "0x835A61a88Cc8D750b5a971219aa8f9813B2067e6", "0xfca82211"],
  ["escrow.getNode", "0x835A61a88Cc8D750b5a971219aa8f9813B2067e6", "0x50c946fe677daca0b95d0a1a3f7edbf9f8151de0c87a43308842a402aa8fc81d2c622b76"],
  ["escrow.deposits", "0x835A61a88Cc8D750b5a971219aa8f9813B2067e6", "0xfc7e286d0000000000000000000000001fbe7a7b3f7a37a967f3d927abd6f04db2766c5b"],
  ["escrow.exitRequestedAt", "0x835A61a88Cc8D750b5a971219aa8f9813B2067e6", "0x57a21c580000000000000000000000001fbe7a7b3f7a37a967f3d927abd6f04db2766c5b"],
];
const [relay, ...rpcs] = process.argv.slice(2);
const ms = (t) => Math.round(performance.now() - t);
let t = performance.now();
const cr = await chainRead({ relays: [relay], sources: rpcs.map((url) => ({ url })), lagSeconds: +(process.env.LAG_S ?? 6) });
console.log("synced in", ms(t), "ms");
for (let i = 0; i < +(process.env.ROUNDS ?? 3); i++) {
  t = performance.now();
  const s = await cr.snapshot();
  const pinned = ms(t);
  t = performance.now();
  const out = await s.multicall(CALLS.map(([, to, data]) => [to, data]));
  const cold = ms(t);
  t = performance.now();
  await s.multicall(CALLS.map(([, to, data]) => [to, data]));
  console.log(JSON.stringify({ block: s.block.number, age_s: Math.round(Date.now() / 1000 - s.block.timestamp), pin_ms: pinned, multicall_ms: cold, cached_ms: ms(t) }));
  if (i === 0) CALLS.forEach(([n], k) => console.log(" ", n, Buffer.from(out[k]).toString("hex").slice(0, 80)));
  await new Promise((ok) => setTimeout(ok, 3000));
}
console.log(JSON.stringify(cr.diagnostics, null, 1));
await cr.close();
process.exit(0);
