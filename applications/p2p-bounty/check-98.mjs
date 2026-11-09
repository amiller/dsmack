// Bounty check for #98, run from the root of the projected tree: a store that cannot be reached
// is WORKSPACE_STORE_UNAVAILABLE/503, while answers and refusals from a reachable store are unchanged.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Workspaces } from "./applications/relay-broker/workspaces.mjs";

const server = createServer((req, res) => {
  res.writeHead(req.url === "/begin" ? 200 : 409, { "content-type": "application/json" });
  res.end(JSON.stringify(req.url === "/begin" ? { ok: true } : { error: { code: "STALE_HEAD", message: "stale" } }));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const workspaces = (url) => new Workspaces({ broker: { payments: { key: { signMessage: async () => "0x" } } }, cfg: { stores: { m: url } } });
const live = workspaces(`http://127.0.0.1:${server.address().port}`);
assert.deepEqual(await live.remote("m", "begin", {}), { ok: true });
await assert.rejects(live.remote("m", "commit", {}), (e) => e.code === "STALE_HEAD" && e.status === 409);
const closed = createServer();
await new Promise((resolve) => closed.listen(0, "127.0.0.1", resolve));
const port = closed.address().port;
await new Promise((resolve) => closed.close(resolve));
await assert.rejects(workspaces(`http://127.0.0.1:${port}`).remote("m", "begin", {}),
  (e) => e.code === "WORKSPACE_STORE_UNAVAILABLE" && e.status === 503);
server.close();
console.log("check-98 passed");
