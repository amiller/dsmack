// The `candidate` service: no dstack socket, so nothing it runs can attest. The checker POSTs
// {files, cases} to :8080/run; this writes the tree, imports the candidate workspaces.mjs and runs
// Workspaces.remote() for each case, answering [{value} | {code, status}] and then exiting.
import { createServer } from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const root = "/workspace/state/tree";
const server = createServer(async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  const { files, cases } = JSON.parse(body);
  for (const [path, b64] of Object.entries(files)) {
    mkdirSync(dirname(root + "/" + path), { recursive: true });
    writeFileSync(root + "/" + path, Buffer.from(b64, "base64"));
  }
  const { Workspaces } = await import(root + "/applications/relay-broker/workspaces.mjs");
  const out = [];
  for (const { url, action } of cases) {
    const w = new Workspaces({ broker: { payments: { key: { signMessage: async () => "0x" } } }, cfg: { stores: { m: url } } });
    try { out.push({ value: await w.remote("m", action, {}) }); } catch (e) { out.push({ code: e.code, status: e.status }); }
  }
  res.end(JSON.stringify(out), () => process.exit(0));
});
server.listen(8080, "0.0.0.0");
