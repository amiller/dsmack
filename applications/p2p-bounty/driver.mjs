// The `checker` service, the only one the bounty pins and the only one with the dstack socket. The host
// sends one JSON line over the pinned egress: {chain_id, bounty, id, payee, commit, objects: [hex loose git
// objects], files: {path: base64}}. Base files and ethers are checked against PINNED sha256 and the candidate
// file against the git objects under `commit`. No candidate code runs here: the `candidate` service runs it
// against stub stores this process serves with per-run random answers, and this process judges the results.
// Only if all cases match does it call /v1/Attest with report_data = Bounty.reportData(id, payee, commit).
import { createHash, randomBytes, randomInt } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createServer, request } from "node:http";
import { connect } from "node:net";

const { HOST, PORT, CANDIDATE, PINNED, DOMAIN } = JSON.parse(Buffer.from(process.env.BOUNTY, "base64"));
const sha = (alg, b) => createHash(alg).update(b).digest();
const need = (ok, msg) => { if (!ok) throw new Error(msg); };

const sock = connect(PORT, HOST).setEncoding("utf8");
const req = await new Promise((resolve, reject) => {
  let buf = "";
  sock.on("data", (c) => { buf += c; if (buf.includes("\n")) resolve(JSON.parse(buf.slice(0, buf.indexOf("\n")))); });
  sock.on("error", reject);
});

const objects = new Map(req.objects.map((h) => { const raw = Buffer.from(h, "hex"); return [sha("sha1", raw).toString("hex"), raw]; }));
function object(id, type) {
  const raw = objects.get(id);
  need(raw, "missing git object " + id);
  const nul = raw.indexOf(0), [t, n] = raw.subarray(0, nul).toString().split(" ");
  need(t === type && Number(n) === raw.length - nul - 1, "bad git object " + id);
  return raw.subarray(nul + 1);
}
let id = /^tree ([0-9a-f]{40})$/m.exec(object(req.commit, "commit").toString())[1];
for (const name of CANDIDATE.split("/")) {
  const tree = object(id, "tree");
  let found;
  for (let p = 0; p < tree.length && !found;) {
    const sp = tree.indexOf(0x20, p), nul = tree.indexOf(0, sp);
    if (tree.subarray(sp + 1, nul).toString() === name) found = tree.subarray(nul + 1, nul + 21).toString("hex");
    p = nul + 21;
  }
  need(found, "candidate path not in commit");
  id = found;
}
const files = { [CANDIDATE]: object(id, "blob") };
for (const [path, digest] of Object.entries(PINNED)) {
  files[path] = Buffer.from(req.files[path], "base64");
  need(sha("sha256", files[path]).toString("hex") === digest, "pinned file mismatch " + path);
}
files["applications/payments/schema.mjs"] = Buffer.from(files["applications/payments/schema.mjs"].toString().replaceAll('"npm:ethers@6.17.0"', '"/workspace/state/tree/ethers.js"'));

const token = randomBytes(16).toString("hex"), code = "E_" + randomBytes(6).toString("hex").toUpperCase(), status = randomInt(400, 500);
const stub = createServer((req, res) => {
  const ok = req.url === "/begin";
  res.writeHead(ok ? 200 : status, { "content-type": "application/json" });
  res.end(JSON.stringify(ok ? { token } : { error: { code, message: "refused" } }));
});
await new Promise((resolve) => stub.listen(8081, "0.0.0.0", resolve));
const cases = [{ url: "http://checker:8081", action: "begin" }, { url: "http://checker:8081", action: "commit" }, { url: "http://checker:8082", action: "begin" }];
const body = JSON.stringify({ files: Object.fromEntries(Object.entries(files).map(([p, b]) => [p, b.toString("base64")])), cases });
const post = () => new Promise((resolve, reject) => {
  const r = request({ host: "candidate", port: 8080, path: "/run", method: "POST", timeout: 120000 }, (res) => {
    let b = ""; res.on("data", (c) => b += c); res.on("end", () => resolve(b));
  });
  r.on("error", reject); r.on("timeout", () => r.destroy(new Error("candidate timeout"))); r.end(body);
});
let out = { commit: req.commit, payee: req.payee, passed: false };
for (let i = 0; i < 60 && out.results === undefined; i++) {
  try { out.results = JSON.parse(await post()); } catch (error) { out.error = String(error); await new Promise((r) => setTimeout(r, 1000)); }
}
const [live, refused, down] = out.results ?? [];
out.passed = live?.value?.token === token && Object.keys(live.value).length === 1
  && refused?.code === code && refused?.status === status
  && down?.code === "WORKSPACE_STORE_UNAVAILABLE" && down?.status === 503;
stub.close();

if (out.passed) {
  const u256 = (v) => Buffer.from(BigInt(v).toString(16).padStart(64, "0"), "hex");
  const addr = (a) => { need(/^0x[0-9a-fA-F]{40}$/.test(a), "address"); return Buffer.from(a.slice(2), "hex"); };
  need(/^[0-9a-f]{40}$/.test(req.commit), "commit");
  const h = sha("sha256", Buffer.concat([Buffer.from(DOMAIN), u256(req.chain_id), addr(req.bounty), u256(req.id), addr(req.payee), Buffer.from(req.commit, "hex")]));
  out.report_data = h.toString("hex") + "00".repeat(32);
  out.attestation = await new Promise((resolve, reject) => {
    const r = request({ socketPath: "/var/run/dstack.sock", path: "/v1/Attest", method: "POST", headers: { "content-type": "application/json" } }, (res) => {
      let body = ""; res.on("data", (c) => body += c); res.on("end", () => res.statusCode === 200 ? resolve(JSON.parse(body).attestation) : reject(new Error(body)));
    });
    r.on("error", reject); r.end(JSON.stringify({ report_data: out.report_data }));
  });
}
writeFileSync("/workspace/artifacts/result.json", JSON.stringify(out));
sock.end(JSON.stringify(out) + "\n");
console.log(JSON.stringify({ passed: out.passed, commit: out.commit, payee: out.payee }));
