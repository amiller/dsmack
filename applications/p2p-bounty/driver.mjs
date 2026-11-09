// Guest side of a p2p bounty run. The host sends one JSON line over the pinned egress:
// {chain_id, bounty, id, payee, commit, objects: [hex loose git objects], files: {path: base64}}.
// Every byte is checked against this measured file: base files and ethers by PINNED sha256, the
// candidate file by walking git objects down from `commit`. The check runs offline; only if it
// passes does this call /v1/Attest with report_data = Bounty.reportData(id, payee, commit).
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { request } from "node:http";
import { connect } from "node:net";

const { HOST, PORT, CANDIDATE, PINNED, CHECK, DOMAIN } = JSON.parse(Buffer.from(process.env.BOUNTY, "base64"));
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
for (const [i, name] of CANDIDATE.split("/").entries()) {
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
const root = "/workspace/state/tree";
files["applications/payments/schema.mjs"] = Buffer.from(files["applications/payments/schema.mjs"].toString().replaceAll('"npm:ethers@6.17.0"', '"/workspace/state/tree/ethers.js"'));
files["check.mjs"] = Buffer.from(CHECK);
for (const [path, raw] of Object.entries(files)) { mkdirSync(dirname(root + "/" + path), { recursive: true }); writeFileSync(root + "/" + path, raw); }

let out = { commit: req.commit, payee: req.payee, passed: false };
try {
  out.log = execFileSync(process.execPath, ["check.mjs"], { cwd: root, timeout: 120000, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  out.passed = true;
} catch (error) { out.log = String(error.stdout ?? "") + String(error.stderr ?? error.message); }

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
