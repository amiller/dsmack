// Provider quote check for the runner, pinned by sha256 in Sources/runner/Pins.swift (the runner refuses any other
// bytes). Dependencies are pinned in package.json / package-lock.json: @phala/aci-verifier, @phala/dcap-qvl.
// usage: node provider_quote.mjs <provider_quote rule JSON> <host> <runner TLS anchors, DER base64, comma separated>
//        (nearai reads the provider API key on stdin; it is never printed)
// Prints {.., tls_spki_sha256: [the TLS SPKI pins the quote attests for <host>], report_b64: exact response body,
//         onchain (onchain rules): {rpc, block, apps: [the DstackApp that admitted each compose_hashes entry]}}.
//
// Admission of a measured compose: it must be in the rule's compose_hashes, or (onchain, nearai only) the measured app-id
// must be in onchain.apps and allowedComposeHashes(compose) on that DstackApp must be true at one block (eth_blockNumber
// first, then eth_call at that block) via onchain.rpc, TLS-pinned to the runner's anchors.
//
// redpill, phala (ACI, aci/1): GET <url>?nonce=<fresh>. Quote verifies to the Intel root (collateral from Intel PCS),
//   TCB UpToDate; report_data = sha256(statement(keyset digest, our nonce)); keyset not expired; event log replays to
//   RTMR3 and sha256(app_compose) is the measured compose-hash, which must be admitted; SPKI pins from
//   workload_keyset.tls_public_keys for <host>.
// nearai (ported from sealed-agent lib/near.mjs): GET <url>?model&nonce&signing_algo=ecdsa&include_tls_fingerprint=true
//   with the key. Gateway: quote verifies (TCB reported, as abalone's providers.json gatewayTcb "reported"),
//   report_data = sha256(signing_address ‖ tls_cert_fingerprint) ‖ nonce, compose measured and admitted; SPKI pin =
//   tls_cert_fingerprint. Each model attestation: model_name = model, keccak(signing_public_key) = signing_address,
//   quote verifies with TCB UpToDate and binds the address (with its own TLS fingerprint, or padded) ‖ nonce, GPU
//   evidence carries our nonce and NVIDIA NRAS says true (NRAS JWT signature not checked), compose measured and admitted.
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import { verifyComposeMeasurement, verifyQuote, verifyReportBinding } from "@phala/aci-verifier";
import { getCollateralAndVerify, INTEL_PCS_URL } from "@phala/dcap-qvl";

class Refused extends Error {}
const must = (ok, what) => { if (!ok) throw new Refused(`provider quote refused: ${what}`); };
const ALLOWED_COMPOSE_HASHES = "0x2f6622e5"; // keccak256("allowedComposeHashes(bytes32)")[:4], = `cast sig`

// The payload of the one pre-system-ready RTMR3 event <name>, bound to its digest (which the RTMR3 replay covers):
// digest = sha384(u32le(event_type) ‖ ":" ‖ name ‖ ":" ‖ payload), as dstack cc-eventlog computes it.
const measured = (report, name) => {
  const evs = [];
  for (const e of JSON.parse(report.attestation.evidence.event_log)) {
    if (e.imr !== 3) continue;
    if (e.event === "system-ready") break;
    if (e.event === name) evs.push(e);
  }
  must(evs.length === 1, `${evs.length} pre-system-ready ${name} events`);
  const t = Buffer.alloc(4); t.writeUInt32LE(evs[0].event_type);
  const d = crypto.createHash("sha384").update(Buffer.concat([t, Buffer.from(`:${name}:`), Buffer.from(evs[0].event_payload, "hex")])).digest("hex");
  must(d === evs[0].digest.toLowerCase(), `${name} event payload does not match its digest`);
  return evs[0].event_payload.toLowerCase();
};

const rpcCall = (rpc, anchors, method, params) => new Promise((resolve, reject) => {
  must(new URL(rpc).protocol === "https:", `onchain.rpc ${rpc} is not https`);
  const ca = anchors.map((b) => `-----BEGIN CERTIFICATE-----\n${b}\n-----END CERTIFICATE-----\n`);
  const req = https.request(rpc, { method: "POST", ca, headers: { "content-type": "application/json" } }, (res) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("end", () => {
      try {
        must(res.statusCode === 200, `RPC ${method} answered HTTP ${res.statusCode}`);
        const r = JSON.parse(Buffer.concat(chunks));
        must(r.error === undefined && typeof r.result === "string", `RPC ${method}: ${JSON.stringify(r.error ?? r)}`);
        resolve(r.result);
      } catch (e) { reject(e); }
    });
  });
  req.on("error", reject);
  req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }));
});

export const chainAt = async (onchain, anchors) => {
  const hex = await rpcCall(onchain.rpc, anchors, "eth_blockNumber", []);
  must(/^0x[0-9a-f]+$/.test(hex), `eth_blockNumber returned ${hex}`);
  return { rpc: onchain.rpc, anchors, hex, block: Number.parseInt(hex, 16) };
};

export const allowed = async (chain, app, composeHash) => {
  const r = await rpcCall(chain.rpc, chain.anchors, "eth_call", [{ to: app, data: ALLOWED_COMPOSE_HASHES + composeHash }, chain.hex]);
  must(r === "0x" + "0".repeat(63) + "1" || r === "0x" + "0".repeat(64), `allowedComposeHashes on ${app} at block ${chain.block} returned ${r}`);
  return r.endsWith("1");
};

// Returns the measured compose-hash and the DstackApp that admitted it (null under compose_hashes).
export const admit = async (report, who, pq, chain) => {
  const m = await verifyComposeMeasurement(report);
  must(m.ok, `${who}: ${m.checks.filter((c) => !c.ok).map((c) => c.detail).join("; ")}`);
  must(measured(report, "compose-hash") === m.composeHash, `${who} compose-hash event payload is not sha256(app_compose)`);
  if (!pq.onchain) {
    must(pq.compose_hashes.includes(m.composeHash), `${who} measured compose-hash ${m.composeHash} is not in the accepted list`);
    return { compose: m.composeHash, app: null };
  }
  const app = "0x" + measured(report, "app-id");
  must(pq.onchain.apps.includes(app), `${who} measured app-id ${app} is not in onchain.apps`);
  must(await allowed(chain, app, m.composeHash), `${who} compose-hash ${m.composeHash} is not allowed by DstackApp ${app} at block ${chain.block}`);
  return { compose: m.composeHash, app };
};

// event_log from tcb_info replays to RTMR3; the top-level model event_log does not (lib/near.mjs).
export const nearEvidence = (att) => {
  const t = typeof att.info.tcb_info === "string" ? JSON.parse(att.info.tcb_info) : att.info.tcb_info, el = t.event_log ?? att.event_log;
  return { attestation: { evidence: { event_log: typeof el === "string" ? el : JSON.stringify(el), app_compose: t.app_compose, quote: att.intel_quote } } };
};

async function main() {
  const [pqArg, host, anchorsArg] = process.argv.slice(2);
  const pq = JSON.parse(pqArg), { kind, attestation_url: url, model } = pq, anchors = anchorsArg.split(",");
  must(Boolean(pq.compose_hashes) !== Boolean(pq.onchain), "exactly one of compose_hashes and onchain");
  const chain = pq.onchain && await chainAt(pq.onchain, anchors);
  const nonce = crypto.randomBytes(32).toString("hex");
  const fetchRaw = async (u, headers = {}) => {
    const r = await fetch(u, { headers });
    must(r.ok, `${new URL(u).origin}${new URL(u).pathname} answered HTTP ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
  };
  const composes = [], apps = [];
  const composeOk = async (report, who) => { const a = await admit(report, who, pq, chain); composes.push(a.compose); apps.push(a.app); };

  let raw, spki, tcb;
  if (kind === "redpill" || kind === "phala") {
    raw = await fetchRaw(`${url}?nonce=${nonce}`);
    const report = JSON.parse(raw);
    const binding = await verifyReportBinding(report, nonce);
    must(binding.ok, binding.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; "));
    const q = await verifyQuote(report, INTEL_PCS_URL);
    must(q.ok, `TDX quote: ${q.detail}`);
    must(q.status === "UpToDate", `TCB status ${q.status} is not UpToDate`);
    tcb = q.status;
    await composeOk(report, "service");
    spki = binding.keyset.tls_public_keys.filter((k) => k.domain === host).map((k) => k.spki_sha256);
  } else if (kind === "nearai") {
    must(model, "nearai needs a model");
    const key = fs.readFileSync(0, "utf8");
    must(key.length > 0, "nearai needs the provider API key on stdin");
    raw = await fetchRaw(`${url}?model=${encodeURIComponent(model)}&nonce=${nonce}&signing_algo=ecdsa&include_tls_fingerprint=true`, { authorization: `Bearer ${key}` });
    const rep = JSON.parse(raw);
    const addr = (a) => Buffer.from(a.replace(/^0x/i, ""), "hex");
    const bound = (a, fp) => fp ? crypto.createHash("sha256").update(addr(a)).update(Buffer.from(fp, "hex")).digest() : Buffer.concat([addr(a), Buffer.alloc(12)]);
    const quote = async (hex, first32, who, gate) => {
      const v = await getCollateralAndVerify(Buffer.from(hex, "hex"), INTEL_PCS_URL);
      if (gate) must(v.status === "UpToDate", `${who} TCB status ${v.status} is not UpToDate`);
      const rd = Buffer.from(v.report.asTd10().reportData);
      must(rd.subarray(0, 32).equals(first32), `${who} report_data does not bind its signing address`);
      must(rd.subarray(32, 64).toString("hex") === nonce, `${who} report_data does not carry our nonce`);
      return v.status;
    };
    const gw = rep.gateway_attestation;
    must(gw?.tls_cert_fingerprint && gw.signing_algo === "ecdsa", "gateway attestation has no TLS binding");
    tcb = await quote(gw.intel_quote, bound(gw.signing_address, gw.tls_cert_fingerprint), "gateway", false);
    await composeOk(nearEvidence(gw), "gateway");
    const mas = rep.model_attestations ?? [];
    must(mas.length > 0, `no model attestation for ${model}`);
    for (const ma of mas) {
      must(ma.model_name === model, `model attestation is for ${ma.model_name}, not ${model}`);
      must("0x" + keccak256(Buffer.from(ma.signing_public_key, "hex")).subarray(12).toString("hex") === ma.signing_address.toLowerCase(), "signing_public_key does not hash to signing_address");
      await quote(ma.intel_quote, bound(ma.signing_address, ma.tls_cert_fingerprint), "model", true);
      const gpu = JSON.parse(ma.nvidia_payload);
      must(gpu.nonce.toLowerCase() === nonce, "GPU evidence nonce is not ours");
      const r = await fetch("https://nras.attestation.nvidia.com/v3/attest/gpu", { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: ma.nvidia_payload });
      must(r.ok, `NVIDIA NRAS answered HTTP ${r.status}`);
      must(JSON.parse(Buffer.from((await r.json())[0][1].split(".")[1], "base64url"))["x-nvidia-overall-att-result"] === true, "NVIDIA NRAS verdict is not true");
      await composeOk(nearEvidence(ma), "model");
    }
    must(new URL(url).hostname === host, `nearai attests the TLS key of ${new URL(url).hostname}, not ${host}`);
    spki = [gw.tls_cert_fingerprint];
  } else must(false, `kind ${kind} is not implemented`);
  spki = spki.map((p) => p.toLowerCase().replace(/:/g, ""));
  must(spki.length > 0, `the attestation binds no TLS key for ${host}`);
  console.log(JSON.stringify({ kind, attestation_url: url, nonce, tcb_status: tcb, compose_hashes: composes, tls_spki_sha256: spki,
    ...(chain && { onchain: { rpc: chain.rpc, block: chain.block, apps } }), report_b64: raw.toString("base64") }));
}
if (import.meta.main) main().catch((e) => { console.error(e instanceof Refused ? e.message : e); process.exit(1); });

// keccak-256 (Ethereum's, not NIST SHA3), copied from sealed-agent lib/keccak.mjs (node has no keccak).
export function keccak256(bytes) {
  const RC = [1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n,
    0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
    0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
  const R = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
  const M = (1n << 64n) - 1n;
  const rot = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M);
  const f = (s) => {
    for (const rc of RC) {
      const c = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
      for (let x = 0; x < 5; x++) { const d = c[(x + 4) % 5] ^ rot(c[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) s[x + y] ^= d; }
      const b = new Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rot(s[x + 5 * y], R[x + 5 * y]);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 25; y += 5) s[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & M & b[(x + 2) % 5 + y]);
      s[0] ^= rc;
    }
  };
  const rate = 136, p = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  p.set(bytes); p[bytes.length] ^= 1; p[p.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let o = 0; o < p.length; o += rate) {
    for (let i = 0; i < rate / 8; i++) { let w = 0n; for (let k = 7; k >= 0; k--) w = (w << 8n) | BigInt(p[o + i * 8 + k]); s[i] ^= w; }
    f(s);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let k = 0; k < 8; k++) out[i * 8 + k] = Number((s[i] >> BigInt(8 * k)) & 0xffn);
  return Buffer.from(out);
}
