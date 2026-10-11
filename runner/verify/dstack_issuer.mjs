// Issuer identity verification only; this does not qualify private issuance or rollback.
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const ISSUER_DOMAIN = "dsmack-coupon-issuer-identity-v2";
const POSSESSION_DOMAIN = "dsmack-coupon-issuer-possession-v2\0";
const POLICY_DOMAIN = "dsmack-coupon-issuer-policy-v2\0";
const RUNTIME_TYPE = 0x08000001;
const deny = () => new Error("dstack issuer identity verification refused");
const hash = (kind, ...parts) => crypto.createHash(kind).update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
const hex = (v, bytes) => typeof v === "string" && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(v);
const keys = (v, expected) => v && Object.getPrototypeOf(v) === Object.prototype && Object.keys(v).sort().join(",") === [...expected].sort().join(",");
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
}
const jsonBytes = (v) => Buffer.from(JSON.stringify(canonical(v)));
function binding(value) {
  if (!keys(value, ["version", "peer_id", "public_key_hex", "challenge_hex", "policy_sha256"]) || value.version !== 2
      || typeof value.peer_id !== "string" || !/^[A-Za-z0-9]{16,128}$/.test(value.peer_id)
      || !hex(value.public_key_hex, 32) || !hex(value.challenge_hex, 32) || !hex(value.policy_sha256, 32)) throw deny();
  return value;
}
export function issuerReportData(value) {
  return hash("sha512", `${ISSUER_DOMAIN}\0`, jsonBytes(binding(value)));
}
export function issuerPossessionMessage(value) {
  return Buffer.concat([Buffer.from(POSSESSION_DOMAIN), issuerReportData(value)]);
}
function checkedPolicy(value) {
  if (!keys(value, ["version", "challenge_ttl_ms", "approved_measurements"]) || value.version !== 2
      || !Number.isSafeInteger(value.challenge_ttl_ms) || value.challenge_ttl_ms < 1000 || value.challenge_ttl_ms > 300_000
      || !Array.isArray(value.approved_measurements) || value.approved_measurements.length < 1 || value.approved_measurements.length > 64) throw deny();
  for (const m of value.approved_measurements) {
    // Runtime pins use the same 4096-byte payload bound as RTMR replay below.
    if (!keys(m, ["compose_sha256", "mr_td", "rtmr0", "rtmr1", "rtmr2", "runtime_events"])
        || !hex(m.compose_sha256, 32) || ![m.mr_td, m.rtmr0, m.rtmr1, m.rtmr2].every((v) => hex(v, 48))
        || !keys(m.runtime_events, ["app-id", "key-provider", "os-image-hash"])
        || !Object.values(m.runtime_events).every((v) => typeof v === "string" && /^[0-9a-f]{2,8192}$/.test(v) && v.length % 2 === 0)) throw deny();
  }
  // Snapshot all policy bytes; caller mutation cannot reinterpret pending challenges.
  return JSON.parse(JSON.stringify(value));
}
export function issuerPolicyHash(value) {
  return hash("sha256", POLICY_DOMAIN, jsonBytes(checkedPolicy(value))).toString("hex");
}
function checkedEvidence(bundle) {
  if (!keys(bundle, ["domain", "binding", "quote_hex", "event_log", "app_compose", "possession_signature_hex"])
      || bundle.domain !== ISSUER_DOMAIN || !hex(bundle.possession_signature_hex, 64)
      || typeof bundle.quote_hex !== "string" || bundle.quote_hex.length < 2 || bundle.quote_hex.length > 262144
      || !/^(?:[0-9a-f]{2})+$/.test(bundle.quote_hex)
      || typeof bundle.event_log !== "string" || Buffer.byteLength(bundle.event_log) > 1048576
      || typeof bundle.app_compose !== "string" || !bundle.app_compose.length || Buffer.byteLength(bundle.app_compose) > 131072) throw deny();
  binding(bundle.binding);
  // Strict copy also removes aliases while asynchronous verification is running.
  return JSON.parse(JSON.stringify(bundle));
}
function checkedQuote(q) {
  const fields = ["quoteVersion", "reportType", "status", "reportData", "tdAttributes", "mrTd", "rtMr0", "rtMr1", "rtMr2", "rtMr3"];
  if (!keys(q, fields) || q.quoteVersion !== 4 || q.reportType !== "td10" || q.status !== "UpToDate"
      || !hex(q.reportData, 64) || !hex(q.tdAttributes, 8)
      || ![q.mrTd, q.rtMr0, q.rtMr1, q.rtMr2, q.rtMr3].every((v) => hex(v, 48))) throw deny();
  // DCAP production verifier also rejects DEBUG/reserved bits and requires SEPT_VE_DISABLE.
  // Keep this explicit in the admission boundary, including its synthetic adapter tests.
  const attr = Buffer.from(q.tdAttributes, "hex");
  if (attr[0] !== 0 || attr[1] !== 0 || attr[2] !== 0 || (attr[3] & 0x3f) !== 0x10
      || attr[4] !== 0 || attr[5] !== 0 || attr[6] !== 0 || (attr[7] & 0x7f) !== 0) throw deny();
  return q;
}
function measuredRuntime(bundle, quote) {
  const events = JSON.parse(bundle.event_log);
  if (!Array.isArray(events) || events.length < 1 || events.length > 2048) throw deny();
  let mr = Buffer.alloc(48), ready = false, readyCount = 0;
  const measured = new Map();
  for (const e of events) {
    if (!e || Object.getPrototypeOf(e) !== Object.prototype || Object.keys(e).some((k) => !["imr", "event_type", "digest", "event", "event_payload", "version", "preimage"].includes(k))
        || !Number.isInteger(e.imr) || e.imr < 0 || e.imr > 3 || !Number.isInteger(e.event_type) || e.event_type < 0 || e.event_type > 0xffffffff
        || (!hex(e.digest, 48) && !(e.imr === 3 && e.digest === "")) || typeof e.event !== "string" || Buffer.byteLength(e.event) > 128
        || typeof e.event_payload !== "string" || !/^(?:[0-9a-f]{2})*$/.test(e.event_payload) || e.event_payload.length > 8192) throw deny();
    // Boot lanes are authorized by exact authenticated MR pins, not untrusted display labels.
    if (e.imr !== 3) continue;
    if (e.event_type !== RUNTIME_TYPE || !/^[A-Za-z0-9_-]{1,128}$/.test(e.event)) throw deny();
    const version = e.version ?? 1;
    let preimage;
    if (version === 1) {
      const type = Buffer.alloc(4); type.writeUInt32LE(RUNTIME_TYPE);
      preimage = Buffer.concat([type, Buffer.from(`:${e.event}:`), Buffer.from(e.event_payload, "hex")]);
      if (e.preimage !== undefined && e.preimage !== preimage.toString("hex")) throw deny();
    } else if (version === 2) {
      preimage = jsonBytes({ name: e.event, payload: e.event_payload, type: RUNTIME_TYPE });
      if (e.preimage !== preimage.toString("hex")) throw deny();
    } else throw deny();
    // Genuine SDK runtime entries may report an empty digest. Authenticate
    // their display bytes by recomputing the digest and matching quoted RTMR3.
    const digest = hash("sha384", preimage);
    if (e.digest !== "" && digest.toString("hex") !== e.digest) throw deny();
    mr = hash("sha384", mr, digest);
    if (["compose-hash", "app-id", "key-provider", "os-image-hash"].includes(e.event)) {
      if (ready || measured.has(e.event)) throw deny();
      measured.set(e.event, e.event_payload);
    }
    if (e.event === "system-ready") { ready = true; readyCount++; }
  }
  if (readyCount !== 1 || measured.size !== 4 || mr.toString("hex") !== quote.rtMr3
      || measured.get("compose-hash") !== hash("sha256", bundle.app_compose).toString("hex")) throw deny();
  return measured;
}

// Run genuine DCAP in a separately reaped process. Intel collateral fetches have
// no abort API in the pinned library; the parent deadline terminates the process.
export function verifyDcapQuote(quoteHex, { timeoutMs = 15_000, signal } = {}) {
  if (typeof quoteHex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(quoteHex) || quoteHex.length > 262144
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) return Promise.reject(deny());
  if (signal?.aborted) return Promise.reject(deny());
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--max-old-space-size=96", fileURLToPath(new URL("./dstack_quote_worker.mjs", import.meta.url))], {
      stdio: ["pipe", "pipe", "pipe"], env: { LANG: "C.UTF-8" }, detached: process.platform !== "win32",
    });
    let bytes = 0, output = [], failed = false, done = false;
    const stop = () => {
      failed = true;
      try { if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL"); else child.kill("SIGKILL"); } catch {}
    };
    const timer = setTimeout(stop, timeoutMs); timer.unref();
    signal?.addEventListener("abort", stop, { once: true });
    if (signal?.aborted) stop();
    child.stdout.on("data", (chunk) => { bytes += chunk.length; if (bytes > 4096) stop(); else output.push(chunk); });
    child.stderr.on("data", stop); // raw collateral/provider errors are never forwarded
    child.stdin.on("error", stop);
    child.once("error", () => { if (!done) { done = true; clearTimeout(timer); signal?.removeEventListener("abort", stop); reject(deny()); } });
    child.once("close", (code) => {
      if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener("abort", stop);
      if (failed || code !== 0) return reject(deny());
      try { resolve(checkedQuote(JSON.parse(Buffer.concat(output).toString("utf8")))); } catch { reject(deny()); }
    });
    child.stdin.end(quoteHex);
  });
}
function verifier({ policy, expectedPolicySha256 }, quoteVerifier, now, synthetic) {
  const approved = checkedPolicy(policy), policyHash = issuerPolicyHash(approved);
  if (!hex(expectedPolicySha256, 32) || expectedPolicySha256 !== policyHash) throw deny();
  const pending = new Map(), active = new Set();
  let closed = false, lastTime = 0;
  function time() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < lastTime) throw deny();
    lastTime = value;
    return value;
  }
  return Object.freeze({
    policySha256: policyHash,
    challenge({ remotePeer, issuerPublicKeyHex }) {
      if (closed) throw deny();
      const issued = time();
      for (const [id, c] of pending) if (c.expires <= issued) pending.delete(id);
      if (pending.size >= 256) throw deny();
      const b = binding({ version: 2, peer_id: remotePeer, public_key_hex: issuerPublicKeyHex, challenge_hex: crypto.randomBytes(32).toString("hex"), policy_sha256: policyHash });
      pending.set(b.challenge_hex, { binding: { ...b }, issued, expires: issued + approved.challenge_ttl_ms });
      return Object.freeze({ ...b });
    },
    async verify(bundle, { remotePeer }) {
      let controller;
      try {
        if (closed) throw deny();
        const evidence = checkedEvidence(bundle), b = evidence.binding, c = pending.get(b.challenge_hex), started = time();
        if (!c || c.expires <= started || active.size >= 4 || b.peer_id !== remotePeer || !jsonBytes(c.binding).equals(jsonBytes(b))) throw deny();
        // Consume before awaiting: neither replay nor concurrent use can duplicate admission.
        pending.delete(b.challenge_hex);
        const publicKey = crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(b.public_key_hex, "hex")]), format: "der", type: "spki" });
        if (!crypto.verify(null, issuerPossessionMessage(b), publicKey, Buffer.from(evidence.possession_signature_hex, "hex"))) throw deny();
        controller = new AbortController(); active.add(controller);
        const q = checkedQuote(await quoteVerifier(evidence.quote_hex, { signal: controller.signal }));
        if (closed || time() >= c.expires || q.reportData !== issuerReportData(b).toString("hex")) throw deny();
        const measured = measuredRuntime(evidence, q);
        const m = approved.approved_measurements.find((entry) => entry.compose_sha256 === measured.get("compose-hash")
          && entry.mr_td === q.mrTd && entry.rtmr0 === q.rtMr0 && entry.rtmr1 === q.rtMr1 && entry.rtmr2 === q.rtMr2
          && Object.entries(entry.runtime_events).every(([name, value]) => measured.get(name) === value));
        if (!m) throw deny();
        const finished = time();
        if (finished >= c.expires) throw deny();
        return Object.freeze({ version: 2, scope: "issuer-identity-only", evidenceStatus: synthetic ? "synthetic-only-not-hardware" : "verified-intel-tdx-identity",
          peerId: b.peer_id, issuerPublicKeyHex: b.public_key_hex, policySha256: policyHash, composeSha256: m.compose_sha256,
          verifiedAtMs: finished, expiresAtMs: c.expires, privateIssuanceQualified: false, rollbackQualified: false });
      } catch { throw deny(); }
      finally { if (controller) active.delete(controller); }
    },
    close() { closed = true; pending.clear(); for (const controller of active) controller.abort(); },
  });
}
export function createDstackIssuerVerifier(options) {
  if (!keys(options, ["policy", "expectedPolicySha256"])) throw deny();
  return verifier(options, verifyDcapQuote, Date.now, false);
}
// Explicit test boundary: synthetic adapters can never emit a hardware success label.
export function createDstackIssuerVerifierForTesting({ policy, expectedPolicySha256, syntheticQuoteVerifier, now = Date.now }) {
  if (typeof syntheticQuoteVerifier !== "function" || typeof now !== "function") throw deny();
  return verifier({ policy, expectedPolicySha256 }, syntheticQuoteVerifier, now, true);
}
