// Base reads verified by a Helios OP-stack light client against the sequencer-signed head. Execution RPCs, wallets and
// head relays are untrusted: a wrong answer fails Helios verification and the read moves on to the next source.
import { createHeliosProvider } from "./vendor/helios-0.12.0.mjs";

export const READS = new Set(["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getCode",
  "eth_getProof", "eth_createAccessList", "eth_call"]);
export const PUBLIC_RPCS = { "base-sepolia": ["https://sepolia.base.org"], base: ["https://mainnet.base.org"] };
const CHAIN_IDS = { "base-sepolia": "0x14a34", base: "0x2105" };
const MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11";
const networks = new Set();
let instances = 0;

const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.slice(2).match(/../g) ?? [], (x) => parseInt(x, 16));
const word = (n) => n.toString(16).padStart(64, "0");

export function aggregate3(calls) {
  const tuples = calls.map(([to, data]) => {
    const d = data.slice(2);
    return to.slice(2).toLowerCase().padStart(64, "0") + word(0) + word(0x60) + word(d.length / 2) + d.padEnd(Math.ceil(d.length / 64) * 64, "0");
  });
  let off = 32 * calls.length;
  const heads = tuples.map((t) => { const h = word(off); off += t.length / 2; return h; });
  return "0x82ad56cb" + word(0x20) + word(calls.length) + heads.join("") + tuples.join("");
}

export function decodeAggregate3(result) {
  const b = unhex(result), u = (i) => Number(BigInt("0x" + hexOf(b.subarray(i, i + 32))));
  const start = u(0) + 32;
  return Array.from({ length: u(start - 32) }, (_, k) => {
    const t = start + u(start + 32 * k), d = t + u(t + 32);
    return b.slice(d + 32, d + 32 + u(d));
  });
}

const timed = (p, ms, what) => {
  let t;
  return Promise.race([p, new Promise((_, no) => t = setTimeout(() => no(new Error(`${what}: no answer in ${ms} ms`)), ms))]).finally(() => clearTimeout(t));
};
const jsonResponse = (body, url) => {
  const r = new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  Object.defineProperty(r, "url", { value: url });
  return r;
};

// sources: [{ url } | { provider }] tried in order per read; relays: base URLs serving GET /latest, tried in order per poll.
// With no arguments a page uses its own Worker at `worker`, then the public RPCs, then an injected wallet on the right chain.
export async function chainRead({ network = "base-sepolia", worker = "/chain-read", relays, sources, wallet = globalThis.ethereum,
  lagSeconds = 6, timeoutMs = 10000, helios = createHeliosProvider } = {}) {
  if (networks.has(network)) throw new Error(`chainRead for ${network} already running`);
  const origin = globalThis.location?.origin, consensus = `https://${network}.operationsolarstorm.org`;
  relays ??= [...(origin ? [origin + worker] : []), consensus];
  sources ??= [...(origin ? [{ name: "worker", url: origin + worker + "/rpc" }] : []), ...PUBLIC_RPCS[network].map((url) => ({ url })),
    ...(wallet ? [{ name: "wallet", provider: wallet }] : [])];
  const diagnostics = { reads: [], relays: {}, skipped: [], background: [] };
  const usable = [], prev = globalThis.fetch;
  for (const s of sources.map((s) => ({ name: s.url ?? "provider", ...s }))) {
    if (!s.provider) { usable.push(s); continue; }
    try {
      const id = await timed(s.provider.request({ method: "eth_chainId" }), timeoutMs, s.name);
      if (BigInt(id) === BigInt(CHAIN_IDS[network])) usable.push(s);
      else diagnostics.skipped.push({ source: s.name, reason: `on chain ${BigInt(id)}, not ${network}` });
    } catch (e) { diagnostics.skipped.push({ source: s.name, reason: String(e.message ?? e) }); }
  }
  if (!usable.length) throw new Error("no usable source: " + JSON.stringify(diagnostics.skipped));

  const send = async (s, body) => {
    if (s.url) return prev(s.url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(timeoutMs) });
    const one = async ({ id, method, params }) => {
      if (!READS.has(method)) return { jsonrpc: "2.0", id, error: { code: -32601, message: `${method} is not a read` } };
      return timed(s.provider.request({ method, params }), timeoutMs, `${s.name} ${method}`)
        .then((result) => ({ jsonrpc: "2.0", id, result }), (e) => ({ jsonrpc: "2.0", id, error: { code: e.code ?? -32603, message: String(e.message ?? e) } }));
    };
    const req = JSON.parse(body);
    return jsonResponse(Array.isArray(req) ? await Promise.all(req.map(one)) : await one(req), "https://eip1193.invalid/");
  };

  // Hand Helios the newest head that is at least lagSeconds old, so the execution RPCs already have its state.
  const heads = [];
  const latest = async (path) => {
    let body;
    for (const r of relays) {
      const d = diagnostics.relays[r] ??= { ok: 0, failed: 0 };
      try {
        const res = await prev(r.replace(/\/$/, "") + path, { signal: AbortSignal.timeout(timeoutMs) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        body = await res.text();
        d.ok++;
        break;
      } catch (e) { d.failed++; d.error = String(e.message ?? e); }
    }
    if (body === undefined) throw new Error("every relay failed: " + JSON.stringify(diagnostics.relays));
    const now = Date.now();
    if (heads.at(-1)?.body !== body) heads.push({ at: now, body });
    while (heads.length > 1 && heads[1].at <= now - lagSeconds * 1000) heads.shift();
    const wait = heads[0].at + lagSeconds * 1000 - now;
    if (wait > 0) await new Promise((ok) => setTimeout(ok, wait));
    return jsonResponse(JSON.parse(heads[0].body), consensus + path);
  };

  // Helios takes only a URL for execution and hardcodes its consensus host, so both are fetches this wrapper answers.
  const exec = `https://exec-${++instances}.chain-read.invalid/`;
  let active, used;
  const wrapped = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.startsWith(consensus + "/")) return latest(url.slice(consensus.length));
    if (!url.startsWith(exec)) return prev(input, init);
    const body = input instanceof Request ? await input.text() : init.body;
    if (active) { used = true; return send(active, body); }
    diagnostics.background.push({ at: Date.now(), body: body.slice(0, 200) });
    return send(usable[0], body);
  };
  // Helios polls a dead relay forever and cannot be shut down mid-sync, so take the first head before starting it.
  await latest("/latest");
  globalThis.fetch = wrapped;
  networks.add(network);

  const p = await helios({ executionRpc: exec, network, dbType: "config" }, "opstack");
  const close = async () => {
    await p.shutdown();
    if (globalThis.fetch === wrapped) globalThis.fetch = prev;
    networks.delete(network);
  };
  await p.waitSynced();

  // Reads run one at a time so the wrapper knows which source the current read uses.
  let queue = Promise.resolve();
  const read = (method, params) => {
    const run = async () => {
      const failures = [], t = Date.now();
      for (const s of usable) {
        active = s, used = false;
        try {
          const result = await p.request({ method, params });
          // Some reads (the head block) Helios answers from its verified head without asking a source.
          diagnostics.reads.push({ method, source: used ? s.name : "helios", failures, ms: Date.now() - t });
          return result;
        } catch (e) { failures.push({ source: s.name, error: String(e.message ?? e) }); }
        finally { active = undefined; diagnostics.reads.splice(0, diagnostics.reads.length - 100); }
      }
      diagnostics.reads.push({ method, source: null, failures, ms: Date.now() - t });
      throw Object.assign(new Error(`${method} failed on every source: ` + failures.map((f) => `${f.source}: ${f.error}`).join("; ")), { failures });
    };
    const r = queue.then(run);
    queue = r.then(() => {}, () => {});
    return r;
  };

  const cache = new Map();
  const snapshot = async () => {
    const b = await read("eth_getBlockByNumber", ["latest", false]);
    const block = { number: Number(b.number), hash: b.hash, timestamp: Number(b.timestamp) }, tag = { blockHash: b.hash };
    if (!cache.has(b.hash)) cache.set(b.hash, new Map());
    if (cache.size > 8) cache.delete(cache.keys().next().value);
    const reads = cache.get(b.hash), key = (to, data) => (to + data).toLowerCase();
    const remember = (k, p) => { reads.set(k, p); p.catch(() => reads.delete(k)); return p; };
    const call = (to, data) => reads.get(key(to, data)) ?? remember(key(to, data), read("eth_call", [{ to, data }, tag]).then(unhex));
    const multicall = async (calls) => {
      const miss = calls.filter(([to, data]) => !reads.has(key(to, data)));
      if (miss.length) {
        const all = read("eth_call", [{ to: MULTICALL3, data: aggregate3(miss) }, tag]).then(decodeAggregate3);
        miss.forEach(([to, data], i) => remember(key(to, data), all.then((r) => r[i])));
      }
      return Promise.all(calls.map(([to, data]) => reads.get(key(to, data))));
    };
    return { block, call, multicall };
  };

  return { snapshot, read, diagnostics, sources: usable.map((s) => s.name), close };
}
