// Guest admission reads through chain-read (applications/chain-read): a Helios OP-stack light client in this process
// verifies every answer against Base's sequencer-signed head. A snapshot pins chain-read's verified head, which lags the
// newest head by its lagSeconds; every read names that block hash. Same snapshot interface as ChainReader (block, tag,
// read, call), so admissionChain runs unchanged.
import { abi, keccak256, require } from "./schema.mjs";
import { admissionChain } from "./admission.mjs";

const hex = (b) => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export class HeliosReader {
  // open() starts a chainRead instance; a failed start is retried on the next snapshot.
  constructor({ escrow, codeHash, open, maxHeadAge = 120, now = () => Date.now() / 1000 }) {
    require(/^0x[0-9a-fA-F]{40}$/.test(escrow) && /^0x[0-9a-fA-F]{64}$/.test(codeHash) && open,
      "escrow, deployed code hash and chain-read opener required");
    // Deployed code cannot change after deployment (EIP-6780), so each address's code is verified once per process.
    Object.assign(this, { escrow, codeHash, open, maxHeadAge, now, codes: new Map() });
  }
  async snapshot() {
    if (!this.chain) { this.chain = this.open(); this.chain.catch(() => { this.chain = undefined; }); }
    const c = await this.chain, s = await c.snapshot();
    const age = this.now() - s.block.timestamp;
    require(age <= this.maxHeadAge, `Helios head is ${Math.round(age)} s old`);
    const block = { hash: s.block.hash, number: s.block.number }, tag = { blockHash: block.hash };
    const fetchRead = async (method, arg) => {
      if (method === "eth_getCode") {
        const k = arg.toLowerCase();
        if (!this.codes.has(k)) { const p = c.read("eth_getCode", [arg, tag]); this.codes.set(k, p); p.catch(() => this.codes.delete(k)); }
        return this.codes.get(k);
      }
      require(method === "eth_call", "unsupported Helios read " + method);
      return hex(await s.call(arg.to, arg.data));
    };
    // State at a pinned block hash never changes, so a snapshot fetches each read once. A failed read is not kept.
    // `used` holds what callers read; warm() fetches without marking, so a refresh replays only reads still in use.
    const reads = new Map(), used = new Set();
    const read = (method, [arg]) => {
      const k = JSON.stringify([method, arg]);
      used.add(k);
      return warm(k, method, arg);
    };
    const warm = (k, method, arg) => {
      if (!reads.has(k)) {
        const p = fetchRead(method, arg);
        reads.set(k, p);
        p.catch(() => reads.delete(k));
      }
      return reads.get(k);
    };
    const code = await read("eth_getCode", [this.escrow]);
    require(code !== "0x" && keccak256(code).toLowerCase() === this.codeHash.toLowerCase(), "escrow deployed code mismatch");
    // Fetches the eth_calls among `keys` in one Multicall3 read: one Helios proof set instead of one per call.
    const warmAll = (keys) => {
      const calls = keys.filter((k) => !reads.has(k)).map((k) => [k, ...JSON.parse(k)]).filter(([, m]) => m === "eth_call");
      if (calls.length) {
        const all = s.multicall(calls.map(([, , a]) => [a.to, a.data]));
        calls.forEach(([k], i) => { const p = all.then((r) => hex(r[i])); reads.set(k, p); p.catch(() => reads.delete(k)); });
      }
      return Promise.allSettled(keys.map((k) => warm(k, ...JSON.parse(k))));
    };
    return { block, tag, read, used, warmAll,
      call: async (name, args = []) =>
        abi.decodeFunctionResult(name, await read("eth_call", [{ to: this.escrow, data: abi.encodeFunctionData(name, args) }]))[0],
    };
  }
}

// Each caller used to pin its own block (Base Sepolia makes one every 200 ms), so chain-read's per-block answers never
// hit and every eth_call paid ~5 s of Helios verification: one guest registration made ~14 reads, 30 s and more, past the
// guest egress timeout (15 s). Callers now share one snapshot for `seconds`. The next is built in the background and
// replays the reads of the one it replaces before it is served, so a steady caller never waits on a cold read. A snapshot
// is served for at most 2 * seconds after it was taken; past that, callers wait for the next one and get its error.
export function sharedSnapshots(reader, seconds = 60, now = () => Date.now() / 1000) {
  let current, next;
  const refresh = () => next ??= (async () => {
    const at = now(), s = await reader.snapshot();
    if (current) {
      require(s.block.number >= current.s.block.number, "chain-read pinned an older block than the served snapshot");
      // Reads that fail here are fetched on demand.
      await s.warmAll([...current.s.used]);
    }
    return current = { s, at };
  })().finally(() => { next = undefined; });
  return {
    snapshot: async () => {
      const age = current ? now() - current.at : Infinity;
      if (age < 2 * seconds) {
        if (age >= seconds) refresh().catch((e) => console.error("helios snapshot refresh:", e.message));
        return current.s;
      }
      return (await refresh()).s;
    },
  };
}

// The App Attest/CDRegistry/Canary interface verifyRelay takes, for unpaid relays: admissionChain (code pins included)
// over the reader's current snapshot.
export function heliosAdmission(reader, cfg) {
  return Object.fromEntries(["key", "category", "rpIdHash", "buildId", "burnedImage", "burnedBuild"]
    .map((k) => [k, async (...args) => (await admissionChain(await reader.snapshot(), cfg))[k](...args)]));
}
