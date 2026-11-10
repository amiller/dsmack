// Guest admission reads through layover-chain, which answers only what its Helios OP-stack light client verified. A
// snapshot pins one verified block hash `depth` blocks behind the head; every read names that hash. Same snapshot
// interface as ChainReader (block, tag, read, call), so admissionChain runs unchanged. Reads fail closed: a reply not
// marked helios-opstack, or pinned to another block, is an error.
import { abi, keccak256, require } from "./schema.mjs";
import { admissionChain } from "./admission.mjs";

export class HeliosReader {
  constructor({ escrow, codeHash, chainRead, depth = 30, maxHeadAge = 120 }) {
    require(/^0x[0-9a-fA-F]{40}$/.test(escrow) && /^0x[0-9a-fA-F]{64}$/.test(codeHash) && /^https:\/\//.test(chainRead),
      "escrow, deployed code hash and layover-chain URL required");
    Object.assign(this, { escrow, codeHash, base: chainRead.replace(/\/$/, ""), depth, maxHeadAge });
  }
  async get(path, params) {
    const r = await fetch(`${this.base}${path}?${new URLSearchParams(params)}`), j = await r.json();
    require(r.ok && j.verified_by === "helios-opstack", `layover-chain ${path}: HTTP ${r.status} ${j.error ?? ""}`);
    return j;
  }
  async snapshot() {
    const head = await this.get("/head", { depth: this.depth });
    require(head.head_age_s <= this.maxHeadAge, `Helios head is ${head.head_age_s} s old`);
    require(Number.isInteger(head.depth) && head.depth >= this.depth && Number.isInteger(head.block) && Number.isInteger(head.head) &&
      head.block <= head.head - this.depth, `layover-chain /head ignored depth ${this.depth}: ${JSON.stringify(head)}`);
    const block = { hash: head.block_hash, number: head.block }, tag = { blockHash: block.hash };
    const pinned = async (path, params) => {
      const j = await this.get(path, { ...params, block: block.hash });
      require(j.block_hash === block.hash, "layover-chain answered for another block");
      return j;
    };
    const fetchRead = async (method, arg) => {
      if (method === "eth_getCode") return (await pinned("/code", { address: arg })).code;
      require(method === "eth_call", "unsupported Helios read " + method);
      return (await pinned("/call", { to: arg.to, data: arg.data })).result;
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
    return { block, tag, read, used, warm: (k) => warm(k, ...JSON.parse(k)),
      call: async (name, args = []) =>
        abi.decodeFunctionResult(name, await read("eth_call", [{ to: this.escrow, data: abi.encodeFunctionData(name, args) }]))[0],
    };
  }
}

// Each caller used to pin its own block (Base Sepolia makes one every 200 ms), so layover-chain's per-block answers never
// hit and every eth_call paid ~5 s of Helios verification: one guest registration made ~14 reads, 30 s and more, past the
// guest egress timeout (15 s). Callers now share one snapshot for `seconds`. The next is built in the background and
// replays the reads of the one it replaces before it is served, so a steady caller never waits on a cold read. A snapshot
// is served for at most 2 * seconds after it was taken; past that, callers wait for the next one and get its error.
export function sharedSnapshots(reader, seconds = 30, now = () => Date.now() / 1000) {
  let current, next;
  const refresh = () => next ??= (async () => {
    const at = now(), s = await reader.snapshot();
    if (current) {
      require(s.block.number >= current.s.block.number, "layover-chain pinned an older block than the served snapshot");
      await Promise.allSettled([...current.s.used].map(s.warm));
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
