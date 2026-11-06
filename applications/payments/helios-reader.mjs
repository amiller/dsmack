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
    const read = async (method, [arg]) => {
      if (method === "eth_getCode") return (await pinned("/code", { address: arg })).code;
      require(method === "eth_call", "unsupported Helios read " + method);
      return (await pinned("/call", { to: arg.to, data: arg.data })).result;
    };
    const code = await read("eth_getCode", [this.escrow]);
    require(code !== "0x" && keccak256(code).toLowerCase() === this.codeHash.toLowerCase(), "escrow deployed code mismatch");
    return { block, tag, read,
      call: async (name, args = []) =>
        abi.decodeFunctionResult(name, await read("eth_call", [{ to: this.escrow, data: abi.encodeFunctionData(name, args) }]))[0],
    };
  }
}

// The App Attest/CDRegistry/Canary interface verifyRelay takes, for unpaid relays: admissionChain (code pins included)
// over a Helios snapshot, renewed every `seconds`.
export function heliosAdmission(reader, cfg, seconds = 30) {
  let chain, until = 0;
  const current = () => {
    if (Date.now() >= until) {
      until = Date.now() + seconds * 1000;
      chain = reader.snapshot().then((s) => admissionChain(s, cfg));
      chain.catch(() => { until = 0; });
    }
    return chain;
  };
  return Object.fromEntries(["key", "category", "rpIdHash", "buildId", "burnedImage", "burnedBuild"]
    .map((k) => [k, async (...args) => (await current())[k](...args)]));
}
