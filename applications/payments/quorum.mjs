import { abi, CHAIN, keccak256, require, RPCS } from "./schema.mjs";

// Every state read uses the same EIP-1898 block hash, with an honest 2/3 majority.
export class Quorum {
  constructor(
    {
      rpcs = RPCS,
      escrow,
      codeHash,
      now = () => Math.floor(Date.now() / 1000),
      fetcher = fetch,
    },
  ) {
    require(
      rpcs.length === 3 &&
        new Set(rpcs.map((u) => new URL(u).hostname)).size === 3,
      "three independent RPC hosts required",
    );
    require(
      /^0x[0-9a-fA-F]{40}$/.test(escrow) &&
        /^0x[0-9a-fA-F]{64}$/.test(codeHash),
      "escrow and deployed code hash pins required",
    );
    Object.assign(this, { rpcs, escrow, codeHash, now, fetcher });
  }
  async rpc(url, method, params) {
    const r = await this.fetcher(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(12000),
    });
    require(r.ok, "RPC HTTP " + r.status);
    const b = await r.json();
    require(!b.error && b.result !== undefined, "RPC " + method + " failed");
    return b.result;
  }
  async majority(method, params, urls = this.rpcs) {
    const replies = await Promise.allSettled(
      urls.map(async (u) =>
        normalize(method, await this.rpc(u, method, params))
      ),
    );
    const groups = new Map();
    for (const r of replies) {
      if (r.status === "fulfilled") {
        const value = r.value;
        const key = JSON.stringify(value);
        const g = groups.get(key) ?? { value, n: 0 };
        g.n++;
        groups.set(key, g);
      }
    }
    const winner = [...groups.values()].find((g) => g.n >= 2);
    require(winner, "RPC quorum disagreement/unavailable: " + method);
    return winner.value;
  }
  async snapshot() {
    const heads = await Promise.allSettled(this.rpcs.map(async (u) => {
      require(
        Number(BigInt(await this.rpc(u, "eth_chainId", []))) === CHAIN,
        "Base Sepolia only",
      );
      const h = await this.rpc(u, "eth_getBlockByNumber", ["finalized", false]);
      require(h?.hash, "missing finalized head");
      return { url: u, head: h };
    }));
    const good = heads.filter((r) => r.status === "fulfilled").map((r) =>
      r.value
    );
    require(good.length >= 2, "Base Sepolia finalized RPC quorum unavailable");
    // Common height is never above any participating provider's finalized head.
    const height = good.reduce(
      (n, g) => BigInt(g.head.number) < n ? BigInt(g.head.number) : n,
      BigInt(good[0].head.number),
    );
    const urls = good.map((g) => g.url);
    const block = await this.majority("eth_getBlockByNumber", [
      "0x" + height.toString(16),
      false,
    ], urls);
    require(
      BigInt(block.number) === height &&
        this.now() - Number(BigInt(block.timestamp)) <= 1800 &&
        Number(BigInt(block.timestamp)) <= this.now() + 30,
      "stale/future finalized head",
    );
    const tag = { blockHash: block.hash, requireCanonical: true };
    const read = (method, params) => this.majority(method, params, urls);
    const code = await read("eth_getCode", [this.escrow, tag]);
    require(
      code !== "0x" &&
        keccak256(code).toLowerCase() === this.codeHash.toLowerCase(),
      "escrow deployed code mismatch",
    );
    return {
      block,
      tag,
      read,
      call: async (name, args = []) => {
        const raw = await read("eth_call", [{
          to: this.escrow,
          data: abi.encodeFunctionData(name, args),
        }, tag]);
        return abi.decodeFunctionResult(name, raw)[0];
      },
    };
  }
  async purchase(s, id, txHash) {
    require(
      /^[1-9][0-9]*$/.test(id) && /^0x[0-9a-fA-F]{64}$/.test(txHash),
      "purchase ID and transaction required",
    );
    const tx = await s.read("eth_getTransactionReceipt", [txHash]);
    require(
      tx && tx.status === "0x1" &&
        BigInt(tx.blockNumber) <= BigInt(s.block.number),
      "purchase not finalized",
    );
    const block = await s.read("eth_getBlockByNumber", [tx.blockNumber, false]);
    require(block.hash === tx.blockHash, "purchase block is not canonical");
    const event = tx.logs.filter((l) =>
      l.address.toLowerCase() === this.escrow.toLowerCase()
    ).map((l) => {
      try {
        return abi.parseLog(l);
      } catch {
        return null;
      }
    }).find((e) =>
      e?.name === "Purchase" && e.args.purchaseId.toString() === id
    );
    require(event, "confirmed Purchase event required");
    const p = await s.call("getPurchase", [id]);
    for (
      const field of [
        "node",
        "payer",
        "buyerKey",
        "unit",
        "amount",
        "price",
        "expires",
      ]
    ) {
      require(
        String(p[field]).toLowerCase() ===
          String(event.args[field]).toLowerCase(),
        "Purchase event/state mismatch: " + field,
      );
    }
    require(!p.closed, "purchase closed");
    return p;
  }
}

// Providers add transport-specific metadata (for example L1 fee extensions).
// Compare only consensus fields consumed by this reader, with fixed key order.
function normalize(method, value) {
  if (value === null) return null;
  const pick = (v, keys) => Object.fromEntries(keys.map((k) => [k, v[k]]));
  if (method === "eth_getBlockByNumber") {
    return pick(value, [
      "number",
      "hash",
      "parentHash",
      "stateRoot",
      "timestamp",
    ]);
  }
  if (method === "eth_getTransactionReceipt") {
    return {
      ...pick(value, ["transactionHash", "blockHash", "blockNumber", "status"]),
      logs: value.logs.map((l) =>
        pick(l, [
          "address",
          "topics",
          "data",
          "logIndex",
          "blockHash",
          "blockNumber",
          "transactionHash",
          "removed",
        ])
      ),
    };
  }
  return value;
}

// A mined transaction is provisional until the same quorum finalizes its block.
export async function confirmedTransactions(cfg, hashes) {
  const q = new Quorum(cfg), deadline = Date.now() + 3600000;
  while (Date.now() < deadline) {
    const s = await q.snapshot();
    let complete = true;
    for (const hash of hashes) {
      const tx = await s.read("eth_getTransactionReceipt", [hash]);
      if (!tx || BigInt(tx.blockNumber) > BigInt(s.block.number)) {
        complete = false;
        break;
      }
      require(tx.status === "0x1", "transaction reverted");
      const block = await s.read("eth_getBlockByNumber", [
        tx.blockNumber,
        false,
      ]);
      require(block.hash === tx.blockHash, "transaction block changed");
    }
    if (complete) return s;
    await new Promise((resolve) => setTimeout(resolve, 10000));
  }
  throw new Error(
    "transaction finality timeout; preserve buyer state and inspect its saved hashes",
  );
}
