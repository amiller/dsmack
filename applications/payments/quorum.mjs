import { abi, CHAIN, keccak256, require } from "./schema.mjs";

// Every state read uses the same EIP-1898 block hash and a strict majority of
// the configured hosts, even when some hosts are unavailable.
export class Quorum {
  constructor(
    {
      rpcs,
      escrow,
      codeHash,
      now = () => Math.floor(Date.now() / 1000),
      fetcher = fetch,
      rpcIpv4 = false,
      rpcProxy,
      blockTag = "finalized",
    },
  ) {
    require(
      Array.isArray(rpcs) && rpcs.length >= 3 &&
        new Set(rpcs.map((u) => new URL(u).hostname)).size === rpcs.length,
      "at least three independent RPC hosts required",
    );
    require(
      /^0x[0-9a-fA-F]{40}$/.test(escrow) &&
        /^0x[0-9a-fA-F]{64}$/.test(codeHash),
      "escrow and deployed code hash pins required",
    );
    // "safe" (about 2 minutes behind on Base Sepolia, versus about 18 for
    // "finalized") is for testnet only; deploy-inference.py refuses it for
    // production on a mainnet chain.
    require(["finalized", "safe"].includes(blockTag), "blockTag must be finalized or safe");
    Object.assign(this, { rpcs, escrow, codeHash, now, fetcher, blockTag });
    this.threshold = Math.floor(rpcs.length / 2) + 1;
    this.client = rpcProxy
      ? Deno.createHttpClient({ proxy: { url: rpcProxy } })
      : rpcIpv4
      ? Deno.createHttpClient({ localAddress: "0.0.0.0" })
      : undefined;
  }
  async rpc(url, method, params, signal) {
    const r = await this.fetcher(url, {
      method: "POST",
      client: this.client,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(12000)])
        : AbortSignal.timeout(12000),
    });
    require(r.ok, "RPC HTTP " + r.status);
    const b = await r.json();
    require(
      !b.error && b.result !== undefined,
      "RPC " + method + " failed: " + (b.error?.message ?? "missing result"),
    );
    return b.result;
  }
  async majority(method, params, urls = this.rpcs) {
    const controller = new AbortController(), groups = new Map(), errors = [];
    return await new Promise((resolve, reject) => {
      let remaining = urls.length, done = false;
      for (const url of urls) {
        (async () => {
          try {
            const value = normalize(
              method,
              await this.rpc(url, method, params, controller.signal),
            );
            if (done) return;
            const key = JSON.stringify(value),
              group = groups.get(key) ?? { value, n: 0 };
            group.n++;
            groups.set(key, group);
            if (group.n >= this.threshold) {
              done = true;
              controller.abort();
              resolve(group.value);
            }
          } catch (e) {
            errors.push(new URL(url).hostname + ": " + e.message);
          } finally {
            remaining--;
            if (!remaining && !done) {
              done = true;
              reject(
                new Error(
                  "refused: RPC quorum disagreement/unavailable: " + method +
                    "; " + errors.join("; "),
                ),
              );
            }
          }
        })();
      }
    });
  }

  async snapshot() {
    const heads = await Promise.allSettled(this.rpcs.map(async (u) => {
      require(
        Number(BigInt(await this.rpc(u, "eth_chainId", []))) === CHAIN,
        "Base Sepolia only",
      );
      const h = await this.rpc(u, "eth_getBlockByNumber", [this.blockTag, false]);
      require(h?.hash, "missing finalized head");
      return { url: u, head: h };
    }));
    const good = heads.filter((r) => r.status === "fulfilled").map((r) =>
      r.value
    );
    require(good.length >= this.threshold, "Base Sepolia finalized RPC quorum unavailable");
    // Choose the highest height finalized by a majority of configured hosts.
    const heights = good.map((g) => BigInt(g.head.number)).sort((a, b) =>
      a > b ? -1 : a < b ? 1 : 0
    );
    const height = heights[this.threshold - 1];
    const headUrls = good.filter((g) => BigInt(g.head.number) >= height).map(
      (g) => g.url,
    );
    const urls = good.map((g) => g.url);
    const block = await this.majority("eth_getBlockByNumber", [
      "0x" + height.toString(16),
      false,
    ], headUrls);
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
    let s;
    try {
      s = await q.snapshot();
    } catch (e) {
      if (
        !/RPC quorum|finalized RPC quorum|stale\/future finalized head/.test(
          e.message,
        )
      ) throw e;
      await new Promise((resolve) => setTimeout(resolve, 10000));
      continue;
    }
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
