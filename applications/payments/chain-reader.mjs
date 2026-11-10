import { abi, keccak256, require } from "./schema.mjs";
import { RpcClient } from "./rpc.mjs";

export class ChainReader {
  constructor({ escrow, codeHash, now = () => Math.floor(Date.now() / 1000), ...transport }) {
    require(/^0x[0-9a-fA-F]{40}$/.test(escrow) && /^0x[0-9a-fA-F]{64}$/.test(codeHash),
      "escrow and deployed code hash pins required");
    Object.assign(this, { escrow, codeHash, now });
    this.rpc = new RpcClient({ ...transport, now: () => now() * 1000 });
  }

  async snapshot() {
    const { block, url } = await this.rpc.withProvider(async url => {
      const block = await this.rpc.rpc(url, "eth_getBlockByNumber", ["finalized", false]);
      if (!block || !/^0x[0-9a-f]+$/i.test(block.number) || !/^0x[0-9a-f]{64}$/i.test(block.hash) ||
          !/^0x[0-9a-f]+$/i.test(block.timestamp)) throw Object.assign(Error("missing finalized head"), { readerFailure: true });
      const age = this.now() - Number(BigInt(block.timestamp));
      if (age < -30 || age > 1800) throw Object.assign(Error("stale/future finalized head"), { readerFailure: true });
      const pinned = await this.rpc.rpc(url, "eth_getBlockByNumber", [block.number, false]);
      if (pinned?.hash?.toLowerCase() !== block.hash.toLowerCase() || BigInt(pinned.number) !== BigInt(block.number)) {
        throw Object.assign(Error("snapshot block changed"), { readerFailure: true });
      }
      return { block, url };
    });
    const tag = { blockHash: block.hash, requireCanonical: true }, checked = new Set([url]);
    const read = (method, params) => this.rpc.withProvider(async url => {
      if (!checked.has(url)) {
        const header = await this.rpc.rpc(url, "eth_getBlockByNumber", [block.number, false]);
        if (header?.hash?.toLowerCase() !== block.hash.toLowerCase() || BigInt(header.number) !== BigInt(block.number)) {
          throw Object.assign(Error("snapshot block changed"), { readerFailure: true });
        }
        checked.add(url);
      }
      return this.rpc.rpc(url, method, params);
    });
    const code = await read("eth_getCode", [this.escrow, tag]);
    require(code !== "0x" && keccak256(code).toLowerCase() === this.codeHash.toLowerCase(),
      "escrow deployed code mismatch");
    return { block, tag, read,
      call: async (name, args = []) => {
        const raw = await read("eth_call", [{ to: this.escrow, data: abi.encodeFunctionData(name, args) }, tag]);
        return abi.decodeFunctionResult(name, raw)[0];
      },
    };
  }
}

// A mined transaction is provisional until the reader finalizes its block.
export async function confirmedTransactions(cfg, hashes) {
  const q = new ChainReader(cfg), deadline = Date.now() + 3600000;
  while (Date.now() < deadline) {
    let s;
    try {
      s = await q.snapshot();
    } catch (e) {
      if (
        !/RPC unavailable|stale\/future finalized head/.test(
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
