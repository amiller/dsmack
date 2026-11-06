import { abi, JsonRpcProvider, keccak256 } from "../payments/schema.mjs";

// Each Claimed event advances one user/operator cumulative USDC total.
export class Earnings {
  constructor(config) {
    this.config = config;
    this.provider = new JsonRpcProvider(config.rpc, config.chainId, { staticNetwork: true });
    this.nextBlock = config.deploymentBlock;
    this.events = [];
    this.cumulative = new Map();
  }
  async read(progress = () => {}) {
    const { provider, config } = this;
    if (!this.checked) {
      const chain = await provider.send("eth_chainId", []);
      if (Number(chain) !== config.chainId) throw Error("RPC returned the wrong chain");
      if (keccak256(await provider.getCode(config.escrow)) !== config.codeHash) throw Error("Escrow code does not match the published pin");
      this.checked = true;
    }
    const head = await provider.getBlock("finalized");
    for (let from = this.nextBlock; from <= head.number; from += 40000) {
      const to = Math.min(from + 39999, head.number);
      progress(`Reading USDC payouts · blocks ${from.toLocaleString()}–${to.toLocaleString()}`);
      const logs = await provider.getLogs({ address: config.escrow, topics: [abi.getEvent("Claimed").topicHash], fromBlock: from, toBlock: to });
      const chunk = [], totals = new Map(this.cumulative);
      for (const log of logs) {
        const event = abi.parseLog(log), user = event.args.user, operator = event.args.operator;
        const key = user.toLowerCase() + ":" + operator.toLowerCase();
        const cumulative = BigInt(event.args.cumulativeOwed), previous = totals.get(key) ?? 0n;
        if (cumulative <= previous) throw Error("Claim total did not advance");
        const block = await provider.getBlock(log.blockNumber);
        chunk.push({ user, operator, operatorCredit: String(cumulative - previous),
          cumulativeOwed: String(cumulative), period: Number(event.args.period), timestamp: block.timestamp,
          transactionHash: log.transactionHash, blockNumber: log.blockNumber });
        totals.set(key, cumulative);
      }
      this.events.push(...chunk);
      this.cumulative = totals;
      this.nextBlock = to + 1;
    }
    this.finalizedBlock = head.number;
    return this.events;
  }
}
