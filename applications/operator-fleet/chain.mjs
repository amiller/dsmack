import { abi, Contract, JsonRpcProvider, keccak256 } from "../payments/schema.mjs";

// Settlement events contain incremental credits. Calldata retains the guest's
// signed cumulative receipts and the broker's run binding after guests rotate.
export class Earnings {
  constructor(config) {
    this.config = config;
    this.provider = new JsonRpcProvider(config.rpc, config.chainId, { staticNetwork: true });
    this.contract = new Contract(config.escrow, abi, this.provider);
    this.nextBlock = config.deploymentBlock;
    this.events = [];
    this.purchases = new Map();
    this.transactions = new Map();
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
      progress(`Reading settled earnings · blocks ${from.toLocaleString()}–${to.toLocaleString()}`);
      const logs = await provider.getLogs({ address: config.escrow, topics: [abi.getEvent("Settled").topicHash], fromBlock: from, toBlock: to });
      const chunk = [];
      for (const log of logs) {
        const event = abi.parseLog(log), id = event.args.purchaseId.toString();
        if (!this.purchases.has(id)) this.purchases.set(id, await this.contract.getPurchase(id, { blockTag: head.number }));
        if (!this.transactions.has(log.transactionHash)) {
          const tx = await provider.getTransaction(log.transactionHash);
          const call = abi.parseTransaction({ data: tx.data, value: tx.value });
          if (call.name !== "settle") throw Error("Settlement event has unexpected transaction input");
          const block = await provider.getBlock(log.blockNumber);
          this.transactions.set(log.transactionHash, { args: call.args, timestamp: block.timestamp });
        }
        const purchase = this.purchases.get(id), tx = this.transactions.get(log.transactionHash), call = tx.args;
        const index = call[0].findIndex(r => r.purchaseId.toString() === id && r.sequence === event.args.sequence);
        if (index < 0) throw Error("Settlement event has no matching signed receipt");
        const receipt = call[0][index].toObject(), binding = call[2].toObject();
        chunk.push({
          purchaseId: id, sequence: Number(event.args.sequence), operatorCredit: event.args.operatorCredit.toString(),
          operator: purchase.operator, node: purchase.node, runId: binding.runId,
          timestamp: tx.timestamp, endedAt: Number(receipt.endedAt), used: receipt.used.toString(), finalReceipt: receipt.finalReceipt,
          transactionHash: log.transactionHash, blockNumber: log.blockNumber,
          envelope: { receipt, signature: call[1][index], nodeBinding: { binding, signature: call[3] } },
        });
      }
      this.events.push(...chunk);
      this.nextBlock = to + 1;
    }
    this.finalizedBlock = head.number;
    return this.events;
  }
}
