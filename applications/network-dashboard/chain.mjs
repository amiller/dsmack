// Event signatures from contracts/src/UsageEscrow.sol. No wallet or RPC SDK needed.
export const SETTLED = "0x1b3f224ef2a1b57782971721ce2f7905bfd55454b3e4773dca698e24fcafae89";
export const PURCHASE = "0x29d5f0dddf6e52c4eafcb22aaa55ecd23d0d4228163dbd769212d9d21b6da403";
const hex = n => "0x" + n.toString(16);
const number = v => { const n = Number(BigInt(v)); if (!Number.isSafeInteger(n) || n < 0) throw Error("Invalid chain integer"); return n; };
const word = (data, at) => BigInt("0x" + data.slice(2 + at * 64, 66 + at * 64));
export function decodeEvent(log) {
  const topic = log.topics?.[0]?.toLowerCase();
  if (log.removed || !/^0x[0-9a-f]{64}$/i.test(log.topics?.[1] || "") || !/^0x(?:[0-9a-f]{64})+$/i.test(log.data || "")) throw Error("Invalid escrow event");
  const base = { id: BigInt(log.topics[1]).toString(), block: number(log.blockNumber), index: number(log.logIndex), transactionHash: log.transactionHash };
  if (topic === PURCHASE && log.data.length === 322 && log.topics.length === 4) {
    const unit = Number(word(log.data, 1));
    if (unit !== 0 && unit !== 1) throw Error("Invalid purchase unit");
    return { ...base, kind: "purchase", unit };
  }
  if (topic === SETTLED && log.data.length === 322 && log.topics.length === 2) {
    const final = word(log.data, 4);
    if (final > 1n) throw Error("Invalid settlement final flag");
    return { ...base, kind: "settled", sequence: word(log.data, 0), used: word(log.data, 1), final: final === 1n };
  }
  throw Error("Unexpected escrow event shape");
}
function logKey(log) {
  return [log.address.toLowerCase(), log.blockHash.toLowerCase(), number(log.blockNumber), log.transactionHash.toLowerCase(), number(log.transactionIndex), number(log.logIndex), log.topics.map(t => t.toLowerCase()), log.data.toLowerCase(), Boolean(log.removed)];
}
export function matchingLogs(a, b) {
  const normalize = logs => logs.map(logKey).sort((x, y) => x[2] - y[2] || x[5] - y[5]);
  if (JSON.stringify(normalize(a)) !== JSON.stringify(normalize(b))) throw Error("Public RPCs disagree on escrow settlements. Totals withheld.");
  return a;
}
export function totals(events, now) {
  const units = new Map(), used = new Map();
  const windows = [86400, 7 * 86400].map(seconds => ({ seconds, guestSeconds: 0n, jobs: new Set() }));
  for (const event of [...events].sort((a, b) => a.block - b.block || a.index - b.index)) {
    if (event.kind === "purchase") { units.set(event.id, event.unit); continue; }
    if (!units.has(event.id)) throw Error("Settlement has no matching purchase");
    const previous = used.get(event.id) || 0n;
    if (event.used < previous) throw Error("Escrow cumulative usage decreased");
    used.set(event.id, event.used);
    if (units.get(event.id) !== 1) continue;
    for (const window of windows) if (event.timestamp >= now - window.seconds && event.timestamp <= now) {
      window.guestSeconds += event.used - previous;
      if (event.final) window.jobs.add(event.id);
    }
  }
  return windows.map(({ seconds, guestSeconds, jobs }) => ({ seconds, guestSeconds: guestSeconds.toString(), jobs: jobs.size }));
}
export class NetworkChain {
  constructor(config, rpc) {
    this.config = config; this.events = []; this.nextBlock = config.deploymentBlock; this.headers = new Map();
    this.rpc = rpc || (async (url, method, params) => {
      const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(25000) });
      if (!response.ok) throw Error(`Public chain RPC returned HTTP ${response.status}`);
      const value = await response.json();
      if (value.error || !("result" in value)) throw Error(value.error?.message || "Invalid public chain RPC reply");
      return value.result;
    });
  }
  async pair(method, params) { return Promise.all(this.config.rpcs.map(url => this.rpc(url, method, params))); }
  async header(block) {
    if (this.headers.has(block)) return this.headers.get(block);
    const [a, b] = await this.pair("eth_getBlockByNumber", [hex(block), false]);
    if (!a || !b || a.hash?.toLowerCase() !== b.hash?.toLowerCase() || a.timestamp !== b.timestamp || number(a.number) !== block || number(b.number) !== block) throw Error("Public RPCs disagree on the settlement block");
    this.headers.set(block, a); return a;
  }
  async logs(from, to) {
    try {
      const pair = await this.pair("eth_getLogs", [{ address: this.config.escrow, fromBlock: hex(from), toBlock: hex(to), topics: [[PURCHASE, SETTLED]] }]);
      return matchingLogs(...pair);
    } catch (error) {
      if (to - from < 1000 || /disagree/.test(error.message)) throw error;
      const mid = Math.floor((from + to) / 2);
      return [...await this.logs(from, mid), ...await this.logs(mid + 1, to)];
    }
  }
  async read(progress = () => {}, now = Math.floor(Date.now() / 1000)) {
    if (this.config.rpcs.length !== 2 || new URL(this.config.rpcs[0]).hostname === new URL(this.config.rpcs[1]).hostname) throw Error("Two independent public RPCs are required");
    const chains = await this.pair("eth_chainId", []);
    if (chains.some(chain => number(chain) !== this.config.chainId)) throw Error("Public RPC returned the wrong chain");
    const finalized = await this.pair("eth_getBlockByNumber", ["finalized", false]);
    if (finalized.some(block => !block)) throw Error("Public RPC has no finalized block");
    const head = Math.min(...finalized.map(block => number(block.number)));
    if (this.lastHead !== undefined && head < this.lastHead) throw Error("Public RPC finalized head regressed. Totals withheld.");
    this.headers.delete(head);
    const header = await this.header(head);
    if (now - number(header.timestamp) > 1800 || number(header.timestamp) > now + 60) throw Error("Finalized chain data is stale");
    if (!this.checked) {
      const code = await this.pair("eth_getCode", [this.config.escrow, hex(head)]);
      if (code[0] === "0x" || code[0] !== code[1]) throw Error("Public RPCs disagree on the UsageEscrow contract");
      this.checked = true;
    }
    for (let from = this.nextBlock; from <= head; from += 40000) {
      const to = Math.min(from + 39999, head);
      progress(`Cross-checking Base Sepolia · blocks ${from.toLocaleString()}–${to.toLocaleString()}`);
      const logs = await this.logs(from, to), chunk = [];
      const blocks = [...new Set(logs.filter(log => log.topics?.[0]?.toLowerCase() === SETTLED).map(log => number(log.blockNumber)))];
      for (let i = 0; i < blocks.length; i += 4) await Promise.all(blocks.slice(i, i + 4).map(block => this.header(block)));
      for (const log of logs) {
        const event = decodeEvent(log);
        if (event.kind === "settled") event.timestamp = number((await this.header(event.block)).timestamp);
        chunk.push(event);
      }
      this.events.push(...chunk); this.nextBlock = to + 1;
    }
    const windows = totals(this.events, now);
    this.lastHead = head;
    return { windows, block: head, blockHash: header.hash, finalizedAt: number(header.timestamp), timestamp: now, providers: [...this.config.rpcs], escrow: this.config.escrow };
  }
}
