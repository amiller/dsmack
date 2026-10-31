import { Interface } from 'ethers';

const kms = new Interface([
  'function isAppAllowed(tuple(address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds)) view returns (bool isAllowed,string reason)',
]);
export const unauthorizedGate = () => Object.assign(new Error("The recovery service changed and isn't authorized"), { code: 'RECOVERY_NOT_AUTHORIZED' });
const unavailable = cause => Object.assign(new Error("Couldn't reach the chain to check the recovery service: retry", { cause }), { code: 'RECOVERY_CHAIN_UNAVAILABLE' });
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
const need = (ok, message) => { if (!ok) throw Error(message); };

// Only the public authorization result is cached. Each gate challenge, TDX
// signature, key binding and event replay is still verified on every request.
export function createGateAuthorization({ fetcher = fetch, now = () => Date.now() } = {}) {
  let cached;
  async function rpc(url, method, params) {
    const response = await fetcher(url, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12000),
    });
    need(response.ok, `Recovery authorization RPC HTTP ${response.status}`);
    const reply = await response.json();
    need(!reply.error && reply.result !== undefined, 'Recovery authorization RPC returned no result');
    return reply.result;
  }
  return async (bootInfo, policy) => {
    const key = JSON.stringify([policy, bootInfo]);
    if (cached?.key === key && now() - cached.at >= 0 && now() - cached.at < 30000) return cached.evidence;
    let evidence, allowed;
    try {
      const providers = policy.rpcs;
      need(policy.chainId === 8453 && /^0x[0-9a-f]{40}$/i.test(policy.kms), 'Invalid recovery authorization chain policy');
      need(providers?.length === 2 && providers.every(url => new URL(url).protocol === 'https:') &&
        new Set(providers.map(url => new URL(url).hostname)).size === 2, 'Two independent HTTPS RPC providers are required');
      const heads = await Promise.all(providers.map(async url => {
        const [chain, head] = await Promise.all([rpc(url, 'eth_chainId', []), rpc(url, 'eth_blockNumber', [])]);
        need(BigInt(chain) === 8453n && /^0x[0-9a-f]+$/i.test(head), 'RPC returned the wrong chain or invalid height');
        return BigInt(head);
      }));
      const height = heads[0] < heads[1] ? heads[0] : heads[1];
      const blockTag = '0x' + height.toString(16);
      const blocks = await Promise.all(providers.map(url => rpc(url, 'eth_getBlockByNumber', [blockTag, false])));
      need(blocks.every(b => same(b?.number, blockTag) && /^0x[0-9a-f]{64}$/i.test(b?.hash)) && same(blocks[0].hash, blocks[1].hash), 'RPC providers disagree on the recovery authorization block');
      need(blocks.every(b => Math.abs(now() / 1000 - Number(BigInt(b.timestamp))) <= 120), 'Recovery authorization block is stale');
      const data = kms.encodeFunctionData('isAppAllowed', [bootInfo]);
      const replies = await Promise.all(providers.map(url => rpc(url, 'eth_call', [{ to: policy.kms, data }, blockTag])));
      need(same(replies[0], replies[1]), 'RPC providers disagree on recovery authorization');
      [allowed] = kms.decodeFunctionResult('isAppAllowed', replies[0]);
      evidence = { chainId: 8453, appId: bootInfo.appId, kms: policy.kms, composeHash: bootInfo.composeHash,
        osImageHash: bootInfo.osImageHash, deviceId: bootInfo.deviceId, mrSystem: bootInfo.mrSystem,
        mrAggregated: bootInfo.mrAggregated, blockNumber: Number(height), blockHash: blocks[0].hash, providers,
        checkedAt: now() };
    } catch (error) { throw unavailable(error); }
    if (!allowed) throw unauthorizedGate();
    cached = { key, at: now(), evidence };
    return evidence;
  };
}
