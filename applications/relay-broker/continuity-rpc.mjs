import { JsonRpcProvider, RPCS } from "../payments/schema.mjs";
import { RpcClient } from "../payments/rpc.mjs";

// Ethers signs once; transport failover submits the same signed bytes.
export function syncRpcProvider(urls, options = {}) {
  const rpcs = Array.isArray(urls) ? urls : [urls, ...RPCS];
  const rpc = new RpcClient({ rpcs, ...options });
  const provider = new JsonRpcProvider(rpcs[0], 84532, {
    staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1,
  });
  provider.send = (method, params) => rpc.request(method, params);
  return provider;
}
