import { FetchRequest, JsonRpcProvider } from "../payments/schema.mjs";

const throttled = error => {
  const code = error.error?.code ?? error.info?.error?.code ?? error.code;
  return code === -32007 || code === -32005 || error.status === 429 ||
    /rate limit|request limit|too many requests|429/i.test(error.error?.message ?? error.shortMessage ?? error.message ?? "");
};

// Retry the exact RPC operation, rather than rebuilding a transaction with a
// different nonce. Mutable heads and pinned code are still read and verified.
export function syncRpcProvider(url, { sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  const request = new FetchRequest(url); request.timeout = 10000;
  const provider = new JsonRpcProvider(request, 84532, { staticNetwork: true, cacheTimeout: -1 });
  const send = provider.send.bind(provider);
  provider.send = async (method, params) => {
    for (let attempt = 0; ; attempt++) {
      try { return await send(method, params); }
      catch (error) {
        if (attempt === 2 || !throttled(error)) throw error;
        await sleep(1000 * (attempt + 1));
      }
    }
  };
  return provider;
}
