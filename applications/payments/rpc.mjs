// Ordered Base Sepolia transport. Quota failures cool down only that provider.
export class RpcClient {
  constructor({ rpcs, fetcher = fetch, now = Date.now, rpcIpv4 = false, rpcProxy = undefined }) {
    if (!Array.isArray(rpcs) || !rpcs.length) throw Error("RPC URLs required");
    this.rpcs = [...new Set(rpcs)];
    this.fetcher = fetcher;
    this.now = now;
    this.states = new Map(this.rpcs.map(url => [url, { verified: false, strikes: 0, until: 0 }]));
    this.client = rpcProxy ? Deno.createHttpClient({ proxy: { url: rpcProxy } })
      : rpcIpv4 ? Deno.createHttpClient({ localAddress: "0.0.0.0" }) : undefined;
  }

  async rpc(url, method, params) {
    const response = await this.fetcher(url, {
      method: "POST", client: this.client, redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(12000),
    });
    if (!response.ok) {
      const retry = response.headers.get("retry-after");
      const delay = retry === null ? 0 : /^\d+$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry) - this.now();
      await response.body?.cancel();
      throw Object.assign(Error("RPC HTTP " + response.status), { status: response.status, delay });
    }
    const body = await response.json();
    if (body.error || body.result === undefined) {
      const error = body.error ?? { message: "missing result" };
      throw Object.assign(Error("RPC " + method + " failed: " + error.message), {
        throttled: [-32005, -32007].includes(error.code) || /rate limit|request limit|too many requests|429/i.test(error.message),
        reverted: error.code === 3 || /revert/i.test(error.message),
      });
    }
    return body.result;
  }

  async withProvider(operation) {
    const errors = [];
    for (const url of this.rpcs) {
      const state = this.states.get(url), host = new URL(url).hostname;
      if (state.until > this.now()) { errors.push(host + ": cooling down"); continue; }
      try {
        if (!state.verified) {
          if (BigInt(await this.rpc(url, "eth_chainId", [])) !== 84532n) throw Error("Base Sepolia only");
          state.verified = true;
        }
        const value = await operation(url);
        state.strikes = 0;
        return value;
      } catch (error) {
        if (error.reverted) throw error;
        if (error.status === 429 || error.throttled) {
          state.until = this.now() + Math.max(Math.min(1000 * 2 ** state.strikes++, 60000), error.delay || 0);
        }
        // Do not reflect keyed URLs or signed transaction bytes in diagnostics.
        errors.push(host + ": " + (error.readerFailure ? error.message : error.status ? "RPC HTTP " + error.status : error.name));
      }
    }
    throw Error("RPC unavailable (Base Sepolia): " + errors.join("; "));
  }

  request(method, params) { return this.withProvider(url => this.rpc(url, method, params)); }
}
