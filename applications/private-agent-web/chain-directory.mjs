import { Interface, keccak256, verifyMessage } from "npm:ethers@6.17.0";
import { readWithRetry, pause } from "./network-read.mjs";
import { address, tunnel } from "../browser-p2p/tunnels.mjs";

const index = new Interface(["function owner() view returns (address)", "function entries() view returns (string)"]);
const escrow = new Interface([
  "function brokerSigner() view returns (address)",
  "function getNode(bytes32) view returns (tuple(address operator,uint8 unit,bytes32 composeHash,bytes32 imageHash))",
]);
const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
const need = (ok, message) => { if (!ok) throw Error("Chain directory: " + message); };

async function rpc(url, method, params, signal, fetcher) {
  return readWithRetry(async () => {
    const response = await fetcher(url, {
      method: "POST", headers: { "content-type": "application/json" }, redirect: "error",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(12000)]) : AbortSignal.timeout(12000),
    });
    need(response.ok, `${new URL(url).hostname} could not read ${method} (HTTP ${response.status}).`);
    const text = await response.text();
    need(text.length <= 1 << 20, "RPC response is too large.");
    const reply = JSON.parse(text);
    need(!reply.error && reply.result !== undefined, `${new URL(url).hostname} could not read ${method}: ${reply.error?.message || "missing result"}.`);
    return reply.result;
  }, signal);
}

async function agreed(snapshot, method, params, signal, fetcher) {
  const controller = new AbortController(), groups = new Map();
  const readSignal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  return new Promise((resolve, reject) => {
    let remaining = snapshot.providers.length;
    const errors = [];
    for (const url of snapshot.providers) {
      (async () => {
        try {
          await snapshot.checkProvider(url);
          const value = await rpc(url, method, params, readSignal, fetcher);
          const key = canonical(value), count = (groups.get(key) || 0) + 1;
          groups.set(key, count);
          if (count === 2) { resolve(value); controller.abort(); }
        } catch (error) { errors.push(`${new URL(url).hostname}: ${error.message}`); }
        finally {
          if (--remaining === 0) reject(Error(`Chain directory: RPC providers disagree or are unavailable on ${method} at block ${snapshot.blockNumber}; ${errors.join("; ")}`));
        }
      })();
    }
  });
}

async function call(snapshot, to, abi, method, args, signal, fetcher) {
  const raw = await agreed(snapshot, "eth_call", [{ to, data: abi.encodeFunctionData(method, args) }, snapshot.blockTag], signal, fetcher);
  return abi.decodeFunctionResult(method, raw);
}

export function signedTunnelNodes(value, publisher, now = Math.floor(Date.now() / 1000)) {
  const envelopes = Array.isArray(value) ? value : [value];
  need(envelopes.length > 0 && envelopes.length <= 32, "TunnelIndex has no signed guest entries.");
  const nodes = new Map();
  for (const envelope of envelopes) {
    need(envelope && !Array.isArray(envelope) && typeof envelope.signature === "string" && Array.isArray(envelope.entries),
      "TunnelIndex contains unsigned entries; the Mac must publish signed dsmack-tunnels/1 guest entries.");
    const { signature, ...unsigned } = envelope;
    need(same(unsigned.publisher, publisher), "tunnel publisher differs from the pinned Mac publisher.");
    let signer;
    try { signer = verifyMessage("dsmack-tunnels/1\n" + canonical(unsigned), signature); }
    catch { throw Error("Chain directory: tunnel publisher signature is invalid."); }
    need(same(signer, publisher), "tunnel publisher signature is invalid.");
    need(Number.isSafeInteger(unsigned.expiresAt) && unsigned.expiresAt <= now + 3600,
      "signed tunnel publication has an invalid expiry.");
    if (unsigned.expiresAt <= now) throw Object.assign(Error("Chain directory: signed tunnel publication has expired."), { code: "PUBLICATION_EXPIRED" });
    need(envelope.entries.length <= 32, "too many tunnel entries.");
    for (const value of envelope.entries) {
      const entry = tunnel(value);
      need(entry.expiresAt <= unsigned.expiresAt && entry.expiresAt <= now + 3600, "guest tunnel expiry exceeds its signed publication.");
      if (entry.expiresAt <= now) continue;
      need(entry.guestPeer, "signed tunnel publication has no guest PeerId.");
      const node = nodes.get(entry.guestPeer) || { kind: "compute", relay_peer: entry.guestPeer, directory: "chain", tunnels: [] };
      if (!node.tunnels.some(prior => address(prior) === address(entry))) node.tunnels.push(entry);
      nodes.set(entry.guestPeer, node);
    }
  }
  need(nodes.size > 0, "TunnelIndex has no unexpired signed guest entries.");
  return [...nodes.values()];
}

export async function discoverChainNodes({ config, signal, fetcher = fetch, now } = {}) {
  const settings = config.chainDirectory;
  need(settings?.registry && settings.publisher, "the TunnelIndex and Mac publisher are not configured.");
  const providers = settings.rpcs;
  need(Array.isArray(providers) && [2, 3].includes(providers.length) && new Set(providers.map(url => new URL(url).hostname)).size === providers.length && providers.every(url => new URL(url).protocol === "https:"),
    "two or three independent HTTPS RPC providers are required.");
  need(config.chainId === 84532, "Base Sepolia is required.");
  const heads = providers.map(async url => {
    const [chain, height] = await Promise.all([rpc(url, "eth_chainId", [], signal, fetcher), rpc(url, "eth_blockNumber", [], signal, fetcher)]);
    need(Number(chain) === 84532, `${new URL(url).hostname} returned the wrong chain.`);
    need(/^0x[0-9a-f]+$/i.test(height), "RPC returned an invalid block height.");
    return BigInt(height);
  });
  // Each pair reads one common height. The first agreeing pair wins, without
  // waiting for the third provider's head or block request.
  const pairs = (providers.length === 2 ? [[0, 1]] : [[0, 1], [0, 2], [1, 2]]).map(async ([a, b]) => {
    const heights = await Promise.all([heads[a], heads[b]]);
    const height = heights[0] < heights[1] ? heights[0] : heights[1];
    const tag = "0x" + height.toString(16);
    const headers = await Promise.all([a, b].map(i => rpc(providers[i], "eth_getBlockByNumber", [tag, false], signal, fetcher)));
    need(headers.every(header => header?.number === tag && /^0x[0-9a-f]{64}$/i.test(header.hash)) && same(headers[0].hash, headers[1].hash),
      "RPC providers disagree on the directory block.");
    return { blockNumber: Number(height), blockHash: headers[0].hash };
  });
  let block;
  try { block = await Promise.any(pairs); }
  catch (error) { throw Error("Chain directory: no two RPC providers agree on a directory block; " + error.errors.map(e => e.message).join("; ")); }
  const snapshot = { ...block, providers: [...providers],
    blockTag: { blockHash: block.blockHash, requireCanonical: true },
    checkProvider: url => heads[providers.indexOf(url)],
  };
  const owner = (await call(snapshot, settings.registry, index, "owner", [], signal, fetcher))[0];
  need(same(owner, settings.publisher), "TunnelIndex owner differs from the pinned Mac publisher.");
  if (settings.codeHash) {
    const code = await agreed(snapshot, "eth_getCode", [settings.registry, snapshot.blockTag], signal, fetcher);
    need(same(keccak256(code), settings.codeHash), "TunnelIndex code differs from its published pin.");
  }
  const [entries] = await call(snapshot, settings.registry, index, "entries", [], signal, fetcher);
  need(entries.length <= 16384, "TunnelIndex entries are too large.");
  const publication = JSON.parse(entries);
  const nodes = signedTunnelNodes(publication, owner, now);
  const expiresAt = Math.min(...(Array.isArray(publication) ? publication : [publication]).map(value => value.expiresAt));
  return {
    nodes, expiresAt, ...snapshot, snapshot,
    verifyRegistration: (registration, signal) => verifyChainRegistration(registration, { snapshot, config, signal, fetcher }),
  };
}

export async function verifyChainRegistration(registration, { snapshot, config, signal, fetcher = fetch }) {
  const p = registration.payments;
  need(p && same(p.escrow, config.escrow) && /^0x[0-9a-f]{64}$/i.test(p.node), "guest has no binding to this usage escrow.");
  const [code, [node], [signer]] = await Promise.all([
    agreed(snapshot, "eth_getCode", [config.escrow, snapshot.blockTag], signal, fetcher),
    call(snapshot, config.escrow, escrow, "getNode", [p.node], signal, fetcher),
    call(snapshot, config.escrow, escrow, "brokerSigner", [], signal, fetcher),
  ]);
  need(same(keccak256(code), config.codeHash), "usage escrow code differs from its published pin.");
  need(same(signer, config.grantSigner) && same(p.grantSigner, signer), "guest grant signer differs from the registered signer.");
  need(node.operator !== "0x0000000000000000000000000000000000000000" && same(node.operator, p.operator) && Number(node.unit) === 1,
    "guest operator or compute class is not registered in UsageEscrow.");
  need(same(node.composeHash, "0x" + registration.manifest_sha256) && same(node.imageHash, "0x" + registration.os_image_hash),
    "guest compose or image differs from its registered UsageEscrow class.");
  return { blockNumber: snapshot.blockNumber, blockHash: snapshot.blockHash, providers: [...snapshot.providers], node: p.node };
}

// Keep the verified snapshot in this page until its signed tunnels expire.
export function chainDirectoryCache({ config, lookup = discoverChainNodes, now = () => Date.now() / 1000,
  publisherOnline, sleep = pause }) {
  let cached;
  return {
    invalidate() { cached = undefined; },
    async read({ signal } = {}) {
      if (cached?.expiresAt > now()) return cached;
      // The pool ticks every 2s and publishes changes at most every 60s.
      // Give a publication already in progress three ticks to land, then fail.
      for (let attempt = 0; ; attempt++) {
        try { cached = await lookup({ config, signal }); return cached; }
        catch (error) {
          if (error.code !== "PUBLICATION_EXPIRED" || attempt === 3 || !await publisherOnline(signal)) throw error;
          await sleep(2000, signal);
        }
      }
    },
  };
}
