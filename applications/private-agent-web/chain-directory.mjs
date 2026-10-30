import { Interface, keccak256, verifyMessage } from "npm:ethers@6.17.0";
import { address, tunnel } from "../browser-p2p/tunnels.mjs";

const index = new Interface(["function owner() view returns (address)", "function entries() view returns (string)"]);
const escrow = new Interface([
  "function brokerSigner() view returns (address)",
  "function getNode(bytes32) view returns (tuple(address operator,uint8 unit,uint128 floorPrice,uint128 target,uint128 price,uint128 booked,uint64 epoch,bytes32 composeHash,bytes32 imageHash))",
]);
const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
const need = (ok, message) => { if (!ok) throw Error("Chain directory: " + message); };

async function rpc(url, method, params, signal, fetcher) {
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
}

async function agreed(snapshot, method, params, signal, fetcher) {
  const replies = await Promise.all(snapshot.providers.map(url => rpc(url, method, params, signal, fetcher)));
  need(canonical(replies[0]) === canonical(replies[1]), `the two RPC providers disagree on ${method} at block ${snapshot.blockNumber}.`);
  return replies[0];
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
    need(Number.isSafeInteger(unsigned.expiresAt) && unsigned.expiresAt > now && unsigned.expiresAt <= now + 3600,
      "signed tunnel publication has expired or has an invalid expiry.");
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
  const providers = settings.rpcs || ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"];
  need(providers.length === 2 && new Set(providers.map(url => new URL(url).hostname)).size === 2 && providers.every(url => new URL(url).protocol === "https:"),
    "two independent HTTPS RPC providers are required.");
  need(config.chainId === 84532, "Base Sepolia is required.");
  const heads = await Promise.all(providers.map(async url => {
    const [chain, height] = await Promise.all([rpc(url, "eth_chainId", [], signal, fetcher), rpc(url, "eth_blockNumber", [], signal, fetcher)]);
    need(Number(chain) === 84532, `${new URL(url).hostname} returned the wrong chain.`);
    need(/^0x[0-9a-f]+$/i.test(height), "RPC returned an invalid block height.");
    return BigInt(height);
  }));
  const height = heads[0] < heads[1] ? heads[0] : heads[1];
  const snapshot = { providers: [...providers], blockNumber: Number(height), blockTag: "0x" + height.toString(16) };
  const headers = await Promise.all(providers.map(url => rpc(url, "eth_getBlockByNumber", [snapshot.blockTag, false], signal, fetcher)));
  need(headers.every(header => header?.number === snapshot.blockTag && /^0x[0-9a-f]{64}$/i.test(header.hash)) && same(headers[0].hash, headers[1].hash),
    "the two RPC providers disagree on the directory block.");
  snapshot.blockHash = headers[0].hash;
  const owner = (await call(snapshot, settings.registry, index, "owner", [], signal, fetcher))[0];
  need(same(owner, settings.publisher), "TunnelIndex owner differs from the pinned Mac publisher.");
  if (settings.codeHash) {
    const code = await agreed(snapshot, "eth_getCode", [settings.registry, snapshot.blockTag], signal, fetcher);
    need(same(keccak256(code), settings.codeHash), "TunnelIndex code differs from its published pin.");
  }
  const [entries] = await call(snapshot, settings.registry, index, "entries", [], signal, fetcher);
  need(entries.length <= 16384, "TunnelIndex entries are too large.");
  const nodes = signedTunnelNodes(JSON.parse(entries), owner, now);
  return {
    nodes, ...snapshot, snapshot,
    verifyRegistration: registration => verifyChainRegistration(registration, { snapshot, config, signal, fetcher }),
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
