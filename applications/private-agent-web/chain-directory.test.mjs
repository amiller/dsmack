import { test } from "node:test";
import assert from "node:assert/strict";
import { Interface, keccak256, Wallet } from "npm:ethers@6.17.0";
import { discoverChainNodes, signedTunnelNodes } from "./chain-directory.mjs";

const publisher = Wallet.createRandom(), now = 1793390000;
const peer = "12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
const entry = { url: "wss://test-guest.trycloudflare.com/", relayPeer: peer, guestPeer: peer, expiresAt: now + 600 };
const index = new Interface(["function owner() view returns (address)", "function entries() view returns (string)"]);
const escrow = new Interface([
  "function brokerSigner() view returns (address)",
  "function getNode(bytes32) view returns (tuple(address operator,uint8 unit,uint128 floorPrice,uint128 target,uint128 price,uint128 booked,uint64 epoch,bytes32 composeHash,bytes32 imageHash))",
]);
const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const word = n => "0x" + n.toString(16).padStart(64, "0");
async function envelope(entries = [entry], expiresAt = now + 600) {
  const unsigned = { entries, expiresAt, publisher: publisher.address.toLowerCase() };
  return { ...unsigned, signature: await publisher.signMessage("dsmack-tunnels/1\n" + canonical(unsigned)) };
}
async function fixture({ disagree, composeHash = word(3) } = {}) {
  const publication = await envelope(), calls = [];
  const config = {
    chainId: 84532, escrow: "0x" + "11".repeat(20), codeHash: keccak256("0x6000"), grantSigner: publisher.address,
    chainDirectory: { registry: "0x" + "22".repeat(20), publisher: publisher.address, rpcs: ["https://one.example", "https://two.example"] },
  };
  const registration = { manifest_sha256: word(3).slice(2), os_image_hash: word(4).slice(2), payments: {
    escrow: config.escrow, node: word(1), operator: publisher.address, grantSigner: config.grantSigner,
  } };
  const fetcher = async (url, options) => {
    const { method, params } = JSON.parse(options.body); calls.push({ url, method, params });
    let result;
    if (method === "eth_chainId") result = "0x14a34";
    if (method === "eth_blockNumber") result = url.includes("one") ? "0x64" : "0x65";
    if (method === "eth_getBlockByNumber") result = { number: params[0], hash: disagree === "block" && url.includes("two") ? word(8) : word(9) };
    if (method === "eth_getCode") result = "0x6000";
    if (method === "eth_call") {
      const abi = params[0].to === config.escrow ? escrow : index;
      const call = abi.parseTransaction({ data: params[0].data });
      if (call.name === "owner") result = abi.encodeFunctionResult("owner", [publisher.address]);
      if (call.name === "entries") result = abi.encodeFunctionResult("entries", [JSON.stringify(publication)]);
      if (call.name === "brokerSigner") result = abi.encodeFunctionResult("brokerSigner", [publisher.address]);
      if (call.name === "getNode") result = abi.encodeFunctionResult("getNode", [[publisher.address, 1, 1, 30, 1, 0, 1, composeHash, word(4)]]);
      if (disagree === call.name && url.includes("two")) result += "00";
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
  };
  return { config, fetcher, calls, registration };
}

test("chain discovery cross-checks a common block and verifies the registered guest class", async () => {
  const f = await fixture(), directory = await discoverChainNodes({ ...f, now });
  assert.equal(directory.blockNumber, 100);
  assert.equal(directory.nodes[0].relay_peer, peer);
  assert.deepEqual(directory.nodes[0].tunnels, [entry]);
  assert.equal((await directory.verifyRegistration(f.registration)).node, word(1));
  const fixedReads = f.calls.filter(call => ["eth_call", "eth_getCode"].includes(call.method));
  assert.ok(fixedReads.length > 0 && fixedReads.every(call => call.params[1] === "0x64"));
  for (const call of fixedReads) assert.ok(fixedReads.some(other => other.url !== call.url && other.method === call.method && JSON.stringify(other.params) === JSON.stringify(call.params)));
});

test("unsigned, altered and expired tunnel publications cannot supply guest peers", async () => {
  assert.throws(() => signedTunnelNodes([entry], publisher.address, now), /unsigned entries/);
  const signed = await envelope();
  assert.throws(() => signedTunnelNodes({ ...signed, entries: [{ ...entry, guestPeer: peer.replace(/.$/, "y") }] }, publisher.address, now), /signature is invalid/);
  assert.throws(() => signedTunnelNodes(signed, publisher.address, now + 601), /expired/);
  const relayOnly = await envelope([{ url: entry.url, relayPeer: peer, expiresAt: now + 600 }]);
  assert.throws(() => signedTunnelNodes(relayOnly, publisher.address, now), /no guest PeerId/);
});

test("provider disagreement stops chain discovery", async () => {
  for (const disagree of ["block", "entries"]) {
    const f = await fixture({ disagree });
    await assert.rejects(discoverChainNodes({ ...f, now }), /two RPC providers disagree/);
  }
});

test("a valid direct attestation cannot replace the registered compose measurements", async () => {
  const f = await fixture({ composeHash: word(5) }), directory = await discoverChainNodes({ ...f, now });
  await assert.rejects(directory.verifyRegistration(f.registration), /differs from its registered UsageEscrow class/);
});
