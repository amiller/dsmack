import test from "node:test";
import assert from "node:assert/strict";
import { fetchDirectAttestation, readDirectAttestation } from "./direct-attestation.mjs";

const relayPeer = "12D3KooW" + "A".repeat(44);
const guestPeer = "12D3KooW" + "B".repeat(44);
const challenge = "a".repeat(64);
const selected = { relay_peer: guestPeer, tunnels: [{
  url: "wss://direct-attestation.trycloudflare.com/", relayPeer, guestPeer,
  expiresAt: Math.ceil(Date.now() / 1000) + 300,
}] };
const policy = { manifest: new TextEncoder().encode(JSON.stringify({
  docker_compose_file: JSON.stringify({ services: { node: {
    command: ["serve", "/p2p/" + relayPeer],
  } } }),
})) };
function remote({ registration = { relay_peer: guestPeer, payments: { challenge } }, remotePeer = guestPeer } = {}) {
  let sent;
  const stream = {
    status: "open", send(raw) { sent = raw; return true; },
    abort() { this.status = "aborted"; },
    async *[Symbol.asyncIterator]() {
      const raw = new TextEncoder().encode(JSON.stringify(registration));
      yield raw.subarray(0, 7); yield raw.subarray(7);
    },
  };
  const connection = {
    remotePeer: { toString: () => remotePeer },
    async newStream(protocol) { assert.equal(protocol, "/dsmack/payments-attest/1"); return stream; },
    async close() { this.closed = true; },
  };
  return { peer: { async dial() { return connection; } }, connection, stream,
    request() { assert.equal(new DataView(sent.buffer).getUint32(0), sent.length - 4); return JSON.parse(new TextDecoder().decode(sent.subarray(4))); } };
}
test("direct attestation sends only the fresh challenge and returns the bound Noise connection", async () => {
  const network = remote();
  const result = await fetchDirectAttestation({ peer: network.peer, selected, policy, challenge });
  assert.deepEqual(network.request(), { challenge });
  assert.equal(result.connection, network.connection);
  assert.equal(result.registration.relay_peer, guestPeer);
  assert.equal(network.connection.closed, undefined);
});
test("a stale direct challenge closes the unverified connection", async () => {
  const network = remote({ registration: { relay_peer: guestPeer, payments: { challenge: "b".repeat(64) } } });
  await assert.rejects(fetchDirectAttestation({ peer: network.peer, selected, policy, challenge }), /stale attestation/);
  assert.equal(network.connection.closed, true);
});
test("a different Noise peer never receives an attestation request", async () => {
  const network = remote({ remotePeer: relayPeer });
  await assert.rejects(fetchDirectAttestation({ peer: network.peer, selected, policy, challenge }), /Noise peer differs/);
  assert.equal(network.connection.closed, true);
});
test("oversized network attestation stops before parsing", async () => {
  async function* oversized() { yield new Uint8Array(150001); }
  await assert.rejects(readDirectAttestation(oversized()), /response limit/);
});
