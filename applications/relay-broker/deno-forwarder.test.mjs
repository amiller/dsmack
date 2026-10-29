import assert from "node:assert/strict";
import { createLibp2p } from "npm:libp2p@3.3.11";
import { tcp } from "npm:@libp2p/tcp@11.0.28";
import { webSockets } from "npm:@libp2p/websockets@10.1.21";
import { multiaddr } from "npm:@multiformats/multiaddr@13.0.3";
import { circuitRelayTransport, circuitRelayServer } from "npm:@libp2p/circuit-relay-v2@4.2.13";
import { noise } from "npm:@chainsafe/libp2p-noise@17.0.0";
import { yamux } from "npm:@chainsafe/libp2p-yamux@8.0.1";
import { identify } from "npm:@libp2p/identify@4.1.14";
import { byteStream } from "npm:@libp2p/utils@7.4.1";
// Test either source or the deployment bundle, with identical peer fixtures.
const { createDenoForwarder } = await import(Deno.args[0] || "./deno-forwarder.mjs");
const enc = new TextEncoder();
const dec = new TextDecoder();
async function makeNode(listen, services = {}) {
  return await createLibp2p({ addresses: { listen }, transports: [tcp(), webSockets(), circuitRelayTransport()],
    connectionEncrypters: [noise()], streamMuxers: [yamux()], services: { identify: identify(), ...services },
    connectionManager: { minConnections: 0 } });
}
async function readFrame(s) {
  const prefix = (await s.read({ bytes: 4 })).subarray();
  return JSON.parse(dec.decode((await s.read({ bytes: new DataView(prefix.buffer, prefix.byteOffset).getUint32(0, false) })).subarray()));
}
async function writeFrame(s, value) {
  const raw = enc.encode(JSON.stringify(value)), prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, raw.length, false);
  await s.write(prefix); await s.write(raw);
}

Deno.test("shared Deno forwards BE32 jobs over Noise and a circuit relay, without plaintext or buyer keys", async () => {
  const relay = await makeNode(["/ip4/127.0.0.1/tcp/0"], { relay: circuitRelayServer({ reservations: { applyDefaultLimit: false } }) });
  let guest, forwarder;
  try {
    const relayAddress = relay.getMultiaddrs()[0].toString();
    guest = await makeNode([relayAddress + "/p2p-circuit"]);
    const target = relayAddress + "/p2p-circuit/p2p/" + guest.peerId.toString();
    const sealed = { epk: "public-key", iv: "nonce", ct: "ciphertext".repeat(80000) };
    const admission = { job_id: "aa".repeat(16), grant: { sig: "broker-signature" }, client_peer: "browser", signature: "browser-signature", bundle_sha256: "ciphertext-hash" };
    const complete = { status: "complete", outputs: { patch: { ct: "sealed-output" } }, statement: { job_id: admission.job_id } };
    let received;
    let jobWaiting;
    const waiting = new Promise((resolve) => { jobWaiting = resolve; });
    await guest.handle("/dsmack/job/1", async (stream) => {
      const s = byteStream(stream); const a = await readFrame(s);
      if (a.job_id === "busy") { await writeFrame(s, { status: "refused", error: "busy" }); await stream.close(); return; }
      await writeFrame(s, { status: "ready" });
      received = { admission: a, sealed: await readFrame(s) };
      if (a.job_id === "oversize") {
        const prefix = new Uint8Array(4); new DataView(prefix.buffer).setUint32(0, 49 << 20, false);
        await s.write(prefix); await stream.close(); return;
      }
      if (a.job_id === "wait") { jobWaiting(); await new Promise((resolve) => stream.addEventListener("close", resolve, { once: true })); return; }
      await writeFrame(s, complete); await stream.close();
    }, { runOnLimitedConnection: true });
    await guest.handle("/dsmack/attest/1", async (stream) => { stream.send(enc.encode('{"attestation":"public-proof"}')); await stream.close(); }, { runOnLimitedConnection: true });
    await guest.handle("/dsmack/payments-attest/1", async (stream) => {
      const s = byteStream(stream); const q = await readFrame(s);
      stream.send(enc.encode(JSON.stringify({ attestation: "fresh-public-proof", challenge: q.challenge }))); await stream.close();
    }, { runOnLimitedConnection: true });
    forwarder = await createDenoForwarder();
    const reachable = await forwarder.probe(relayAddress);
    assert.equal(reachable.reachable, true); assert.equal(reachable.peer_id, relay.peerId.toString());
    const unreachable = await forwarder.probe(relayAddress.replace(/\/tcp\/[0-9]+/, "/tcp/1").replace(/\/p2p\/[^/]+$/, "/p2p/" + guest.peerId.toString()));
    assert.equal(unreachable.reachable, false); assert.equal(unreachable.error, "node_unreachable");
    assert.deepEqual(await forwarder.forward("attestation", { target }), { attestation: "public-proof" });
    assert.deepEqual(await forwarder.forward("attestation", { target, challenge: "ab".repeat(32) }), { attestation: "fresh-public-proof", challenge: "ab".repeat(32) });
    assert.deepEqual(await forwarder.forward("jobs", { target, admission, sealed }), complete);
    assert.deepEqual(received, { admission, sealed });
    assert.deepEqual(await forwarder.forward("jobs", { target, admission: { ...admission, job_id: "busy" }, sealed }), { status: "refused", error: "busy" });
    await assert.rejects(forwarder.forward("jobs", { target, admission, sealed }, { signal: AbortSignal.abort(new Error("browser left")) }), /node_unreachable/);
    await assert.rejects(forwarder.forward("jobs", { target, admission: { ...admission, job_id: "oversize" }, sealed }), /node_result_lost/);
    const abort = new AbortController();
    const abandoned = forwarder.forward("jobs", { target, admission: { ...admission, job_id: "wait" }, sealed }, { signal: abort.signal });
    await waiting; abort.abort(new Error("browser left after admission"));
    await assert.rejects(abandoned, /node_result_lost/);
  } finally { await forwarder?.stop(); await guest?.stop(); await relay.stop(); }
});

Deno.test("outbound relay WebSocket backhaul reaches the broker through its existing HTTP route", async () => {
  const relay = await makeNode(["/ip4/127.0.0.1/tcp/0"], { relay: circuitRelayServer({ reservations: { applyDefaultLimit: false } }) });
  const forwarder = await createDenoForwarder({ backhaulPeers: [relay.peerId.toString()] });
  const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, (req) => {
    const response = forwarder.acceptWebSocket(req);
    response.headers.set("cache-control", "no-store");
    return response;
  });
  try {
    const target = "/ip4/127.0.0.1/tcp/" + server.addr.port + "/ws/p2p/" + forwarder.peerId;
    const identified = new Promise((resolve) => relay.addEventListener("peer:identify", (event) => {
      if (event.detail.peerId.toString() === forwarder.peerId) resolve();
    }, { once: true }));
    await relay.dial(multiaddr(target));
    await identified;
    const unreachableAddress = relay.getMultiaddrs()[0].toString().replace(/\/tcp\/[0-9]+/, "/tcp/1");
    const connection = await forwarder.probe(unreachableAddress);
    assert.equal(connection.reachable, true);
    assert.equal(connection.peer_id, relay.peerId.toString());
  } finally { await relay.stop(); await forwarder.stop(); await server.shutdown(); }
});
