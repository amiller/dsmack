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
const { createDenoForwarder, ForwardError } = await import(Deno.args[0] || "./deno-forwarder.mjs");
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

Deno.test("shared Deno fetches node attestations over Noise and a circuit relay", async () => {
  const relay = await makeNode(["/ip4/127.0.0.1/tcp/0"], { relay: circuitRelayServer({ reservations: { applyDefaultLimit: false } }) });
  let guest, forwarder;
  try {
    const relayAddress = relay.getMultiaddrs()[0].toString();
    guest = await makeNode([relayAddress + "/p2p-circuit"]);
    const target = relayAddress + "/p2p-circuit/p2p/" + guest.peerId.toString();
    await guest.handle("/dsmack/attest/1", async (stream) => { stream.send(enc.encode('{"attestation":"public-proof"}')); await stream.close(); }, { runOnLimitedConnection: true });
    await guest.handle("/dsmack/payments-attest/1", async (stream) => {
      const s = byteStream(stream); const q = await readFrame(s);
      stream.send(enc.encode(JSON.stringify({ attestation: "fresh-public-proof", challenge: q.challenge }))); await stream.close();
    }, { runOnLimitedConnection: true });
    forwarder = await createDenoForwarder();
    const unreachable = relayAddress.replace(/\/tcp\/[0-9]+/, "/tcp/1").replace(/\/p2p\/[^/]+$/, "/p2p/" + guest.peerId.toString());
    await assert.rejects(forwarder.forward("attestation", { target: unreachable }), /node_unreachable/);
    const discoveryRequest = new AbortController();
    assert.deepEqual(await forwarder.forward("attestation", { target }, { signal: discoveryRequest.signal }), { attestation: "public-proof" });
    // Deno's successful HTTP response can abort its Request signal afterwards.
    discoveryRequest.abort(new Error("successful discovery HTTP response ended"));
    assert.deepEqual(await forwarder.forward("attestation", { target, challenge: "ab".repeat(32) }), { attestation: "fresh-public-proof", challenge: "ab".repeat(32) });
  } finally { await forwarder?.stop(); await guest?.stop(); await relay.stop(); }
});

Deno.test("HTTP polling backhaul carries pinned relay Noise", async () => {
  const relay = await makeNode(["/ip4/127.0.0.1/tcp/0"], { relay: circuitRelayServer({ reservations: { defaultDurationLimit: 120000, defaultDataLimit: 8n << 20n } }) });
  const forwarder = await createDenoForwarder({ backhaulPeers: [relay.peerId.toString()] });
  const http = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, (req) => forwarder.acceptBackhaul(req));
  const base = "http://127.0.0.1:" + http.addr.port + "/sandbox/p2p";
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const adapters = new Set();
  const adapt = async (conn) => {
    const controller = new AbortController();
    let id;
    try {
      const response = await fetch(base + "/open", { method: "POST", signal: controller.signal });
      assert.equal(response.status, 200); id = (await response.json()).id;
      const upload = async () => {
        const buffer = new Uint8Array(32768);
        while (true) {
          const size = await conn.read(buffer);
          if (size === null) return;
          const sent = await fetch(base + "/" + id + "/send", { method: "POST", body: buffer.slice(0, size), signal: controller.signal });
          if (sent.status !== 204) throw new Error("backhaul send refused");
        }
      };
      const download = async () => {
        while (true) {
          const response = await fetch(base + "/" + id + "/recv", { signal: controller.signal });
          if (response.status === 204) continue;
          if (response.status !== 200) throw new Error("backhaul closed");
          const bytes = new Uint8Array(await response.arrayBuffer());
          for (let offset = 0; offset < bytes.length;) offset += await conn.write(bytes.subarray(offset));
        }
      };
      await Promise.race([upload(), download()]);
    } catch (error) { if (!controller.signal.aborted && error.name !== "BadResource") { /* connection failure closes this transport */ } }
    finally {
      controller.abort();
      try { conn.close(); } catch { /* peer already closed */ }
      if (id) await fetch(base + "/" + id, { method: "DELETE" });
    }
  };
  const accepting = (async () => {
    try { for await (const conn of listener) { const task = adapt(conn); adapters.add(task); task.finally(() => adapters.delete(task)); } }
    catch (error) { if (error.name !== "BadResource" && error.name !== "Interrupted") throw error; }
  })();
  try {
    const target = "/ip4/127.0.0.1/tcp/" + listener.addr.port + "/p2p/" + forwarder.peerId;
    const identified = new Promise((resolve) => relay.addEventListener("peer:identify", (event) => {
      if (event.detail.peerId.toString() === forwarder.peerId) resolve();
    }, { once: true }));
    await relay.dial(multiaddr(target)); await identified;
    const unreachableAddress = relay.getMultiaddrs()[0].toString().replace(/\/tcp\/[0-9]+/, "/tcp/1");
    await relay.handle("/dsmack/attest/1", async (stream) => {
      stream.send(enc.encode('{"attestation":"backhaul-proof"}')); await stream.close();
    });
    assert.deepEqual(await forwarder.forward("attestation", { target: unreachableAddress }), { attestation: "backhaul-proof" });
    const stranger = await makeNode([]);
    try { await assert.rejects(stranger.dialProtocol(multiaddr(target), "/ipfs/id/1.0.0", { signal: AbortSignal.timeout(2000) })); }
    finally { await stranger.stop(); }
  } finally {
    listener.close(); await relay.stop(); await forwarder.stop(); await accepting;
    await Promise.all([...adapters]); await http.shutdown();
  }
});

Deno.test("project signing identity keeps relay backhaul peer pins valid after promotion", async () => {
  const { signingKey } = await import("./grants.mjs");
  const key = await signingKey("71".repeat(32));
  const first = await createDenoForwarder({ signingKey: key });
  const restarted = await createDenoForwarder({ signingKey: key });
  try { assert.equal(first.peerId, restarted.peerId); }
  finally { await first.stop(); await restarted.stop(); }
});

Deno.test("forward errors retain bounded nested dial causes without stacks", () => {
  const dial = new AggregateError([
    new Error("connect ECONNREFUSED"),
    new Error("circuit hop refused", { cause: new Error("reservation expired") }),
  ], "All multiaddr dials failed");
  const error = new ForwardError("node_unreachable", dial);
  assert.equal(error.stage, "node_unreachable");
  assert.deepEqual(error.detail, { name: "AggregateError", message: "All multiaddr dials failed", errors: [
    { name: "Error", message: "connect ECONNREFUSED" },
    { name: "Error", message: "circuit hop refused", cause: { name: "Error", message: "reservation expired" } },
  ] });
  assert.equal(JSON.stringify(error.detail).includes("stack"), false);
  assert.equal(new ForwardError("node_result_lost", new Error("x".repeat(2000))).detail.message.length, 512);
});
