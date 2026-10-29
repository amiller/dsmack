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
    const unreachable = relayAddress.replace(/\/tcp\/[0-9]+/, "/tcp/1").replace(/\/p2p\/[^/]+$/, "/p2p/" + guest.peerId.toString());
    await assert.rejects(forwarder.forward("attestation", { target: unreachable }), /node_unreachable/);
    const discoveryRequest = new AbortController();
    assert.deepEqual(await forwarder.forward("attestation", { target }, { signal: discoveryRequest.signal }), { attestation: "public-proof" });
    // Deno's successful HTTP response can abort its Request signal afterwards.
    discoveryRequest.abort(new Error("successful discovery HTTP response ended"));
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

Deno.test("HTTP polling backhaul carries pinned relay Noise through ordinary shared-project requests", async () => {
  const relay = await makeNode(["/ip4/127.0.0.1/tcp/0"], { relay: circuitRelayServer({ reservations: { applyDefaultLimit: false } }) });
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
        const buffer = new Uint8Array(65536);
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
