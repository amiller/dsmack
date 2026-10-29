// In-process TCP/Noise/circuit-relay transport for the shared Deno broker.
// Only public admission data and secret-box ciphertext cross this transport.
import { createLibp2p } from "npm:libp2p@3.3.11";
import { tcp } from "npm:@libp2p/tcp@11.0.28";
import { webSockets } from "npm:@libp2p/websockets@10.1.21";
import { circuitRelayTransport } from "npm:@libp2p/circuit-relay-v2@4.2.13";
import { noise } from "npm:@chainsafe/libp2p-noise@17.0.0";
import { yamux } from "npm:@chainsafe/libp2p-yamux@8.0.1";
import { identify } from "npm:@libp2p/identify@4.1.14";
import { multiaddr } from "npm:@multiformats/multiaddr@13.0.3";

const enc = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CONTROL_LIMIT = 4096;
const BUNDLE_LIMIT = 48 << 20;
const ATTESTATION_LIMIT = 150000;
const canonical = (value) => JSON.stringify(value, (_key, v) => v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v);

export class ForwardError extends Error {
  constructor(code, cause) { super(code, { cause }); this.code = code; this.status = 502; }
}

class Reader {
  constructor(stream) { this.iterator = stream[Symbol.asyncIterator](); this.chunk = new Uint8Array(); this.offset = 0; }
  async pull() {
    if (this.offset < this.chunk.length) return true;
    const next = await this.iterator.next();
    if (next.done) return false;
    this.chunk = next.value instanceof Uint8Array ? next.value : next.value.subarray();
    this.offset = 0;
    return true;
  }
  async bytes(length) {
    const out = new Uint8Array(length);
    let used = 0;
    while (used < length) {
      if (!await this.pull()) throw new Error("unexpected EOF");
      const size = Math.min(length - used, this.chunk.length - this.offset);
      out.set(this.chunk.subarray(this.offset, this.offset + size), used);
      this.offset += size; used += size;
    }
    return out;
  }
  async frame(limit) {
    const prefix = await this.bytes(4);
    const length = new DataView(prefix.buffer).getUint32(0, false);
    if (!length || length > limit) throw new Error("frame size");
    return JSON.parse(decoder.decode(await this.bytes(length)));
  }
  async registration() {
    const parts = []; let length = 0;
    while (await this.pull()) {
      const part = this.chunk.subarray(this.offset);
      length += part.length;
      if (length > ATTESTATION_LIMIT) throw new Error("attestation size");
      parts.push(part); this.offset = this.chunk.length;
    }
    const raw = new Uint8Array(length); let offset = 0;
    for (const part of parts) { raw.set(part, offset); offset += part.length; }
    return JSON.parse(decoder.decode(raw));
  }
}

async function sendFrame(stream, value, limit, signal) {
  const body = enc.encode(canonical(value));
  if (!body.length || body.length > limit) throw new Error("frame size");
  const prefix = new Uint8Array(4); new DataView(prefix.buffer).setUint32(0, body.length, false);
  if (!stream.send(prefix)) await stream.onDrain({ signal });
  for (let offset = 0; offset < body.length; offset += 65536) {
    signal.throwIfAborted();
    if (!stream.send(body.subarray(offset, offset + 65536))) await stream.onDrain({ signal });
  }
}

export async function createDenoForwarder({ privateKey, logger, backhaulPeers = [] } = {}) {
  const node = await createLibp2p({
    ...(privateKey ? { privateKey } : {}), ...(logger ? { logger } : {}),
    addresses: { listen: backhaulPeers.length ? ["/ip4/127.0.0.1/tcp/0/ws"] : [] },
    transports: [tcp({ outboundSocketInactivityTimeout: 905000 }), webSockets(), circuitRelayTransport()],
    connectionGater: { denyInboundEncryptedConnection: (peer) => !backhaulPeers.includes(peer.toString()) },
    connectionEncrypters: [noise()], streamMuxers: [yamux()],
    services: { identify: identify() },
    connectionManager: { minConnections: 0, dialTimeout: 25000, addressDialTimeout: 25000 },
  });
  const websocketAddress = node.getMultiaddrs().find((addr) => addr.toString().includes("/ws"));
  const websocketPort = websocketAddress?.getComponents().find((part) => part.name === "tcp")?.value;
  const channels = new Map();
  const closeChannel = (id) => {
    const channel = channels.get(id);
    if (!channel) return;
    channels.delete(id); clearTimeout(channel.timer); channel.wake?.();
    if (channel.socket.readyState < WebSocket.CLOSING) channel.socket.close();
  };
  const touch = (id, milliseconds = 900000) => {
    const channel = channels.get(id);
    if (channel) { clearTimeout(channel.timer); channel.timer = setTimeout(() => closeChannel(id), milliseconds); }
  };
  return {
    async acceptBackhaul(req) {
      const path = new URL(req.url).pathname;
      const error = (code, status) => Response.json({ error: code }, { status });
      if (!websocketPort) return error("backhaul_not_configured", 503);
      if (req.method === "POST" && path === "/sandbox/p2p/open") {
        if (channels.size >= 8) return error("backhaul_busy", 429);
        const id = Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) => x.toString(16).padStart(2, "0")).join("");
        const socket = new WebSocket("ws://127.0.0.1:" + websocketPort);
        socket.binaryType = "arraybuffer";
        const channel = { socket, queue: [], bytes: 0, wake: undefined, receiving: false, timer: undefined };
        channels.set(id, channel); touch(id, 30000);
        socket.addEventListener("message", (event) => {
          if (!(event.data instanceof ArrayBuffer) || channel.bytes + event.data.byteLength > 4194304) { closeChannel(id); return; }
          channel.queue.push(new Uint8Array(event.data)); channel.bytes += event.data.byteLength; channel.wake?.();
        });
        socket.addEventListener("close", () => closeChannel(id), { once: true });
        socket.addEventListener("error", () => closeChannel(id), { once: true });
        try {
          await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error("loopback websocket timeout")), 5000);
            socket.addEventListener("open", () => { clearTimeout(timeout); resolve(); }, { once: true });
            socket.addEventListener("error", () => { clearTimeout(timeout); reject(new Error("loopback websocket failed")); }, { once: true });
          });
        } catch { closeChannel(id); return error("backhaul_unavailable", 503); }
        return Response.json({ id });
      }
      const match = /^\/sandbox\/p2p\/([0-9a-f]{64})(?:\/(send|recv))?$/.exec(path);
      if (!match) return error("not_found", 404);
      const [, id, action] = match, channel = channels.get(id);
      if (!channel) return error("backhaul_closed", 404);
      if (req.method === "DELETE" && !action) { closeChannel(id); return new Response(null, { status: 204 }); }
      if (req.method === "POST" && action === "send") {
        const parts = []; let size = 0;
        if (req.body) for await (const part of req.body) {
          size += part.length;
          if (size > 65536) return error("backhaul_chunk_too_large", 413);
          parts.push(part);
        }
        if (!size) return error("backhaul_empty_chunk", 400);
        if (channel.socket.readyState !== WebSocket.OPEN) return error("backhaul_closed", 404);
        if (channel.socket.bufferedAmount + size > 4194304) { closeChannel(id); return error("backhaul_overflow", 429); }
        const raw = new Uint8Array(size); let offset = 0;
        for (const part of parts) { raw.set(part, offset); offset += part.length; }
        channel.socket.send(raw); touch(id);
        return new Response(null, { status: 204 });
      }
      if (req.method === "GET" && action === "recv") {
        if (channel.receiving) return error("backhaul_recv_in_flight", 409);
        channel.receiving = true;
        try {
          if (!channel.queue.length) await new Promise((resolve) => {
            const finish = () => { clearTimeout(timer); req.signal.removeEventListener("abort", finish); channel.wake = undefined; resolve(); };
            const timer = setTimeout(finish, 20000); channel.wake = finish;
            if (req.signal.aborted) finish(); else req.signal.addEventListener("abort", finish, { once: true });
          });
          if (!channels.has(id)) return error("backhaul_closed", 404);
          if (!channel.queue.length) return new Response(null, { status: 204 });
          const first = channel.queue[0], raw = first.subarray(0, 65536);
          if (first.length <= 65536) channel.queue.shift(); else channel.queue[0] = first.subarray(65536);
          channel.bytes -= raw.length; touch(id);
          return new Response(raw, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
        } finally { channel.receiving = false; }
      }
      return error("not_found", 404);
    },
    peerId: node.peerId.toString(),
    stop: () => { for (const id of channels.keys()) closeChannel(id); return node.stop(); },
    async probe(target, { signal: requestedSignal } = {}) {
      const started = Date.now();
      const signal = AbortSignal.any([...(requestedSignal ? [requestedSignal] : []), AbortSignal.timeout(5000)]);
      try {
        const connection = await node.dial(multiaddr(target), { signal });
        return { reachable: true, peer_id: connection.remotePeer.toString(), elapsed_ms: Date.now() - started };
      } catch (error) {
        return { reachable: false, error: "node_unreachable", reason: error.name, elapsed_ms: Date.now() - started };
      }
    },
    async forward(endpoint, payload, { signal: requestedSignal } = {}) {
      if (endpoint !== "attestation" && endpoint !== "jobs") throw new Error("forward endpoint");
      const signal = AbortSignal.any([...(requestedSignal ? [requestedSignal] : []),
        AbortSignal.timeout(endpoint === "jobs" ? 900000 : 30000)]);
      let stream;
      let phase = "node_unreachable";
      try {
        const protocol = endpoint === "jobs" ? "/dsmack/job/1" : payload.challenge
          ? "/dsmack/payments-attest/1" : "/dsmack/attest/1";
        stream = await node.dialProtocol(multiaddr(payload.target), protocol,
          { signal, runOnLimitedConnection: true });
        // Agent turns may be quiet for longer than libp2p's default 120 seconds.
        stream.inactivityTimeout = endpoint === "jobs" ? 900000 : 30000;
        const abort = () => stream.abort(signal.reason instanceof Error ? signal.reason : new Error("request aborted"));
        signal.addEventListener("abort", abort, { once: true });
        try {
          signal.throwIfAborted();
          const reader = new Reader(stream);
          if (endpoint === "attestation") {
            phase = "node_attestation";
            if (payload.challenge) await sendFrame(stream, { challenge: payload.challenge }, CONTROL_LIMIT, signal);
            return await reader.registration();
          }
          phase = "node_admission";
          await sendFrame(stream, payload.admission, CONTROL_LIMIT, signal);
          const admission = await reader.frame(CONTROL_LIMIT);
          if (admission.status === "refused") return admission;
          if (admission.status !== "ready") throw new Error("node did not send ready");
          phase = "node_result_lost";
          await sendFrame(stream, payload.sealed, BUNDLE_LIMIT, signal);
          return await reader.frame(BUNDLE_LIMIT);
        } finally { signal.removeEventListener("abort", abort); }
      } catch (cause) { throw new ForwardError(phase, cause); }
      finally { if (stream && stream.status !== "closed" && stream.status !== "aborted") stream.abort(new Error("forward complete")); }
    },
  };
}
