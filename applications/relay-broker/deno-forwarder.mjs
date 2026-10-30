// In-process TCP/Noise/circuit-relay transport for the shared Deno broker.
// Only public admission data and secret-box ciphertext cross this transport.
import { privateKeyFromRaw } from "npm:@libp2p/crypto@5.2.0/keys";
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
const ATTESTATION_LIMIT = 150000;
const canonical = (value) => JSON.stringify(value, (_key, v) => v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v);

// A completed request must not later abort a cached libp2p connection created
// during its dial. Detach the HTTP signal and cancel the operation timer on exit.
function operationScope(milliseconds, external) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new DOMException("operation timed out", "TimeoutError")), milliseconds);
  const abort = () => controller.abort(external.reason);
  if (external?.aborted) abort(); else external?.addEventListener("abort", abort, { once: true });
  return { signal: controller.signal, clear() { clearTimeout(timeout); external?.removeEventListener("abort", abort); } };
}
function networkCause(error, budget = { nodes: 0 }, seen = new Set(), depth = 0) {
  budget.nodes++;
  const name = String(error?.name || "Error"), message = String(error?.message ?? error);
  const detail = { name: name.slice(0, 64), message: message.slice(0, 512) };
  if (name.length > 64 || message.length > 512) detail.truncated = true;
  if (depth >= 4 || seen.has(error)) { detail.truncated = true; return detail; }
  seen.add(error);
  if (error?.cause != null) {
    if (budget.nodes < 8) detail.cause = networkCause(error.cause, budget, seen, depth + 1);
    else detail.truncated = true;
  }
  if (Array.isArray(error?.errors)) {
    detail.errors = [];
    for (const nested of error.errors.slice(0, 4)) {
      if (budget.nodes >= 8) { detail.truncated = true; break; }
      detail.errors.push(networkCause(nested, budget, seen, depth + 1));
    }
    if (detail.errors.length < error.errors.length) detail.truncated = true;
  }
  return detail;
}
export class ForwardError extends Error {
  constructor(code, cause, progress = []) {
    super(code, { cause }); this.code = code; this.stage = code; this.status = 502;
    this.detail = networkCause(cause);
    if (progress.length) this.detail.progress = progress;
  }
}

class EmptyAttestationResponseError extends Error {
  constructor() {
    super("guest closed without an attestation response");
    this.name = "EmptyAttestationResponseError";
    this.code = "EMPTY_ATTESTATION_RESPONSE";
  }
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
  async registration() {
    const parts = []; let length = 0;
    while (await this.pull()) {
      const part = this.chunk.subarray(this.offset);
      length += part.length;
      if (length > ATTESTATION_LIMIT) throw new Error("attestation size");
      parts.push(part); this.offset = this.chunk.length;
    }
    if (length === 0) throw new EmptyAttestationResponseError();
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

export async function createDenoForwarder({ privateKey, signingKey, logger, backhaulPeers = [], onProgress } = {}) {
  if (signingKey) {
    // Noise signs its protocol-prefixed static key; grants sign canonical JSON.
    // Keep the project identity stable across shared-worker promotions.
    const jwk = await crypto.subtle.exportKey("jwk", signingKey.priv);
    const bytes = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const raw = new Uint8Array(64); raw.set(bytes(jwk.d)); raw.set(bytes(jwk.x), 32);
    privateKey = privateKeyFromRaw(raw);
  }
  const node = await createLibp2p({
    ...(privateKey ? { privateKey } : {}), ...(logger ? { logger } : {}),
    addresses: { listen: backhaulPeers.length ? ["/ip4/127.0.0.1/tcp/0/ws"] : [] },
    transports: [tcp({ outboundSocketInactivityTimeout: 905000 }), webSockets(), circuitRelayTransport()],
    connectionGater: { denyInboundEncryptedConnection: (peer) => !backhaulPeers.includes(peer.toString()) },
    connectionEncrypters: [noise()], streamMuxers: [yamux()],
    services: { identify: identify() },
    connectionManager: { minConnections: 0, dialTimeout: 25000, addressDialTimeout: 25000 },
    // One backhaul receive can long-poll for 20s; its HTTP deadline is 25s.
    // A 5s LAN heartbeat must not preempt that bounded HTTPS transport.
    connectionMonitor: { pingInterval: 30000, pingTimeout: { minTimeout: 30000, maxTimeout: 60000 } },
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
          if (event.data.byteLength) {
            channel.queue.push(new Uint8Array(event.data)); channel.bytes += event.data.byteLength; channel.wake?.();
          }
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
          // WebSocket messages carry one TCP byte stream. Drain every queued
          // message that fits so small muxer frames do not each cost a WAN poll.
          const raw = new Uint8Array(Math.min(65536, channel.bytes));
          let offset = 0;
          while (offset < raw.length) {
            const first = channel.queue[0], count = Math.min(first.length, raw.length - offset);
            raw.set(first.subarray(0, count), offset); offset += count;
            if (count === first.length) channel.queue.shift(); else channel.queue[0] = first.subarray(count);
          }
          channel.bytes -= raw.length; touch(id);
          return new Response(raw, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
        } finally { channel.receiving = false; }
      }
      return error("not_found", 404);
    },
    peerId: node.peerId.toString(),
    stop: () => { for (const id of channels.keys()) closeChannel(id); return node.stop(); },
    async forward(endpoint, payload, { signal: requestedSignal } = {}) {
      if (endpoint !== "attestation") throw new Error("forward endpoint");
      const scope = operationScope(30000, requestedSignal), { signal } = scope;
      const protocol = payload.challenge
        ? "/dsmack/payments-attest/1" : "/dsmack/attest/1";
      const started = performance.now(), progress = [];
      const record = (event, stage) => {
        if (progress.length >= 48) return;
        const entry = { event: event.slice(0, 96), elapsedMs: Math.round((performance.now() - started) * 10) / 10,
          ...(stage ? { stage } : {}) };
        progress.push(entry);
        // Event names/timing are public; never forward libp2p event.detail,
        // which can contain connections, protocol messages or key objects.
        onProgress?.({ endpoint, peer: payload.target.split("/p2p/").at(-1), ...entry });
      };
      const dialProgress = event => {
        const stage = event.type.startsWith("circuit-relay:") ? "hop"
          : event.type.startsWith("upgrader:encrypt-") ? "noise"
          : event.type.startsWith("upgrader:multiplex-") ? "muxer"
          : event.type.startsWith("connection:") &&
            (event.detail?.protocols?.includes(protocol) || event.detail?.stream?.protocol === protocol) ? "application" : undefined;
        record(event.type, stage);
      };
      let stream;
      let phase = "node_unreachable";
      try {
        record("forward:start");
        stream = await node.dialProtocol(multiaddr(payload.target), protocol,
          { signal, runOnLimitedConnection: true, onProgress: dialProgress });
        record("application:ready", "application");
        // Agent turns may be quiet for longer than libp2p's default 120 seconds.
        stream.inactivityTimeout = 30000;
        const abort = () => stream.abort(signal.reason instanceof Error ? signal.reason : new Error("request aborted"));
        signal.addEventListener("abort", abort, { once: true });
        try {
          signal.throwIfAborted();
          phase = "node_attestation";
          record("attestation:request", "attestation");
          if (payload.challenge) await sendFrame(stream, { challenge: payload.challenge }, CONTROL_LIMIT, signal);
          const registration = await new Reader(stream).registration();
          record("attestation:received", "attestation");
          return registration;
        } finally { signal.removeEventListener("abort", abort); }
      } catch (cause) {
        record("forward:failed");
        throw new ForwardError(phase, cause, progress);
      }
      finally { scope.clear(); if (stream && stream.status !== "closed" && stream.status !== "aborted") stream.abort(new Error("forward complete")); }
    },
  };
}
