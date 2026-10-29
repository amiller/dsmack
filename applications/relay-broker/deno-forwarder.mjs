// In-process TCP/Noise/circuit-relay transport for the shared Deno broker.
// Only public admission data and secret-box ciphertext cross this transport.
import { createLibp2p } from "npm:libp2p@3.3.11";
import { tcp } from "npm:@libp2p/tcp@11.0.28";
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

export async function createDenoForwarder({ privateKey, logger } = {}) {
  const node = await createLibp2p({
    ...(privateKey ? { privateKey } : {}), ...(logger ? { logger } : {}),
    addresses: { listen: [] }, transports: [tcp({ outboundSocketInactivityTimeout: 905000 }), circuitRelayTransport()],
    connectionEncrypters: [noise()], streamMuxers: [yamux()],
    services: { identify: identify() },
    connectionManager: { minConnections: 0, dialTimeout: 25000, addressDialTimeout: 25000 },
  });
  return {
    peerId: node.peerId.toString(),
    stop: () => node.stop(),
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
