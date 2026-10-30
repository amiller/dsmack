import { Client, parseJSONRPCMessage, serializeMessage } from "@modelcontextprotocol/client";
import { createLibp2p } from "libp2p";
import { webSockets } from "@libp2p/websockets";
import { circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { identify } from "@libp2p/identify";
import { multiaddr } from "@multiformats/multiaddr";
import { tunnel, address } from "../browser-p2p/tunnels.mjs";
import { require, walletBody } from "./credit.mjs";

const encoder = new TextEncoder();
const MAX_FRAME = 8 * 1024 * 1024;
// A completed dial must not leave a timer or caller signal attached to the
// conversation's cached connection. Tool cancellation belongs to MCP calls.
async function connecting(milliseconds, signal, operation) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("Guest connection timed out.")), milliseconds);
  const abort = () => controller.abort(signal.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  try { return await operation(controller.signal); }
  finally { clearTimeout(timeout); signal?.removeEventListener("abort", abort); }
}
// MCP 2026-07-28 custom transport: a shared reliable libp2p Noise byte
// stream, using the specification's stdio NDJSON framing and cancellation.
export class Libp2pMcpTransport {
  constructor(stream, iterator, initial = new Uint8Array()) {
    this.stream = stream;
    this.iterator = iterator;
    this.initial = initial;
  }
  async start() {
    this.reading = this.read();
  }
  async read() {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let pending = "";
    try {
      let value = this.initial;
      for (;;) {
        pending += decoder.decode(value, { stream: true });
        require(encoder.encode(pending).length <= MAX_FRAME, "Guest MCP message exceeds output cap.");
        let at;
        while ((at = pending.indexOf("\n")) >= 0) {
          const line = pending.slice(0, at);
          pending = pending.slice(at + 1);
          if (line) this.onmessage?.(parseJSONRPCMessage(JSON.parse(line)));
        }
        const next = await this.iterator.next();
        if (next.done) break;
        value = next.value.subarray();
      }
      pending += decoder.decode();
      require(!pending.trim(), "Guest MCP stream ended with an incomplete message.");
    } catch (e) {
      if (!this.closed) this.onerror?.(e);
    } finally {
      this.closed = true;
      this.onclose?.();
    }
  }
  async send(message) {
    require(!this.closed, "Guest connection has closed.");
    const data = encoder.encode(serializeMessage(message));
    require(data.length <= MAX_FRAME, "MCP request exceeds input cap.");
    if (!this.stream.send(data)) await this.stream.onDrain();
  }
  async close() {
    if (this.closed) return;
    this.closed = true;
    await this.stream.close();
    this.onclose?.();
  }
}
async function admission(stream, session) {
  const payload = encoder.encode(JSON.stringify({ job_id: session.sessionId, grant: session.grant }));
  const frame = new Uint8Array(payload.length + 4);
  new DataView(frame.buffer).setUint32(0, payload.length);
  frame.set(payload, 4);
  stream.send(frame);
  const iterator = stream[Symbol.asyncIterator]();
  let pending = new Uint8Array();
  for (;;) {
    if (pending.length >= 4) {
      const size = new DataView(pending.buffer, pending.byteOffset).getUint32(0);
      require(size <= 65536, "Guest admission response exceeds limit.");
      if (pending.length >= size + 4) {
        const result = JSON.parse(new TextDecoder().decode(pending.subarray(4, size + 4)));
        require(result.status === "ready", "Guest refused session: " + (result.error || result.status));
        return { iterator, initial: pending.slice(size + 4) };
      }
    }
    const next = await iterator.next();
    require(!next.done, "Guest closed before session admission.");
    const data = next.value.subarray(), joined = new Uint8Array(pending.length + data.length);
    joined.set(pending); joined.set(data, pending.length); pending = joined;
  }
}
export class GuestSession {
  constructor({ api, cfg, credit, conversationId, discover, changed, repository, catalog, savedLease }) {
    Object.assign(this, { api, cfg, credit, conversationId, discover, changed, repository, catalog, savedLease });
  }
  tools() {
    return this.catalog.map(tool => ({
      name: tool.name, label: tool.name, description: tool.description,
      parameters: tool.inputSchema,
      execute: async (_id, args, signal, onUpdate) => {
        const client = await this.ensure(signal);
        const result = await client.callTool({ name: tool.name, arguments: args }, {
          signal, timeout: this.environment.commandTimeoutSeconds * 1000 + 15000,
          onprogress: p => {
            if (p.message) onUpdate?.({ content: [{ type: "text", text: p.message }], details: { progress: p.progress } });
          },
        });
        this.lastActivity = Date.now();
        await this.status();
        return { content: result.content, isError: !!result.isError, details: result._meta?.["dsmack/piDetails"] || result.structuredContent || {} };
      },
    }));
  }
  async restore() {
    const saved = this.savedLease;
    if (!saved?.active || this.lease || !this.credit.signer) return;
    require(saved.wallet === this.credit.address.toLowerCase(), "This conversation’s held guest belongs to another wallet. Connect its owner to end the session.");
    require(saved.conversationId === this.conversationId, "Saved guest belongs to another conversation.");
    this.lease = { sessionId: saved.sessionId };
    this.node = { registration: saved.node };
    this.environment = saved.environment;
    await this.status();
    if (this.lease) this.poll = setInterval(() => this.status().catch(e => this.changed({ state: "disconnected-held", lease: this.lease, node: this.node?.registration, active: true, error: e.message })), 10000);
  }
  async ensure(signal) {
    await this.restore();
    require(!this.lease || this.client, "This conversation still holds a disconnected guest. Choose End session before starting a fresh workspace.");
    if (this.client) return this.client;
    if (!this.opening) this.opening = this.open(signal).catch(async e => {
      await this.end().catch(() => {});
      throw e;
    }).finally(() => { this.opening = null; });
    return this.opening;
  }
  async open(signal) {
    this.changed({ state: "verifying" });
    const verified = await this.discover({ wait: true });
    this.node = verified;
    const peer = await createLibp2p({
      addresses: { listen: [] }, transports: [webSockets(), circuitRelayTransport()],
      connectionEncrypters: [noise()], streamMuxers: [yamux()], services: { identify: identify() },
    });
    this.peer = peer;
    this.lease = await this.api("/agent/open", await walletBody(this.credit, "agent-open", {
      conversationId: this.conversationId, client_peer: peer.peerId.toString(), node_peer: verified.registration.relay_peer,
    }), { signal });
    this.changed({ state: "connecting", lease: this.lease, node: verified.registration });
    const response = await fetch(this.cfg.tunnels || this.cfg.broker + "/tunnels", { signal, redirect: "error", cache: "no-store" });
    require(response.ok, "Guest relay discovery failed: HTTP " + response.status);
    const measured = JSON.parse(new TextDecoder().decode(verified.policy.manifest));
    const relayPeer = JSON.parse(measured.docker_compose_file).services.node.command[1].split("/").at(-1);
    const entries = (await response.json()).map(tunnel).filter(t =>
      t.relayPeer === relayPeer && (!t.guestPeer || t.guestPeer === verified.registration.relay_peer) &&
      t.expiresAt * 1000 > Date.now()
    ).map(t => ({ ...t, guestPeer: verified.registration.relay_peer }));
    require(entries.length, "No live browser relay advertises the verified guest.");
    let connection, failure;
    for (const entry of entries) {
      try { connection = await connecting(20000, signal, scoped => peer.dial(multiaddr(address(entry)), { signal: scoped })); break; }
      catch (e) { failure = e; }
    }
    if (!connection) throw failure;
    require(connection.remotePeer.toString() === verified.registration.relay_peer, "Noise peer differs from attested guest.");
    const stream = await connecting(30000, signal, scoped => connection.newStream("/dsmack/agent-mcp/1.0.0", { runOnLimitedConnection: true, signal: scoped }));
    stream.inactivityTimeout = Math.max(330000, this.lease.seconds * 1000 + 15000);
    const admissionTimer = setTimeout(() => stream.abort(new Error("Guest session admission timed out.")), 30000);
    let framed;
    try { framed = await admission(stream, this.lease); }
    finally { clearTimeout(admissionTimer); }
    const transport = new Libp2pMcpTransport(stream, framed.iterator, framed.initial);
    const client = new Client({ name: "dsmack-private-agent", version: "1" }, {
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      supportedProtocolVersions: ["2026-07-28"],
    });
    transport.onclose = () => {
      this.client = null;
      if (this.lease && this.statusSnapshot?.active !== false) this.changed({ state: "disconnected-held", active: true, lease: this.lease, node: this.node?.registration });
    };
    await client.connect(transport);
    const { tools } = await client.listTools();
    const expected = new Map(this.catalog.map(t => [t.name, t]));
    require(tools.length === expected.size && tools.every(t => expected.has(t.name) && t.description === expected.get(t.name).description && JSON.stringify(t.inputSchema) === JSON.stringify(expected.get(t.name).inputSchema)), "Guest tools differ from the page's Pi tool definitions.");
    const env = await client.readResource({ uri: "dsmack://environment" });
    this.environment = JSON.parse(env.contents[0].text);
    this.client = client;
    for (const [path, content] of this.repository()) {
      const written = await client.callTool({ name: "write", arguments: { path, content } }, { signal });
      require(!written.isError, "Repository import failed: " + JSON.stringify(written.content));
    }
    const baseline = await client.callTool({ name: "bash", arguments: { command: "git add --all && git -c user.name=Dsmack -c user.email=agent@dsmack.invalid commit -qm 'Imported repository' --allow-empty" } }, { signal });
    require(!baseline.isError, "Repository baseline failed: " + JSON.stringify(baseline.content));
    this.lastActivity = Date.now();
    await this.status();
    this.poll = setInterval(() => this.status().catch(e => this.changed({ state: "error", error: e.message })), 10000);
    return client;
  }
  async status() {
    if (!this.lease) return;
    const result = await this.api("/agent/status", await walletBody(this.credit, "agent-status", { sessionId: this.lease.sessionId }));
    if (result.credit) this.credit.chatCredit = result.credit;
    this.changed({ ...result, state: result.active ? (this.client ? "held" : "disconnected-held") : "released", lease: this.lease, node: this.node?.registration, environment: this.environment });
    if (!result.active) {
      clearInterval(this.poll);
      await this.client?.close(); this.client = null;
      await this.peer?.stop(); this.peer = null;
      this.lease = null;
      this.savedLease = null;
    }
    return result;
  }
  async patch() {
    require(this.client, "Run a tool in this conversation before downloading its patch.");
    const result = await this.client.readResource({ uri: "dsmack://workspace/patch" });
    const content = result.contents[0];
    return content.blob ? Uint8Array.from(atob(content.blob), c => c.charCodeAt(0)) : encoder.encode(content.text);
  }
  async end() {
    clearInterval(this.poll);
    await this.client?.close(); this.client = null;
    await this.peer?.stop(); this.peer = null;
    if (this.lease) {
      let result = await this.api("/agent/end", await walletBody(this.credit, "agent-end", { sessionId: this.lease.sessionId }));
      for (let attempt = 0; result.active && attempt < 10; attempt++) {
        this.changed({ ...result, state: "ending", lease: this.lease });
        await new Promise(resolve => setTimeout(resolve, 500));
        result = await this.api("/agent/status", await walletBody(this.credit, "agent-status", { sessionId: this.lease.sessionId }));
      }
      if (result.credit) this.credit.chatCredit = result.credit;
      this.changed({ ...result, state: result.active ? "ending" : "released", lease: this.lease });
      if (!result.active) { this.lease = null; this.savedLease = null; }
      else this.poll = setInterval(() => this.status().catch(e => this.changed({ state: "error", error: e.message })), 5000);
    }
  }
}
