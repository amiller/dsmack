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
export function createGuestPeer() {
  return createLibp2p({
    addresses: { listen: [] }, transports: [webSockets(), circuitRelayTransport()],
    connectionEncrypters: [noise()], streamMuxers: [yamux()], services: { identify: identify() },
  });
}
export class GuestSession {
  constructor({ api, cfg, credit, conversationId, discover, changed, repository, catalog, savedLease, workspace }) {
    Object.assign(this, { api, cfg, credit, conversationId, discover, changed, repository, catalog, savedLease, workspace });
  }
  tools() {
    return this.catalog.map(tool => ({
      name: tool.name, label: tool.name, description: tool.description,
      parameters: tool.inputSchema,
      execute: async (_id, args, signal, onUpdate) => {
        const client = await this.ensure(signal, tool.name === "bash" ? Number(args.timeout || this.environment?.commandTimeoutSeconds || 120) : 5);
        performance.mark("dsmack:tool:start", { detail: tool.name });
        const result = await client.callTool({ name: tool.name, arguments: args }, {
          signal, timeout: this.environment.commandTimeoutSeconds * 1000 + 15000,
          onprogress: p => {
            if (p.message) onUpdate?.({ content: [{ type: "text", text: p.message }], details: { progress: p.progress } });
          },
        });
        performance.mark("dsmack:tool:end", { detail: tool.name });
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
  async ensure(signal, commandSeconds = 120) {
    if (!this.opening) this.opening = (async () => {
      let moved = false;
      await this.restore();
      if (this.lease) await this.status();
      const cutoff = Number(this.lease?.handoverAt || this.node?.registration.admit_until || 0) * 1000;
      if (this.lease && (!this.client || (cutoff && cutoff <= Date.now() + (Math.min(120, commandSeconds) + 5) * 1000))) {
        performance.mark("dsmack:handover:start");
        moved = true;
        this.changed({ state: "handover", lease: this.lease, node: this.node?.registration });
        await this.end();
        await this.waitForRelease(signal);
      }
      if (this.client) return this.client;
      const client = await this.open(signal);
      if (moved) performance.mark("dsmack:handover:ready");
      return client;
    })().catch(async e => {
      // Admission failures can leave an unused claim. Never retry a tool whose
      // result was lost: its edits may already be present in the saved version.
      await this.end().catch(() => {});
      throw e;
    }).finally(() => { this.opening = null; });
    return this.opening;
  }
  async waitForRelease(signal) {
    const deadline = Date.now() + 150000;
    while (this.lease) {
      signal?.throwIfAborted();
      require(Date.now() < deadline, "The guest is still saving its workspace. Retry when it has released.");
      await new Promise(resolve => setTimeout(resolve, 500));
      await this.status();
    }
  }
  async open(signal) {
    performance.mark("dsmack:guest:start");
    this.changed({ state: "verifying" });
    const head = await this.workspace.latest();
    const deadline = Date.now() + 90000, exclude = new Set();
    this.workspaceReady = false;
    const peer = await createGuestPeer();
    this.peer = peer;
    const verified = await this.discover({ peer, wait: true, deadline, exclude, signal, workspace: head,
      claim: async selected => {
        // Claim capacity before expensive verification to avoid four browsers
        // all attesting the first guest. Only verified guests receive MCP/data.
        performance.mark("dsmack:grant:start", { detail: selected.relay_peer });
        this.lease = await this.api("/agent/open", await walletBody(this.credit, "agent-open", {
          conversationId: this.conversationId, client_peer: peer.peerId.toString(), node_peer: selected.relay_peer,
        }), { signal });
        performance.mark("dsmack:grant:end", { detail: this.lease.sessionId });
        return async () => {
          const result = await this.api("/agent/end", await walletBody(this.credit, "agent-end", { sessionId: this.lease.sessionId }));
          require(!result.active, "Unverified guest grant could not be released.");
          if (result.credit) this.credit.chatCredit = result.credit;
          this.lease = null;
        };
      },
    });
    this.node = verified;
    this.changed({ state: "connecting", lease: this.lease, node: verified.registration });
    performance.mark("dsmack:tunnels:start");
    let tunnelEntries = verified.chainTunnels;
    if (!tunnelEntries) {
      const response = await fetch(this.cfg.tunnels || this.cfg.broker + "/tunnels", { signal, redirect: "error", cache: "no-store" });
      require(response.ok, "Guest relay discovery through the broker failed (HTTP " + response.status + "). Directory: broker.");
      tunnelEntries = await response.json();
    }
    const measured = JSON.parse(new TextDecoder().decode(verified.policy.manifest));
    const relayPeer = JSON.parse(measured.docker_compose_file).services.node.command[1].split("/").at(-1);
    const entries = tunnelEntries.map(tunnel).filter(t =>
      t.relayPeer === relayPeer && (!t.guestPeer || t.guestPeer === verified.registration.relay_peer) &&
      t.expiresAt * 1000 > Date.now()
    ).map(t => ({ ...t, guestPeer: verified.registration.relay_peer }));
    performance.mark("dsmack:tunnels:end");
    require(entries.length, "No live browser relay advertises the verified guest.");
    performance.mark("dsmack:dial:start");
    let connection = verified.connection, failure;
    for (const entry of connection ? [] : entries) {
      try { connection = await connecting(20000, signal, scoped => peer.dial(multiaddr(address(entry)), { signal: scoped })); break; }
      catch (e) { failure = e; }
    }
    if (!connection) throw failure;
    require(connection.remotePeer.toString() === verified.registration.relay_peer, "Noise peer differs from attested guest.");
    performance.mark("dsmack:dial:end");
    performance.mark("dsmack:mcp:start");
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
    performance.mark("dsmack:mcp:ready");
    // A prior stay can finish sealing while this browser waits for admission.
    // Read its final head before releasing a workspace key to the next guest.
    await this.workspace.latest();
    const restored = await this.workspace.bind(client, verified.registration, this.lease);
    if (!restored) {
      for (const [path, content] of this.repository()) {
        const written = await client.callTool({ name: "write", arguments: { path, content } }, { signal });
        require(!written.isError, "Repository import failed: " + JSON.stringify(written.content));
      }
      const baseline = await client.callTool({ name: "bash", arguments: { command: "git add --all && git -c user.name=Dsmack -c user.email=agent@dsmack.invalid commit -qm 'Imported repository' --allow-empty" } }, { signal });
      require(!baseline.isError, "Repository baseline failed: " + JSON.stringify(baseline.content));
    }
    this.workspaceReady = true;
    this.lastActivity = Date.now();
    await this.status();
    this.poll = setInterval(() => this.status().catch(e => this.changed({ state: "error", error: e.message })), 10000);
    return client;
  }
  async status() {
    if (!this.lease) return;
    const sessionId = this.lease.sessionId;
    const result = await this.api("/agent/status", await walletBody(this.credit, "agent-status", { sessionId }));
    if (this.lease?.sessionId !== sessionId) return result;
    Object.assign(this.lease, { handoverAt: result.handoverAt, seconds: result.seconds, grant: result.grant });
    if (result.credit) this.credit.chatCredit = result.credit;
    const sealing = result.usageUnresolved || (result.active && (result.endRequested || result.stopReason ||
      result.handoverAt * 1000 <= Date.now()));
    this.changed({ ...result, state: sealing ? "sealing" : result.active ? (this.client ? "held" : "disconnected-held") : "released", lease: this.lease, node: this.node?.registration, environment: this.environment });
    if (!result.active && !result.usageUnresolved) {
      clearInterval(this.poll);
      await this.client?.close(); this.client = null;
      await this.peer?.stop(); this.peer = null;
      this.lease = null;
      this.savedLease = null;
      this.workspaceReady = false;
      await this.workspace.latest();
    }
    return result;
  }
  async patch() {
    require(this.client, "Run a tool in this conversation before downloading its patch.");
    const result = await this.client.readResource({ uri: "dsmack://workspace/patch" });
    const content = result.contents[0];
    return content.blob ? Uint8Array.from(atob(content.blob), c => c.charCodeAt(0)) : encoder.encode(content.text);
  }
  async save() {
    require(this.client && this.workspaceReady, "Run a tool in this conversation before saving its workspace.");
    return this.workspace.save(this.client, this.lease);
  }
  async end() {
    if (this.client && this.workspaceReady) await this.save();
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
      if (!result.active && !result.usageUnresolved) {
        this.lease = null; this.savedLease = null; this.workspaceReady = false;
        await this.workspace.latest();
      }
      else this.poll = setInterval(() => this.status().catch(e => this.changed({ state: "error", error: e.message })), 5000);
    }
  }
}
