import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve, join } from "node:path";
import { createConnection } from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import { createLibp2p } from "libp2p";
import { webSockets } from "@libp2p/websockets";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { identify } from "@libp2p/identify";

const here = dirname(fileURLToPath(import.meta.url));
const temporary = await mkdtemp(join(tmpdir(), "dsmack-reconnect-"));
await symlink(resolve(here, "node_modules"), join(temporary, "node_modules"));
const bundled = join(temporary, "agent-tools.mjs");
await build({ entryPoints: [resolve(here, "agent-tools.mjs")], outfile: bundled,
  bundle: true, platform: "node", format: "esm", packages: "external",
  alias: { "@sandbox": resolve(here, "../compute-node/browser/sandbox.mjs"), "npm:ethers@6.17.0": "ethers" }, logLevel: "silent" });
const { GuestSession } = await import(pathToFileURL(bundled));
const modulePath = process.env.DSMACK_AGENT_MCP_MODULE || resolve(here, "../compute-node/agent-mcp.mjs");
const { listen } = await import(pathToFileURL(modulePath));
const { toolCatalog } = await import(new URL("./pi-tools.mjs", pathToFileURL(modulePath)));
test.after(() => rm(temporary, { recursive: true, force: true }));
const encoder = new TextEncoder();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

test("end tells the broker to release the stay before closing its retained MCP stream", async () => {
  let ended = false, saved = false, closed = false;
  const session = new GuestSession({ cfg: {}, conversationId: "ending",
    credit: { address: "public-wallet", signer: { signMessage: async () => "signature" } },
    changed: () => {}, workspace: { save: async () => { saved = true; }, latest: async () => null },
    api: async path => {
      assert.equal(path, "/agent/end"); assert(saved); assert(!closed);
      ended = true; return { active: false };
    },
  });
  session.lease = { sessionId: "held-stay" };
  session.workspaceReady = true;
  session.client = { close: async () => {
    assert(ended, "the guest retains its MCP stream until the broker ends the stay");
    closed = true;
  } };
  session.peer = { stop: async () => { assert(closed); } };
  await session.end();
  assert.equal(session.lease, null); assert.equal(session.client, null);
});

async function readAdmission(stream) {
  const iterator = stream[Symbol.asyncIterator]();
  let bytes = new Uint8Array();
  for (;;) {
    if (bytes.length >= 4) {
      const length = new DataView(bytes.buffer).getUint32(0);
      if (bytes.length >= length + 4) return {
        request: JSON.parse(new TextDecoder().decode(bytes.subarray(4, length + 4))),
        iterator, initial: bytes.slice(length + 4),
      };
    }
    const next = await iterator.next(); assert(!next.done);
    bytes = new Uint8Array([...bytes, ...next.value.subarray()]);
  }
}

test("a broken Noise stream resumes the same grant without restoring or replaying a real Bash call", { timeout: 30000 }, async () => {
  const root = await mkdtemp(join(temporary, "workspace-"));
  const socket = join(temporary, "agent.sock"), listener = await listen({ root, socket });
  const remote = await createLibp2p({ addresses: { listen: ["/ip4/127.0.0.1/tcp/0/ws"] },
    transports: [webSockets()], connectionEncrypters: [noise()], streamMuxers: [yamux()], services: { identify: identify() } });
  const admissions = [], sockets = new Set(), events = [], apiPaths = [];
  let session, firstConnection, binds = 0, discoveries = 0, reverifications = 0;
  await remote.handle("/dsmack/agent-mcp/1.0.0", async stream => {
    const framed = await readAdmission(stream); admissions.push(framed.request);
    assert.equal(framed.request.job_id, "one-stay");
    assert.deepEqual(framed.request.grant, { fixture: "one-signed-grant" });
    assert.equal(!!framed.request.resume, admissions.length > 1);
    assert(remote.getConnections().some(c => c.remotePeer.toString() === session.peer.peerId.toString()));
    const body = encoder.encode(JSON.stringify({ status: "ready", ...(framed.request.resume ? { resumed: true } : {}) }));
    const ack = new Uint8Array(body.length + 4); new DataView(ack.buffer).setUint32(0, body.length); ack.set(body, 4); stream.send(ack);
    const local = createConnection(socket); sockets.add(local);
    local.on("error", () => {});
    local.on("data", bytes => stream.send(bytes));
    local.on("close", () => { sockets.delete(local); stream.close().catch(() => {}); });
    try {
      await new Promise((done, reject) => { local.once("connect", done); local.once("error", reject); });
      if (framed.initial.length) local.write(framed.initial);
      for (;;) {
        const next = await framed.iterator.next();
        if (next.done) break;
        local.write(next.value.subarray());
      }
    } catch { /* The regression deliberately breaks the actual Noise connection. */ }
    finally { local.destroy(); }
  });
  const peer = remote.peerId.toString();
  const registration = { relay_peer: peer, admit_until: Math.floor(Date.now() / 1000) + 600,
    attestation: { run: "same-measured-run" }, payments: { runId: "same-run-id" }, receipt_key: "same-receipt-key", secret_key: "same-attested-key" };
  const lease = { sessionId: "one-stay", seconds: 600, handoverAt: registration.admit_until, grant: { fixture: "one-signed-grant" } };
  const verified = connection => ({ registration, connection,
    policy: { manifest: encoder.encode(JSON.stringify({ docker_compose_file: JSON.stringify({ services: { node: { command: ["serve", "/p2p/" + peer] } } }) })) },
    chainTunnels: [{ url: "wss://reconnect-fixture.trycloudflare.com/", relayPeer: peer, guestPeer: peer, expiresAt: registration.admit_until }] });
  session = new GuestSession({ cfg: {}, credit: { address: "public-wallet", signer: { signMessage: async () => "fixture-signature" } }, conversationId: "conversation",
    catalog: toolCatalog(), repository: () => [], changed: value => { session.statusSnapshot = value; events.push(value.state); },
    workspace: { latest: async () => null, bind: async () => { binds++; return true; }, save: async () => { throw Error("Reconnect must not save or restore"); } },
    api: async path => { apiPaths.push(path); if (path === "/agent/open") return structuredClone(lease); assert.equal(path, "/agent/status"); return { ...lease, active: true, guestSeconds: 1 }; },
    discover: async ({ peer: browser, claim }) => { discoveries++; await claim(registration); firstConnection = await browser.dial(remote.getMultiaddrs()[0]); return verified(firstConnection); },
    reverify: async ({ registration: previous }) => { reverifications++; assert.equal(previous, registration); return verified(await session.peer.dial(remote.getMultiaddrs()[0])); },
  });
  try {
    const bash = session.tools().find(t => t.name === "bash");
    const interrupted = bash.execute("interrupted", { command: "printf 'once\\n' >> counter; printf started > started; sleep 10; printf NEVER", timeout: 15 });
    let interruption;
    const failed = assert.rejects(interrupted, error => { interruption = error; return true; });
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) { if (await readFile(join(root, "started"), "utf8").catch(() => "") === "started") break; await pause(10); }
    assert.equal(await readFile(join(root, "started"), "utf8").catch(() => ""), "started", interruption?.stack);
    firstConnection.abort(new Error("actual connection lost during command"));
    await failed;
    assert.equal(session.client, null);
    assert.equal(admissions.length, 1, "Interrupted calls are never reissued");
    const restored = await bash.execute("new-call", { command: "cat counter; printf SAME_STAY_OK", timeout: 2 });
    assert(!restored.isError);
    assert.equal(restored.content.find(x => x.type === "text").text, "once\nSAME_STAY_OK");
    assert.equal(session.lease.sessionId, lease.sessionId);
    assert.equal(admissions.length, 2); assert.equal(discoveries, 1); assert.equal(reverifications, 1); assert.equal(binds, 1);
    assert.equal(apiPaths.filter(p => p === "/agent/open").length, 1);
    assert(!apiPaths.includes("/agent/end")); assert(events.includes("reconnecting"));
    await session.client.close();
    session.reverify = async () => ({ ...verified(undefined), registration: { ...registration, payments: { runId: "different-run" } } });
    await assert.rejects(bash.execute("wrong-run", { command: "printf MUST_NOT_RUN", timeout: 1 }), /differs from the existing attested stay/);
    assert.equal(admissions.length, 2, "A different attested run must not receive MCP admission or private data");
    assert(!apiPaths.includes("/agent/end"), "Failed reconnect preserves the existing bounded stay");
  } finally {
    clearInterval(session.poll); await session.client?.close().catch(() => {}); await session.peer?.stop();
    for (const socket of sockets) socket.destroy();
    await new Promise(done => listener.close(done)); await remote.stop();
  }
});


test("a failed broker status read cannot hide a completed command or run it twice", async () => {
  let commands = 0;
  const changes = [];
  const session = new GuestSession({ catalog: [{ name: "bash", description: "bash", inputSchema: {} }], changed: change => changes.push(change) });
  session.node = { policy: {} }; session.environment = { commandTimeoutSeconds: 120 };
  session.ensure = async () => ({ callTool: async () => { commands++; return { content: [{ type: "text", text: "completed command" }] }; } });
  session.status = async () => { throw new TypeError("Failed to fetch"); };
  const result = await session.tools()[0].execute("call", { command: "echo completed" });
  assert.equal(commands, 1);
  assert.equal(result.content[0].text, "completed command");
  assert.match(changes[0].error, /browser lost its connection/);
});

test("a failed guest connection invalidates its chain directory before the next attempt", async () => {
  let invalidated = 0;
  const session = new GuestSession({});
  const error = Error("guest disconnected");
  session.connectGuest = async () => { throw error; };
  await assert.rejects(session.connect({ invalidateDirectory: () => invalidated++ }), value => value === error);
  assert.equal(invalidated, 1);
});


test("a browser failure before Bash starts names the browser connection instead of returning bare Failed to fetch", async () => {
  const session = new GuestSession({ catalog: [{ name: "bash", description: "bash", inputSchema: {} }] });
  session.ensure = async () => { throw new TypeError("Failed to fetch"); };
  await assert.rejects(session.tools()[0].execute("call", { command: "echo completed" }), /browser lost its connection.*background/);
});

test("user-key guest tool calls retain PromptGuard preflight and complete assistant response", async () => {
  const calls = [], assistant = { role: "assistant", provider: "anthropic", content: [
    { type: "text", text: "Read the requested file." },
    { type: "toolCall", id: "read-one", name: "read", arguments: { path: "note.txt" } },
  ] };
  const session = new GuestSession({ catalog: [{ name: "read", description: "Read", inputSchema: { type: "object" } }] });
  session.node = { policy: { monitor: { name: "baseline-pg2" } } };
  session.environment = { commandTimeoutSeconds: 120 };
  session.record = { agent: { state: { model: { provider: "anthropic" }, messages: [assistant] } } };
  session.ensure = async () => ({ callTool: async call => { calls.push(call); return { content: [{ type: "text", text: "File contents" }] }; } });
  session.status = async () => {};
  const manifest = encoder.encode(JSON.stringify({ docker_compose_file: JSON.stringify({ services: { node: {
    environment: { DSMACK_MONITOR_POLICY: JSON.stringify({ name: "baseline-pg2" }) },
  } } }) }));
  await session.preflight({ messages: [{ role: "user", content: "Inspect my file." }] }, undefined, manifest);
  for (let i = 0; i < 2; i++) await session.tools()[0].execute("read-" + i, { path: "note.txt" });
  assert.equal(calls.filter(call => call.name === "dsmack_monitor").length, 3);
  for (const call of calls.filter(call => call.name === "read"))
    assert.equal(call._meta["dsmack/monitorResponse"], JSON.stringify(assistant.content));
});
