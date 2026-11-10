import test from "node:test";
import assert from "node:assert/strict";
import { createServer, connect } from "node:net";
import { PassThrough } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { browseForwarder, browsePolicy } from "./browse-forwarder.mjs";
import { browse, createAgentServer, initializeWorkspace } from "./agent-mcp.mjs";

// initializeWorkspace repoints TMPDIR into each test workspace; keep the original.
const testTmp = tmpdir();

// A stand-in operator proxy: records each request head and answers /browse with the policy for the token it was sent.
async function upstream(t, failures = 0) {
  const heads = [];
  const server = createServer((socket) => socket.once("data", (chunk) => {
    const head = chunk.toString("latin1").split("\r\n\r\n")[0];
    heads.push(head);
    if (head.startsWith("GET /browse") && failures > 0) { failures--; socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); }
    else if (head.startsWith("GET /browse")) {
      const auth = /Proxy-Authorization: Basic (\S+)/.exec(head)?.[1];
      const body = JSON.stringify(auth ? { mode: "named", hosts: ["shop.example"], token: Buffer.from(auth, "base64").toString() } : { mode: "none", hosts: [] });
      socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    } else socket.end("HTTP/1.1 200 Connection Established\r\n\r\ntunnel");
  }));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}`, heads };
}

const request = (port, text) => new Promise((done, fail) => {
  const socket = connect(port, "127.0.0.1", () => socket.write(text));
  let reply = ""; socket.on("data", (d) => { reply += d; }); socket.on("end", () => done(reply)); socket.on("error", fail);
});

test("forwarder replaces any client proxy credential with the stay's browse token", async (t) => {
  const up = await upstream(t);
  let token = null;
  const forwarder = await browseForwarder(up.url, () => token, 18481);
  t.after(() => forwarder.close());
  await request(18481, "CONNECT shop.example:443 HTTP/1.1\r\nProxy-Authorization: Basic Zm9yZ2Vk\r\n\r\n");
  assert.doesNotMatch(up.heads[0], /Proxy-Authorization/);
  token = "b".repeat(32);
  assert.match(await request(18481, "CONNECT shop.example:443 HTTP/1.1\r\nproxy-authorization: Basic Zm9yZ2Vk\r\n\r\n"), /tunnel/);
  assert.match(up.heads[1], new RegExp("Proxy-Authorization: Basic " + Buffer.from("browse:" + token).toString("base64")));
  assert.doesNotMatch(up.heads[1], /Zm9yZ2Vk/);
  assert.deepEqual(await browsePolicy(18481), { mode: "named", hosts: ["shop.example"], token: "browse:" + token });
});

test("a tools/call carrying dsmack/browse sets the token and the environment reports the proxy's policy", async (t) => {
  const up = await upstream(t);
  const forwarder = await browseForwarder(up.url, () => browse.token);
  t.after(() => forwarder.close());
  const root = await mkdtemp(resolve(testTmp, "browse-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await initializeWorkspace(root);
  const toServer = new PassThrough(), fromServer = new PassThrough();
  const handle = serveStdio(() => createAgentServer(root), { transport: new StdioServerTransport(toServer, fromServer), legacy: "reject" });
  const client = new Client({ name: "browse-test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  t.after(async () => { await client.close(); await handle.close(); });
  await client.connect(new StdioServerTransport(fromServer, toServer));
  const environment = async () => JSON.parse((await client.readResource({ uri: "dsmack://environment" })).contents[0].text).browse;
  assert.deepEqual(await environment(), { mode: "none", hosts: [] });
  await client.callTool({ name: "write", arguments: { path: "a.txt", content: "x" }, _meta: { "dsmack/browse": "not a token" } });
  assert.equal(browse.token, null);
  await client.callTool({ name: "write", arguments: { path: "a.txt", content: "x" }, _meta: { "dsmack/browse": "c".repeat(32) } });
  assert.equal(browse.token, "c".repeat(32));
  assert.deepEqual(await environment(), { mode: "named", hosts: ["shop.example"], token: "browse:" + "c".repeat(32) });
});

test("a failed policy fetch leaves the previous token, so the next call retries and the statement stays true", async (t) => {
  const up = await upstream(t, 1);
  const forwarder = await browseForwarder(up.url, () => browse.token, 18482);
  t.after(() => forwarder.close());
  const root = await mkdtemp(resolve(testTmp, "browse-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await initializeWorkspace(root);
  Object.assign(browse, { token: null, policy: { mode: "none", hosts: [] } });
  const toServer = new PassThrough(), fromServer = new PassThrough();
  const handle = serveStdio(() => createAgentServer(root, { browsePort: 18482 }), { transport: new StdioServerTransport(toServer, fromServer), legacy: "reject" });
  const client = new Client({ name: "browse-retry", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  t.after(async () => { await client.close(); await handle.close(); });
  await client.connect(new StdioServerTransport(fromServer, toServer));
  const call = () => client.callTool({ name: "write", arguments: { path: "a.txt", content: "x" }, _meta: { "dsmack/browse": "d".repeat(32) } });
  await assert.rejects(call(), /browse policy HTTP 403/);
  assert.equal(browse.token, null);
  await call();
  assert.equal(browse.token, "d".repeat(32));
  assert.equal(browse.policy.mode, "named");
});
