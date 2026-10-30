import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { PassThrough } from "node:stream";
import { Client } from "@modelcontextprotocol/client";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createAgentServer, createWorkspaceTools, initializeWorkspace, workspacePath } from "./agent-mcp.mjs";
import { toolCatalog } from "./pi-tools.mjs";
import { WorkspaceSnapshots, WORKSPACE_CHUNK_BYTES } from "./workspace.mjs";
import { randomBytes } from "node:crypto";
const testTmp = tmpdir();

async function workspace(t) {
  const root = await mkdtemp(resolve(testTmp, "dsmack-agent-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await initializeWorkspace(root);
  return root;
}

test("file operations reject paths and symlinks outside the workspace", async (t) => {
  const root = await workspace(t);
  await symlink("/etc", resolve(root, "escape"));
  await assert.rejects(workspacePath(root, "/etc/passwd"), /outside/);
  await assert.rejects(workspacePath(root, resolve(root, "escape/passwd")), /Symlink escapes/);
  await assert.rejects(workspacePath(root, resolve(root, "escape/new/file")), /Symlink escapes/);
  const tools = createWorkspaceTools(root);
  await assert.rejects(tools.find((tool) => tool.name === "read").execute("read", { path: "escape/passwd" }), /Symlink escapes/);
});

test("MCP 2026 discovery, pi tools, progress and patch preserve real execution", async (t) => {
  const root = await workspace(t);
  const toServer = new PassThrough(), fromServer = new PassThrough();
  const handle = serveStdio(() => createAgentServer(root), { transport: new StdioServerTransport(toServer, fromServer), legacy: "reject" });
  const client = new Client({ name: "agent-boundary-test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StdioServerTransport(fromServer, toServer);
  t.after(async () => { await client.close(); await handle.close(); });
  await client.connect(transport);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })), toolCatalog().map(({ label, ...tool }) => tool));
  await client.callTool({ name: "write", arguments: { path: "hello.js", content: 'console.log("before");\n' } });
  const changed = await client.callTool({ name: "edit", arguments: { path: "hello.js", edits: [{ oldText: '"before"', newText: '"after"' }] } });
  assert.equal(changed.isError, undefined);
  const updates = [];
  const run = await client.callTool({ name: "bash", arguments: { command: "node hello.js; sleep 0.2; printf 'done\\n'" } }, { onprogress: (progress) => updates.push(progress) });
  assert.match(run.content[0].text, /after\ndone/);
  assert(updates.some((progress) => progress.message.includes("after")));
  const failed = await client.callTool({ name: "bash", arguments: { command: "printf 'script failed\\n'; exit 7" } });
  assert.equal(failed.isError, true);
  assert.match(failed.content[0].text, /script failed/);
  assert.match(failed.content[0].text, /code 7/);
  const patch = await client.readResource({ uri: "dsmack://workspace/patch" });
  const diff = Buffer.from(patch.contents[0].blob, "base64").toString();
  assert.match(diff, /new file mode/); assert.match(diff, /console.log\("after"\)/);
  const escaped = await client.callTool({ name: "write", arguments: { path: "/etc/escape", content: "no" } });
  assert.equal(escaped.isError, true); assert.match(escaped.content[0].text, /outside/);
  const timed = await client.callTool({ name: "bash", arguments: { command: "sleep 30", timeout: 0.1 } });
  assert.equal(timed.isError, true); assert.match(timed.content[0].text, /timed out|timeout/i);
  const env = await client.readResource({ uri: "dsmack://environment" });
  assert.equal(JSON.parse(env.contents[0].text).commandTimeoutSeconds, 120);
});

test("bash terminates raw output floods", async (t) => {
  const root = await workspace(t);
  const [bash] = createWorkspaceTools(root);
  await assert.rejects(bash.execute("bash", { command: "yes flood" }), /output limit/);
});


test("workspace keys and pending saves survive a browser MCP connection closing", async (t) => {
  const root = await workspace(t), snapshots = new WorkspaceSnapshots(root);
  async function connection() {
    const toServer = new PassThrough(), fromServer = new PassThrough();
    const handle = serveStdio(() => createAgentServer(root, { snapshots }), { transport: new StdioServerTransport(toServer, fromServer), legacy: "reject" });
    const client = new Client({ name: "workspace-reconnect-test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StdioServerTransport(fromServer, toServer));
    return { client, close: async () => { await client.close(); await handle.close(); } };
  }
  const first = await connection();
  await first.client.callTool({ name: "dsmack_workspace", arguments: { operation: "bind", workspaceId: "conversation-reconnect", key: "ab".repeat(32), head: null } });
  await first.client.callTool({ name: "write", arguments: { path: "survives.txt", content: "browser closed" } });
  await writeFile(resolve(root, "transfer.bin"), randomBytes(800000));
  await first.close();
  const internal = await connection();
  try {
    const saved = await internal.client.callTool({ name: "dsmack_workspace", arguments: { operation: "seal" } });
    assert.equal(saved.structuredContent.version, 1);
    const repeated = await internal.client.callTool({ name: "dsmack_workspace", arguments: { operation: "seal" } });
    assert.deepEqual(repeated.structuredContent, saved.structuredContent);
    const chunk = await internal.client.callTool({ name: "dsmack_workspace", arguments: { operation: "read", offset: 0 } });
    assert.equal(Buffer.from(chunk.structuredContent.data, "base64").length, WORKSPACE_CHUNK_BYTES);
    assert(Buffer.byteLength(JSON.stringify(chunk)) < 1024 * 1024, "A 512 KiB snapshot chunk must fit the native MCP frame");
    await internal.client.callTool({ name: "dsmack_workspace", arguments: { operation: "commit", head: { ...saved.structuredContent, cid: "stored", mac: "mac" } } });
    const later = await internal.client.callTool({ name: "dsmack_workspace", arguments: { operation: "seal" } });
    assert.equal(later.structuredContent.version, 2);
  } finally { await internal.close(); }
});


test("downloading a patch keeps tracked and staged build sources while snapshots exclude intent-only build output", async (t) => {
  const root = await workspace(t), next = await workspace(t);
  const toServer = new PassThrough(), fromServer = new PassThrough();
  const handle = serveStdio(() => createAgentServer(root), { transport: new StdioServerTransport(toServer, fromServer), legacy: "reject" });
  const client = new Client({ name: "patch-snapshot-test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  t.after(async () => { await client.close(); await handle.close(); });
  await client.connect(new StdioServerTransport(fromServer, toServer));
  const tool = (name, args) => client.callTool({ name, arguments: args });
  await tool("write", { path: "src/build/tracked.py", content: "tracked source" });
  const committed = await tool("bash", { command: "git add src/build/tracked.py && git -c user.name=Test -c user.email=test@invalid commit -qm 'Track build source'" });
  assert(!committed.isError);
  await tool("write", { path: "src/build/staged.py", content: "staged source" });
  const staged = await tool("bash", { command: "git add src/build/staged.py" });
  assert(!staged.isError);
  await tool("write", { path: "src/build/generated.bin", content: "generated output" });
  const patch = await client.readResource({ uri: "dsmack://workspace/patch" });
  assert.match(Buffer.from(patch.contents[0].blob, "base64").toString(), /src\/build\/generated.bin/);
  const workspaceId = "patch-snapshot", key = "ab".repeat(32);
  await tool("dsmack_workspace", { operation: "bind", workspaceId, key, head: null });
  const saved = (await tool("dsmack_workspace", { operation: "seal" })).structuredContent;
  const chunk = (await tool("dsmack_workspace", { operation: "read", offset: 0 })).structuredContent;
  assert(chunk.eof);
  const restored = new WorkspaceSnapshots(next);
  await restored.call({ operation: "bind", workspaceId, key, head: saved });
  await restored.call({ operation: "write", offset: 0, data: chunk.data });
  await restored.call({ operation: "restore" });
  assert.equal(await readFile(resolve(next, "src/build/tracked.py"), "utf8"), "tracked source");
  assert.equal(await readFile(resolve(next, "src/build/staged.py"), "utf8"), "staged source");
  await assert.rejects(access(resolve(next, "src/build/generated.bin")), { code: "ENOENT" });
});
