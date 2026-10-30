import { createServer } from "node:net";
import { access, chmod, chown, mkdir, readFile, realpath, unlink, writeFile } from "node:fs/promises";
import { constants, writeSync, closeSync } from "node:fs";
import { resolve, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { Server } from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { Value } from "typebox/value";
import { createBashTool, createReadTool, createWriteTool, createEditTool, toolCatalog, piVersion } from "./pi-tools.mjs";

export const COMMAND_TIMEOUT_SECONDS = 120;
export const OUTPUT_CAP_BYTES = 50 * 1024;
export const RAW_OUTPUT_CAP_BYTES = 1024 * 1024;
const exec = promisify(execFile);

export async function workspacePath(root, input) {
  const path = resolve(input);
  const within = (value) => value === root || (!relative(root, value).startsWith(`..${sep}`) && relative(root, value) !== ".." && !relative(root, value).startsWith(sep));
  if (!within(path)) throw new Error("Path is outside /workspace");
  let parent = path;
  while (true) {
    try {
      const physical = await realpath(parent);
      if (!within(physical)) throw new Error("Symlink escapes /workspace");
      break;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      parent = dirname(parent);
    }
  }
  return path;
}

export function createWorkspaceTools(root) {
  const safe = (path) => workspacePath(root, path);
  const read = {
    readFile: async (path) => readFile(await safe(path)),
    access: async (path) => access(await safe(path), constants.R_OK),
    detectImageMimeType: async (path) => {
      const bytes = await readFile(await safe(path));
      if (bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return "image/png";
      if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return "image/jpeg";
      if (bytes.subarray(0, 3).toString() === "GIF") return "image/gif";
      if (bytes.subarray(0, 4).toString() === "RIFF" && bytes.subarray(8, 12).toString() === "WEBP") return "image/webp";
      return null;
    },
  };
  const write = {
    writeFile: async (path, content) => {
      if (Buffer.byteLength(content) > 4 * 1024 * 1024) throw new Error("File exceeds 4 MiB workspace write limit");
      await writeFile(await safe(path), content);
    },
    mkdir: async (path) => mkdir(await safe(path), { recursive: true }),
  };
  const bash = {
    exec: async (command, cwd, { signal, timeout, onData }) => {
      const seconds = Math.min(timeout ?? COMMAND_TIMEOUT_SECONDS, COMMAND_TIMEOUT_SECONDS);
      if (!Number.isFinite(seconds) || seconds <= 0) throw new Error("Timeout must be positive seconds");
      if (signal?.aborted) throw new Error("aborted");
      const working = await safe(cwd);
      const child = spawn("/bin/bash", ["--noprofile", "--norc", "-c", command], {
        cwd: working, detached: true,
        env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: root, TMPDIR: resolve(root, ".tmp"), LANG: "C.UTF-8", TERM: "dumb",
          HTTP_PROXY: process.env.HTTPS_PROXY || "", HTTPS_PROXY: process.env.HTTPS_PROXY || "", ALL_PROXY: process.env.HTTPS_PROXY || "",
          http_proxy: process.env.HTTPS_PROXY || "", https_proxy: process.env.HTTPS_PROXY || "", all_proxy: process.env.HTTPS_PROXY || "" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let bytes = 0, failure;
      const kill = () => { if (child.pid) { try { process.kill(-child.pid, "SIGKILL"); } catch {} } };
      const timer = setTimeout(() => { failure = `timeout:${seconds}`; kill(); }, seconds * 1000);
      const cancel = () => { failure = "aborted"; kill(); };
      signal?.addEventListener("abort", cancel, { once: true });
      const output = (data) => {
        const remaining = RAW_OUTPUT_CAP_BYTES - bytes;
        if (remaining > 0) onData(data.subarray(0, remaining));
        bytes += data.length;
        if (bytes > RAW_OUTPUT_CAP_BYTES) { failure = "Command exceeded the 1 MiB raw output limit"; kill(); }
      };
      child.stdout.on("data", output); child.stderr.on("data", output);
      try {
        const exitCode = await new Promise((done, reject) => { child.once("error", reject); child.once("close", (code) => done(code ?? 137)); });
        if (failure) throw new Error(failure);
        return { exitCode };
      } finally {
        clearTimeout(timer); signal?.removeEventListener("abort", cancel); kill();
      }
    },
  };
  return [createBashTool(root, { operations: bash, exposeSessionEnvironment: false }), createReadTool(root, { operations: read }), createWriteTool(root, { operations: write }), createEditTool(root, { operations: { ...read, ...write } })];
}

export function environment(root = "/workspace") {
  return { os: "Linux", user: "agent (uid 1000)", cwd: root, workspace: root,
    persistence: "Workspace persists for this conversation only; releasing or expiring the guest deletes it.",
    commandTimeoutSeconds: COMMAND_TIMEOUT_SECONDS, outputCapBytes: OUTPUT_CAP_BYTES, rawOutputCapBytes: RAW_OUTPUT_CAP_BYTES,
    outputCapLines: 2000, idleTimeoutSeconds: 300, piVersion, mcpVersion: "2026-07-28", mcpSdkVersion: "2.4.0",
    allowlist: JSON.parse(process.env.AGENT_NETWORK_ALLOWLIST || "[]"), proxy: process.env.HTTPS_PROXY || "",
    network: "All outbound traffic is restricted by the measured guest firewall to the operator CONNECT proxy. The proxy accepts only its configured host allowlist; direct Internet connections are blocked.",
    confinement: "Tools run as uid 1000 with no supplementary groups in a container with a read-only root filesystem. /workspace is the writable application directory; file tools reject paths or symlinks outside it. Shell commands can read installed system runtimes. Attestation socket and daemon state are restricted to root.",
  };
}

export function createAgentServer(root, options = {}) {
  const tools = createWorkspaceTools(root, options);
  const server = new Server({ name: "Dsmack attested Pi tools", version: piVersion }, { capabilities: { tools: {}, resources: {} }, supportedProtocolVersions: ["2026-07-28"] });
  let pending = Promise.resolve();
  const serial = (fn) => { const result = pending.then(fn); pending = result.catch(() => {}); return result; };
  server.setRequestHandler("tools/list", async () => ({ tools: toolCatalog().map(({ label, ...tool }) => ({ ...tool, title: label })) }));
  server.setRequestHandler("tools/call", (request, ctx) => serial(async () => {
    const { name, arguments: args = {}, _meta } = request.params;
    const tool = tools.find((entry) => entry.name === name);
    if (!tool) throw new Error("Unknown tool");
    if (!Value.Check(tool.parameters, args)) throw new Error("Arguments do not match pi tool schema");
    const deadline = AbortSignal.timeout(COMMAND_TIMEOUT_SECONDS * 1000);
    const signal = AbortSignal.any([ctx.mcpReq.signal, deadline]);
    let progress = 0, notifications = Promise.resolve();
    const onUpdate = _meta?.progressToken === undefined ? undefined : (update) => {
      const message = update.content.filter((part) => part.type === "text").map((part) => part.text).join("\n");
      if (!message) return;
      notifications = notifications.then(() => ctx.mcpReq.notify({ method: "notifications/progress", params: { progressToken: _meta.progressToken, progress: ++progress, message } })).catch(() => {});
    };
    try {
      const result = await tool.execute(String(ctx.mcpReq.id), args, signal, onUpdate);
      await notifications;
      return { content: result.content, ...(result.isError ? { isError: true } : {}), _meta: { "dsmack/piDetails": result.details ?? null } };
    } catch (error) {
      await notifications.catch(() => {});
      return { isError: true, content: [{ type: "text", text: error.message || String(error) }] };
    }
  }));
  server.setRequestHandler("resources/list", async () => ({ resources: [
    { uri: "dsmack://environment", name: "Measured guest environment", mimeType: "application/json" },
    { uri: "dsmack://workspace/patch", name: "Workspace diff", mimeType: "text/x-diff" },
  ] }));
  server.setRequestHandler("resources/read", (request) => serial(async () => {
    const uri = request.params.uri;
    if (uri === "dsmack://environment") return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(environment(root)) }] };
    if (uri === "dsmack://workspace/patch") {
      await exec("git", ["add", "--intent-to-add", "--all"], { cwd: root, timeout: 10000 });
      const { stdout } = await exec("git", ["diff", "--binary", "HEAD", "--", ".", ":(exclude).tmp"], { cwd: root, timeout: 10000, maxBuffer: 8 * 1024 * 1024, encoding: "buffer" });
      return { contents: [{ uri, mimeType: "text/x-diff", blob: stdout.toString("base64") }] };
    }
    throw new Error("Unknown resource");
  }));
  return server;
}

export async function initializeWorkspace(root) {
  await mkdir(resolve(root, ".tmp"), { recursive: true });
  process.env.TMPDIR = resolve(root, ".tmp");
  await exec("git", ["init", "-q"], { cwd: root });
  await writeFile(resolve(root, ".git/info/exclude"), ".tmp/\nartifacts/\nstate/\n");
  await exec("git", ["-c", "user.name=Dsmack", "-c", "user.email=agent@dsmack.invalid", "commit", "--allow-empty", "-qm", "Initial workspace"], { cwd: root });
}

export async function listen({ root = "/workspace", socket = process.env.AGENT_MCP_SOCKET || "/run/dsmack/agent-mcp.sock" } = {}) {
  await mkdir(dirname(socket), { recursive: true, mode: 0o711 });
  await unlink(socket).catch((error) => { if (error.code !== "ENOENT") throw error; });
  let ready;
  const initialized = new Promise((done) => { ready = done; });
  const listener = createServer((stream) => {
    stream.pause();
    initialized.then(() => {
      serveStdio(() => createAgentServer(root), { transport: new StdioServerTransport(stream, stream, { maxBufferSize: 8 * 1024 * 1024 }), legacy: "reject", onerror: (error) => console.error(error.message) });
      stream.resume();
    });
  });
  await new Promise((done, reject) => { listener.once("error", reject); listener.listen(socket, done); });
  await chmod(socket, 0o600);
  if (process.getuid() === 0) {
    await chown(socket, 1000, 1000);
    process.setgroups([]); process.setgid(1000); process.setuid(1000);
  }
  await initializeWorkspace(root);
  ready();
  if (process.env.AGENT_READY_FD !== undefined) {
    const fd = Number(process.env.AGENT_READY_FD);
    writeSync(fd, "ready\n"); closeSync(fd);
  }
  console.error("agent MCP ready");
  return listener;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await listen();
