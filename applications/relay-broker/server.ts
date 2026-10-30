import { Continuity } from "./continuity.mjs";
import { Workspaces } from "./workspaces.mjs";
import { tunnelIndex } from "./tunnel-index.mjs";
import { fleet, readFleet } from "./fleet.mjs";
import { rankNodes, busyRetrySeconds } from "./scheduler.mjs";
import { json } from "../payments/schema.mjs";
import { Payments } from "./payments.mjs";
import { Inference, InferenceError } from "./inference.mjs";
import { NearError, NearProvider } from "./near.mjs";
import { rpcChain } from "../../dstack-compat/secret-release/policy.mjs";
import { withEnrollment } from "./attestation.mjs";
import { Broker, limits, Refused } from "./broker.mjs";
import { canonical } from "./grants.mjs";
import { getProviderEnvKey, getSigningKey } from "./key.ts";
import { decryptEnvelope, info as environmentInfo } from "./provider-env.mjs";
import { sandbox } from "./sandbox.mjs";
import { AgentSessions } from "./agent.mjs";

type Context = { env: Record<string, string>; dataDir: string };
async function load(ctx: Context) {
  const cfg = JSON.parse(
    await Deno.readTextFile(new URL("config.json", import.meta.url)),
  );
  if (!ctx.dataDir) {
    throw new Error("webhost must provide a persistent dataDir");
  }
  const key = await getSigningKey(ctx.env.DSTACK_SOCKET);
  const atomicSave = async (path: string, value: object) => {
    await Deno.writeTextFile(path + ".tmp", JSON.stringify(value), {
      mode: 0o600,
    });
    using file = await Deno.open(path + ".tmp", { write: true });
    await file.sync();
    await Deno.rename(path + ".tmp", path);
    using directory = await Deno.open(ctx.dataDir, { read: true });
    await directory.sync();
  };
  let payments;
  if (cfg.payments) {
    const path = ctx.dataDir + "/payments-" +
      cfg.payments.escrow.toLowerCase() + ".json";
    let state;
    try {
      state = JSON.parse(await Deno.readTextFile(path));
    } catch (e) {
      if (!(e instanceof Deno.errors.NotFound)) throw e;
    }
    payments = new Payments({
      cfg: cfg.payments,
      key: await getSigningKey(ctx.env.DSTACK_SOCKET, true),
      state,
      save: (v: object) => atomicSave(path, v),
    });
  }
  let inference, providerEnvironment;
  if (cfg.inference) {
    if (!payments) {
      throw new Error("inference requires a configured payment broker");
    }
    const encryptionKey = await getProviderEnvKey(ctx.env.DSTACK_SOCKET);
    providerEnvironment = await environmentInfo(encryptionKey, payments.key);
    const secrets = ctx.env.NEAR_ENCRYPTED_ENV
      ? await decryptEnvelope(
        JSON.parse(ctx.env.NEAR_ENCRYPTED_ENV),
        encryptionKey,
      )
      : {};
    const provider = secrets.NEAR_API_KEY
      ? new NearProvider({
        ...cfg.inference,
        apiKey: secrets.NEAR_API_KEY,
        attestationPolicy: cfg.inference,
      })
      : undefined;
    inference = new Inference({ payments, cfg: cfg.inference, provider });
    await inference.recover();
  }
  const path = ctx.dataDir + "/credits.json";
  let credits = {};
  try {
    credits = JSON.parse(await Deno.readTextFile(path));
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }
  const chain = withEnrollment(
    rpcChain(cfg.rpc, cfg.attest, cfg.canary),
    cfg.enrollments,
  );
  const broker = new Broker({
    cfg,
    chain,
    key,
    credits,
    payments,
    inference,
    providerEnvironment,
    saveCredits: (value: object) => atomicSave(path, value),
  });
  const syncPath = ctx.dataDir + "/continuity.json", blobs = ctx.dataDir + "/continuity-blocks";
  await Deno.mkdir(blobs, { recursive: true, mode: 0o700 });
  let syncState;
  try { syncState = JSON.parse(await Deno.readTextFile(syncPath)); }
  catch (e) { if (!(e instanceof Deno.errors.NotFound)) throw e; }
  const workspacePath = ctx.dataDir + "/workspaces.json";
  let workspaceState;
  try { workspaceState = JSON.parse(await Deno.readTextFile(workspacePath)); }
  catch (e) { if (!(e instanceof Deno.errors.NotFound)) throw e; }
  return Object.assign(broker, { workspaces: new Workspaces({ broker, cfg: cfg.workspaces,
    state: workspaceState, save: (v: object) => atomicSave(workspacePath, v) }), continuity: new Continuity({
    cfg: { rpc: cfg.rpc, ...cfg.continuity }, key,
    anchorKey: payments?.key ?? await getSigningKey(ctx.env.DSTACK_SOCKET, true),
    state: syncState,
    save: (v: object) => atomicSave(syncPath, v),
    put: async (cid: string, ciphertext: string) => {
      const temporary = blobs + "/" + cid + "." + crypto.randomUUID() + ".tmp";
      await Deno.writeTextFile(temporary, ciphertext, { mode: 0o600 });
      using f = await Deno.open(temporary, { write: true }); await f.sync();
      await Deno.rename(temporary, blobs + "/" + cid);
      using directory = await Deno.open(blobs, { read: true }); await directory.sync();
    },
    get: async (cid: string) => {
      try { return await Deno.readTextFile(blobs + "/" + cid); }
      catch (e) { if (!(e instanceof Deno.errors.NotFound)) throw e; return null; }
    },
  }) });
}

const escape = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (
      c,
    ) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]!),
  );
function page(b: Broker) {
  const rows = b.live().filter((r) => r.kind === "relay").map((r) => {
    let command = b.cfg.client_command;
    for (
      const k of [
        "relay_peer",
        "relay_maddr",
        "manifest_sha256",
        "os_image_hash",
        "cdhash",
      ]
    ) command = command.replaceAll("{" + k + "}", String(r[k]));
    return `<article><h2>${
      escape(r.relay_peer)
    }</h2><p>Attestation: verified · lease until ${
      new Date(r.expires_at * 1000).toISOString()
    }</p><dl>${
      ["manifest_sha256", "os_image_hash", "cdhash"].map((k) =>
        `<dt>${k}</dt><dd>${escape(String(r[k]))}</dd>`
      ).join("")
    }</dl><pre>${escape(command)}</pre></article>`;
  }).join("");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Attested egress relay</title><style>body{font:16px system-ui;max-width:65rem;margin:3rem auto;padding:0 1rem;background:#101828;color:#edf2fa}a{color:#8cd8ff}article{border:1px solid #475467;border-radius:12px;padding:1rem;margin:1rem 0}h2,dd,pre{overflow-wrap:anywhere}h2{font-size:1rem}dd{margin:0 0 1rem}pre{white-space:pre-wrap;background:#1d2939;padding:1rem}</style><h1>Attested egress relay</h1><p>${
    b.payments
      ? "Base Sepolia ETH · prices and paid grants at /payments/nodes"
      : `Free testnet credit: ${
        limits.max_bytes / 1048576
      } MiB and ${limits.grants_per_hour} grants per client PeerId per hour.`
  } Nodes renew their registration every 25–30 seconds.</p><p><a href="key">Broker public key</a> · <a href="relays">Relay registry</a> · <a href="nodes">Compute nodes</a></p>${
    rows || "<p>No live relays.</p>"
  }</html>`;
}

async function body(req: Request, maximum = 150000) {
  if (!req.body) throw new Refused("JSON body required", 400);
  let size = 0;
  const chunks = [];
  for await (const chunk of req.body) {
    size += chunk.length;
    if (size > maximum) throw new Refused("request too large", 413);
    chunks.push(chunk);
  }
  const raw = new Uint8Array(size);
  let i = 0;
  for (const c of chunks) {
    raw.set(c, i);
    i += c.length;
  }
  try {
    const r = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    if (!r || typeof r !== "object" || Array.isArray(r)) {
      throw new Error("object required");
    }
    return r;
  } catch {
    throw new Refused("JSON object required", 400);
  }
}

let state: ReturnType<typeof load> | undefined;
export default async function handler(req: Request, ctx: Context) {
  const loading = state ??= load(ctx);
  let broker;
  try {
    broker = await loading;
  } catch (error) {
    // Shared-runtime promotion can briefly remove the project GetKey socket.
    // A rejected startup must not poison every later request after it returns.
    if (state === loading) state = undefined;
    throw error;
  }
  return await handleRequest(req, broker, ctx);
}

export async function handleRequest(req: Request, b: Broker, ctx?: Context) {
  const path = new URL(req.url).pathname;
  if(path==="/tunnels")return await tunnelIndex(req,ctx?.env.OPERATOR_TOKEN_SHA256,ctx?.dataDir?ctx.dataDir+"/tunnels.json":undefined);
  if(path==="/fleet" || ["/fleet/ownership", "/fleet/link", "/fleet/unlink", "/fleet/revoke-provisioner"].includes(path))return await fleet(req,b.cfg.payments?.escrow,ctx?.dataDir?ctx.dataDir+"/fleet.json":undefined);
  const origin = req.headers.get("origin");
  const allowedOrigin = origin &&
    (origin === new URL(req.url).origin ||
      (b.cfg.inference?.origins ?? []).includes(origin) ||
      (b.cfg.browser_origins ?? []).includes(origin));
  const finish = (response: Response) => {
    response.headers.set("cache-control", "no-store");
    if (allowedOrigin) {
      response.headers.set("access-control-allow-origin", origin!);
      response.headers.set("vary", "Origin");
      response.headers.set(
        "access-control-allow-methods",
        "GET, POST, OPTIONS",
      );
      response.headers.set("access-control-allow-headers", "content-type");
    }
    return response;
  };
  try {
    let response;
    if (origin && !allowedOrigin) {
      return finish(
        Response.json({
          error: {
            code: "ORIGIN_REFUSED",
            message: "origin is not configured",
          },
        }, { status: 403 }),
      );
    }
    if (req.method === "OPTIONS") {
      return finish(new Response(null, { status: 204 }));
    }
    if (path.startsWith("/workspaces/") && req.method === "POST") {
      const workspaces = (b as Broker & { workspaces?: Workspaces }).workspaces;
      if (!workspaces || !b.payments) throw new InferenceError("WORKSPACE_STORE_UNAVAILABLE", "workspace storage is not configured", 503);
      response = Response.json(await workspaces.call(path.slice("/workspaces/".length), await body(req, 1024 * 1024)));
    } else if (path.startsWith("/sync/") && req.method === "POST") {
      const sync = (b as Broker & { continuity?: Continuity }).continuity;
      if (!sync) return finish(Response.json({ error: "sync not configured" }, { status: 503 }));
      try { response = Response.json(await sync.call(path.slice(6), await body(req, 3 * 1024 * 1024))); }
      catch (e) { if (e instanceof Error && "status" in e) return finish(Response.json({ error: e.message }, { status: Number(e.status) })); throw e; }
    } else if (path.startsWith("/agent/") && req.method === "POST") {
      if (!b.inference || !b.payments) throw new InferenceError("PROVIDER_NOT_CONFIGURED", "agent credit is not configured", 503);
      const sessions = new AgentSessions(b, () => readFleet(ctx?.dataDir ? ctx.dataDir + "/fleet.json" : undefined, b.now())), request = await body(req);
      const action = path.slice("/agent/".length);
      if (action === "open") response = Response.json(await sessions.open(request));
      else if (action === "status") response = Response.json(await sessions.status(request));
      else if (action === "end") response = Response.json(await sessions.status(request, true));
      else if (action === "receipt") response = Response.json(await sessions.receipt(request));
      else response = new Response("not found", { status: 404 });
    } else if (path.startsWith("/sandbox/")) {
      response = await sandbox(req, b);
    } else if (path.startsWith("/inference/")) {
      if (!b.inference) {
        throw new InferenceError(
          "PROVIDER_NOT_CONFIGURED",
          "inference is not configured",
          503,
        );
      }
      const action = path.slice("/inference/".length);
      if (req.method === "GET" && action === "environment-key") {
        response = Response.json(b.providerEnvironment);
      } else if (req.method === "GET" && action === "status") {
        response = Response.json(b.inference.status());
      } else if (req.method === "GET" && action === "quote") {
        response = Response.json(await b.inference.quote());
      } else if (req.method === "POST" && action === "grant-credit") {
        response = Response.json(await b.inference.grantCredit(await body(req), {
          issuer: b.cfg.payments?.fundingAddress, escrow: b.cfg.payments?.escrow, brokerKey: b.key.public_key,
        }));
      } else if (
        req.method === "POST" &&
        ["credit", "prepare", "chat", "usage", "artifact-budget"].includes(action)
      ) {
        const request = await body(req);
        const result = await b.inference[action === "artifact-budget" ? "artifactBudget" : action](request);
        response = result instanceof Response ? result : Response.json(result);
      } else response = new Response("not found", { status: 404 });
    } else if (req.method === "GET" && path === "/payments/key") {
      const key = b.payments?.key ??
        await getSigningKey(ctx?.env.DSTACK_SOCKET, true);
      response = Response.json({
        algorithm: "secp256k1",
        address: key.address,
        chainId: 84532,
        escrow: b.payments?.cfg.escrow,
        codeHash: b.payments?.cfg.codeHash,
      });
    } else if (b.payments && path.startsWith("/payments/")) {
      const p = b.payments;
      if (req.method === "GET" && path === "/payments/challenge") {
        response = Response.json(p.challenge());
      } else if (req.method === "GET" && path === "/payments/classes") {
        response = Response.json(JSON.parse(json(await p.classes())));
      } else if (req.method === "GET" && path === "/payments/nodes") {
        response = Response.json(await p.list(b.live()));
      } else if (req.method === "POST" && path === "/payments/confirm") {
        response = Response.json(await p.confirm(await body(req)));
      } else if (req.method === "POST" && path === "/payments/grant") {
        response = Response.json(await p.grant(await body(req), b.live()));
      } else if (req.method === "POST" && path === "/payments/receipts") {
        response = Response.json(await p.collect(await body(req)));
      } else if (req.method === "GET" && path === "/payments/receipts") {
        response = Response.json(Object.values(p.state.receipts));
      } else response = new Response("not found", { status: 404 });
    } else if (req.method === "GET" && path === "/key") {
      response = Response.json({
        algorithm: "Ed25519",
        public_key: b.key.public_key,
      });
    } else if (req.method === "GET" && path === "/relays") {
      response = Response.json(b.live().filter((r) => r.kind === "relay"));
    } else if (req.method === "GET" && path === "/nodes") {
      const sessions = new AgentSessions(b), url = new URL(req.url);
      const nodes = b.live().filter((r) => r.kind === "compute");
      const currentFleet = await readFleet(ctx?.dataDir ? ctx.dataDir + "/fleet.json" : undefined, b.now());
      if (url.searchParams.get("all") === "1") {
        // Preserve every peer for operator readiness and retirement observation.
        response = Response.json(rankNodes(nodes, currentFleet,
          (node, placement) => sessions.available(node, placement), { now: b.now() }));
      } else {
        const workspaceId = url.searchParams.get("workspaceId"), version = Number(url.searchParams.get("version"));
        const hash = url.searchParams.get("hash");
        const snapshotOwner = workspaceId && workspaceId.length <= 128 && Number.isSafeInteger(version) && version > 0 &&
          /^[0-9a-f]{64}$/.test(hash ?? "")
          ? await (b as Broker & {workspaces?: {snapshotOwner?: (ref: {workspaceId: string; version: number; hash: string | null}) => Promise<string | undefined>}})
            .workspaces?.snapshotOwner?.({ workspaceId, version, hash }) : undefined;
        const ranked = rankNodes(nodes, currentFleet,
          (node, placement) => sessions.available(node, placement), { now: b.now(), snapshotOwner });
        if (ranked.some(node => node.available)) response = Response.json(ranked);
        else {
          const retryAfterSeconds = busyRetrySeconds(nodes, b.payments?.state.agentSessions, b.now());
          response = Response.json({ error: { code: "FLEET_BUSY", message: `busy, retry in ${retryAfterSeconds} seconds`, retryAfterSeconds } },
            { status: 503, headers: { "retry-after": String(retryAfterSeconds) } });
        }
      }
    } else if (req.method === "GET" && path === "/") {
      response = new Response(page(b), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    } else if (
      req.method === "POST" && (path === "/relays" || path === "/nodes")
    ) {
      response = Response.json(await b.register(await body(req)), {
        status: 201,
      });
    } else if (req.method === "POST" && path === "/grant") {
      response = new Response(canonical(await b.grant(await body(req))), {
        headers: { "content-type": "application/json" },
      });
    } else response = new Response("not found", { status: 404 });
    response.headers.set("cache-control", "no-store");
    response.headers.set(
      "content-security-policy",
      "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    );
    return finish(response);
  } catch (e) {
    if (e instanceof InferenceError || e instanceof NearError) {
      const retryAfterSeconds = e instanceof InferenceError ? e.retryAfterSeconds : undefined;
      return finish(
        Response.json({ error: { code: e.code, message: e.message,
          ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) } }, {
          status: e.status,
          ...(retryAfterSeconds !== undefined ? { headers: { "retry-after": String(retryAfterSeconds) } } : {}),
        }),
      );
    }
    if (e instanceof Refused) {
      return finish(Response.json(
        path.startsWith("/inference/")
          ? { error: { code: "BAD_REQUEST", message: e.message } }
          : { error: e.message },
        { status: e.status },
      ));
    }
    if (e instanceof Error && e.message.startsWith("refused:")) {
      return finish(Response.json({ error: e.message }, { status: 403 }));
    }
    throw e;
  }
}

// Standalone dev runner passes the same context as the webhost entry shim.
if (import.meta.main) {
  const [host, port, dataDir] = Deno.args;
  const env = JSON.parse(await new Response(Deno.stdin.readable).text());
  Deno.serve(
    { hostname: host, port: Number(port) },
    (req) => handler(req, { env, dataDir }),
  );
}
