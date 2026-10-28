import { Payments } from "./payments.mjs";
import { rpcChain } from "../../dstack-compat/secret-release/policy.mjs";
import { withEnrollment } from "./attestation.mjs";
import { Broker, Refused, limits } from "./broker.mjs";
import { canonical } from "./grants.mjs";
import { getSigningKey } from "./key.ts";

type Context = { env: Record<string, string>; dataDir: string };
async function load(ctx: Context) {
  const cfg = JSON.parse(await Deno.readTextFile(new URL("config.json", import.meta.url)));
  if (!ctx.dataDir) throw new Error("webhost must provide a persistent dataDir");
  const key = await getSigningKey(ctx.env.DSTACK_SOCKET);
  const atomicSave = async (path: string,value: object) => {
    await Deno.writeTextFile(path+".tmp",JSON.stringify(value),{mode:0o600});
    using file=await Deno.open(path+".tmp",{write:true});
    await file.sync();
    await Deno.rename(path + ".tmp",path);
    using directory=await Deno.open(ctx.dataDir,{read:true});
    await directory.sync();
  };
  let payments;
  if (cfg.payments) {
    const path=ctx.dataDir+"/payments.json";
    let state;
    try {state=JSON.parse(await Deno.readTextFile(path));}
    catch(e) {if (!(e instanceof Deno.errors.NotFound)) throw e;}
    payments=new Payments({cfg:cfg.payments,key:await getSigningKey(ctx.env.DSTACK_SOCKET,true),state,save:(v:object)=>atomicSave(path,v)});
  }
  const path = ctx.dataDir + "/credits.json";
  let credits = {};
  try { credits = JSON.parse(await Deno.readTextFile(path)); }
  catch (e) { if (!(e instanceof Deno.errors.NotFound)) throw e; }
  const chain = withEnrollment(rpcChain(cfg.rpc, cfg.attest, cfg.canary), cfg.enrollments);
  return new Broker({ cfg, chain, key, credits, payments, saveCredits: (value: object) => atomicSave(path,value) });
}

const escape = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
function page(b: Broker) {
  const rows = b.live().filter((r) => r.kind === "relay").map((r) => {
    let command = b.cfg.client_command;
    for (const k of ["relay_peer", "relay_maddr", "manifest_sha256", "os_image_hash", "cdhash"]) command = command.replaceAll("{" + k + "}", String(r[k]));
    return `<article><h2>${escape(r.relay_peer)}</h2><p>Attestation: verified · lease until ${new Date(r.expires_at * 1000).toISOString()}</p><dl>${["manifest_sha256", "os_image_hash", "cdhash"].map((k) => `<dt>${k}</dt><dd>${escape(String(r[k]))}</dd>`).join("")}</dl><pre>${escape(command)}</pre></article>`;
  }).join("");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Attested egress relay</title><style>body{font:16px system-ui;max-width:65rem;margin:3rem auto;padding:0 1rem;background:#101828;color:#edf2fa}a{color:#8cd8ff}article{border:1px solid #475467;border-radius:12px;padding:1rem;margin:1rem 0}h2,dd,pre{overflow-wrap:anywhere}h2{font-size:1rem}dd{margin:0 0 1rem}pre{white-space:pre-wrap;background:#1d2939;padding:1rem}</style><h1>Attested egress relay</h1><p>${b.payments ? "Base Sepolia ETH · prices and paid grants at /payments/nodes" : `Free testnet credit: ${limits.max_bytes / 1048576} MiB and ${limits.grants_per_hour} grants per client PeerId per hour.`} Nodes renew their registration every 25–30 seconds.</p><p><a href="key">Broker public key</a> · <a href="relays">Relay registry</a> · <a href="nodes">Compute nodes</a></p>${rows || "<p>No live relays.</p>"}</html>`;
}

async function body(req: Request) {
  if (!req.body) throw new Refused("JSON body required", 400);
  let size = 0; const chunks = [];
  for await (const chunk of req.body) {
    size += chunk.length;
    if (size > 150000) throw new Refused("request too large", 413);
    chunks.push(chunk);
  }
  const raw = new Uint8Array(size); let i = 0;
  for (const c of chunks) { raw.set(c, i); i += c.length; }
  try {
    const r = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    if (!r || typeof r !== "object" || Array.isArray(r)) throw new Error("object required");
    return r;
  } catch { throw new Refused("JSON object required", 400); }
}

let state: ReturnType<typeof load> | undefined;
export default async function handler(req: Request, ctx: Context) {
  const b = await (state ??= load(ctx)), path = new URL(req.url).pathname;
  try {
    let response;
    if(req.method==="GET" && path==="/payments/key") {
      const key=b.payments?.key ?? await getSigningKey(ctx.env.DSTACK_SOCKET,true);
      response=Response.json({algorithm:"secp256k1",address:key.address,chainId:84532,escrow:b.payments?.cfg.escrow,codeHash:b.payments?.cfg.codeHash});
    }
    else if (b.payments && path.startsWith("/payments/")) {
      const p=b.payments;
      if(req.method==="GET" && path==="/payments/challenge") response=Response.json(p.challenge());
      else if(req.method==="GET" && path==="/payments/nodes") response=Response.json(await p.list(b.live()));
      else if(req.method==="POST" && path==="/payments/grant") response=Response.json(await p.grant(await body(req),b.live()));
      else if(req.method==="POST" && path==="/payments/receipts") response=Response.json(await p.collect(await body(req)));
      else if(req.method==="GET" && path==="/payments/receipts") response=Response.json(Object.values(p.state.receipts));
      else response=new Response("not found",{status:404});
    }
    else if (req.method === "GET" && path === "/key") response = Response.json({ algorithm: "Ed25519", public_key: b.key.public_key });
    else if (req.method === "GET" && path === "/relays") response = Response.json(b.live().filter((r) => r.kind === "relay"));
    else if (req.method === "GET" && path === "/nodes") response = Response.json(b.live().filter((r) => r.kind === "compute"));
    else if (req.method === "GET" && path === "/") response = new Response(page(b), { headers: { "content-type": "text/html; charset=utf-8" } });
    else if (req.method === "POST" && (path === "/relays" || path === "/nodes")) {
      response = Response.json(await b.register(await body(req)), { status: 201 });
    } else if (req.method === "POST" && path === "/grant") response = new Response(canonical(await b.grant(await body(req))), { headers: { "content-type": "application/json" } });
    else response = new Response("not found", { status: 404 });
    response.headers.set("cache-control", "no-store");
    response.headers.set("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
    return response;
  } catch (e) {
    if (e instanceof Refused) return Response.json({ error: e.message }, { status: e.status });
    if (e instanceof Error && e.message.startsWith("refused:")) return Response.json({ error: e.message }, { status: 403 });
    throw e;
  }
}

// Standalone dev runner passes the same context as the webhost entry shim.
if (import.meta.main) {
  const [host, port, dataDir] = Deno.args;
  const env = JSON.parse(await new Response(Deno.stdin.readable).text());
  Deno.serve({ hostname: host, port: Number(port) }, (req) => handler(req, { env, dataDir }));
}
