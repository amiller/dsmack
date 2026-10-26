// dstack-webhost handler (isolation: container). The task secrets are not in ctx.env: the daemon's shared runtime
// can read every project's env. The handler keeps a P-256 key in ctx.dataDir, a volume only this project's container
// mounts, and config.json (part of the deployed source tree, so of its tree_hash) is
// {rpc, attest, canary, tasks: {<task id>: {manifest, images: [os_image_hash], wrapped}}}, all hex, with
// wrapped = seal(pub, secret, taskLabel(task id, task)), so a secret only opens under the terms it was sealed for.
//   GET /public-key -> {pub}
//   POST /release {task_id, attestation} -> {epk, iv, ct}, the task's secret sealed to the attested guest's secret-key
import { hex, open, p256Key, release, rpcChain, seal, unhex } from "./policy.mjs";

export const taskLabel = (id: string, t: { manifest: string; images: string[] }) =>
  "dsmack.secret-release/webhost-task/1" + JSON.stringify([id, t.manifest, t.images]);

async function load(dataDir: string) {
  const path = dataDir + "/release-key";
  try {
    await Deno.writeTextFile(path, hex(crypto.getRandomValues(new Uint8Array(32))), { createNew: true, mode: 0o600 });
  } catch (e) {
    if (!(e instanceof Deno.errors.AlreadyExists)) throw e;
  }
  return { key: await p256Key(unhex(await Deno.readTextFile(path))),
    cfg: JSON.parse(await Deno.readTextFile(new URL("config.json", import.meta.url))) };
}
let state: ReturnType<typeof load> | undefined;

export default async function handler(req: Request, ctx: { dataDir: string }) {
  const { key, cfg } = await (state ??= load(ctx.dataDir)), path = new URL(req.url).pathname;
  if (req.method === "GET" && path === "/public-key") return Response.json({ pub: hex(key.pub) });
  if (req.method !== "POST" || path !== "/release") return new Response("not found", { status: 404 });
  const r = await req.json(), task = Object.hasOwn(cfg.tasks, r.task_id) ? cfg.tasks[r.task_id] : undefined;
  if (!task) return Response.json({ error: "unknown task" }, { status: 404 });
  try {
    const secret = await open(key, task.wrapped, taskLabel(r.task_id, task));
    return Response.json(await release(r, task, secret, rpcChain(cfg.rpc, cfg.attest, cfg.canary)));
  } catch (e) {
    if (!(e instanceof Error) || !e.message.startsWith("refused")) throw e;
    return Response.json({ error: e.message }, { status: 403 });
  }
}

// deno run --allow-read --allow-write --allow-net server.ts serve <host> <port> <data dir>   (config.json beside server.ts)
// deno run server.ts wrap <pub> <task id> <manifest> <image>...   (secret hex on stdin) -> wrapped
if (import.meta.main) {
  const [op, ...a] = Deno.args;
  if (op === "serve") Deno.serve({ hostname: a[0], port: Number(a[1]) }, (req) => handler(req, { dataDir: a[2] }));
  else if (op === "wrap") {
    const secret = unhex((await new Response(Deno.stdin.readable).text()).trim());
    console.log(JSON.stringify(await seal(unhex(a[0]), secret, taskLabel(a[1], { manifest: a[2], images: a.slice(3) }))));
  } else throw new Error("usage: server.ts serve <host> <port> <data dir> | wrap <pub> <task id> <manifest> <image>...");
}
