// dstack-webhost handler: POST /release {task_id, attestation} -> {epk, iv, ct}, the task's secret sealed to the
// attested guest's secret-key (policy.mjs). ctx.env.SECRET_RELEASE is JSON
// {rpc, attest, canary, tasks: {<task id>: {manifest, images: [os_image_hash], secret}}}, all hex.
import { release, rpcChain, unhex } from "./policy.mjs";

export default async function handler(req: Request, ctx: { env: Record<string, string> }) {
  if (req.method !== "POST" || new URL(req.url).pathname !== "/release") return new Response("not found", { status: 404 });
  const cfg = JSON.parse(ctx.env.SECRET_RELEASE), r = await req.json(), task = cfg.tasks[r.task_id];
  if (!task) return Response.json({ error: "unknown task" }, { status: 404 });
  try {
    return Response.json(await release(r, task, unhex(task.secret), rpcChain(cfg.rpc, cfg.attest, cfg.canary)));
  } catch (e) {
    if (!(e instanceof Error) || !e.message.startsWith("refused")) throw e;
    return Response.json({ error: e.message }, { status: 403 });
  }
}

// Standalone: SECRET_RELEASE_FILE=<config.json> deno run --allow-net --allow-read --allow-env server.ts <host> <port>
if (import.meta.main) {
  const env = { SECRET_RELEASE: Deno.readTextFileSync(Deno.env.get("SECRET_RELEASE_FILE")!) };
  Deno.serve({ hostname: Deno.args[0], port: Number(Deno.args[1]) }, (req) => handler(req, { env }));
}
