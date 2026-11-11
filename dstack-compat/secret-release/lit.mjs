// Build, register and run lit-action.js on Lit Chipotle. Deno:
//   deno run -A lit.mjs cid <policy.json>                 print the action's CID and size
//   deno run -A lit.mjs setup <policy.json>               group + action + execute-only usage key (account key)
//   deno run -A lit.mjs exec <policy.json> <params.json>  POST /lit_action with the usage key, print the response
//   deno run -A lit.mjs serve <policy.json> <tasks.json> <host> <port>
//       POST /release {task_id, attestation} -> the action's release for that task, so a guest calls it as its policy URL
//   deno run -A lit.mjs wrap <pub> <task id> <manifest> <image>...   secret hex on stdin -> wrapped, for tasks.json
// policy.json is {rpc, attest, canary}; it is inlined, so it is part of the CID and of the action key.
// tasks.json is {<task id>: {manifest, images, wrapped}}. serve holds only the execute-only usage key and the action
// checks the request, so the forwarder is not trusted.
// LIT_ACCOUNT_KEY is the account key file (read in place, never printed); LIT_STATE is the directory for state.json
// and the usage key this script creates.
import { seal, unhex } from "./policy.mjs";

const API = "https://api.chipotle.litprotocol.com/core/v1";
const here = (f) => new URL(f, import.meta.url);

export async function actionSource(policy) {
  const policyJs = (await Deno.readTextFile(here("policy.mjs"))).replace(/^export /gm, "");
  if (/^import /m.test(policyJs)) throw new Error("policy.mjs has imports; a Lit action must be one file");
  return policyJs + (await Deno.readTextFile(here("lit-action.js"))) + `\nconst POLICY = ${JSON.stringify(policy)};\n`;
}

// CIDv0 as Chipotle computes it (UnixFS file, dag-pb, sha2-256), for one-chunk sources.
const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const varint = (n) => { const o = []; while (n > 127) { o.push((n & 127) | 128); n >>>= 7; } o.push(n); return o; };
export async function cidV0(code) {
  const data = new TextEncoder().encode(code);
  if (data.length > 262144) throw new Error(`source is ${data.length} bytes, more than one chunk`);
  const unixfs = [0x08, 0x02, 0x12, ...varint(data.length), ...data, 0x18, ...varint(data.length)];
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([0x0a, ...varint(unixfs.length), ...unixfs])));
  let n = BigInt("0x" + [0x12, 0x20, ...d].map((x) => x.toString(16).padStart(2, "0")).join("")), s = "";
  while (n > 0n) { s = ALPHA[Number(n % 58n)] + s; n /= 58n; }
  return s;
}

async function api(method, p, key, body) {
  const r = await fetch(API + p, { method, headers: { "content-type": "application/json", "X-Privacy-Mode": "true", ...(key && { "X-Api-Key": key }) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${p} -> ${r.status} ${text.slice(0, 600)}`);
  return JSON.parse(text);
}

// lit-action.js opens `wrapped` under this label, so a secret only releases under the task terms it was sealed for.
export const litTaskLabel = (t) => "dsmack.secret-release/lit-task/1" + JSON.stringify([t.id, t.manifest, t.images]);
export const wrap = (pub, secret, task) => seal(unhex(pub), secret, litTaskLabel(task));

export function releaseParams(tasks, req) {
  if (!Object.hasOwn(tasks, req.task_id)) throw new Error("unknown task " + req.task_id);
  const { manifest, images, wrapped } = tasks[req.task_id];
  return { op: "release", task: { id: req.task_id, manifest, images }, wrapped, task_id: req.task_id, attestation: req.attestation };
}

if (import.meta.main && Deno.args[0] === "wrap") {
  const [, pub, id, manifest, ...images] = Deno.args;
  console.log(JSON.stringify(await wrap(pub, unhex((await new Response(Deno.stdin.readable).text()).trim()), { id, manifest, images })));
} else if (import.meta.main) {
  const [cmd, policyFile, paramsFile] = Deno.args;
  const code = await actionSource(JSON.parse(await Deno.readTextFile(policyFile))), cid = await cidV0(code);
  const state = Deno.env.get("LIT_STATE"), secret = (f) => Deno.readTextFileSync(f).trim();
  if (cmd === "cid") console.log(JSON.stringify({ cid, bytes: code.length }));
  if (cmd === "setup") {
    const acct = secret(Deno.env.get("LIT_ACCOUNT_KEY"));
    const server = await api("POST", "/get_lit_action_ipfs_id", null, code);
    if (server !== cid) throw new Error(`CID mismatch: local ${cid}, server ${server}`);
    const { group_id } = await api("POST", "/add_group", acct, { group_name: "dsmack-secret-release", group_description: "dsmack secret-release action",
      pkp_ids_permitted: [], cid_hashes_permitted: [] });
    await api("POST", "/add_action_to_group", acct, { group_id: Number(group_id), action_ipfs_cid: cid });
    const { usage_api_key } = await api("POST", "/add_usage_api_key", acct, { name: "dsmack-secret-release-exec", description: "execute only, one group",
      can_create_groups: false, can_delete_groups: false, can_create_pkps: false, manage_ipfs_ids_in_groups: [], add_pkp_to_groups: [],
      remove_pkp_from_groups: [], execute_in_groups: [Number(group_id)] });
    Deno.writeTextFileSync(`${state}/usage-key`, usage_api_key, { mode: 0o600, createNew: true });
    Deno.writeTextFileSync(`${state}/state.json`, JSON.stringify({ cid, groupId: Number(group_id) }));
    console.log(JSON.stringify({ cid, groupId: Number(group_id), usageKey: `${state}/usage-key` }));
  }
  // relay <policy.json> <tasks.json> <port>: the guest's POST /release {task_id, attestation} becomes a Lit release.
  // tasks.json is {<task id>: {manifest, images, wrapped}}. The relay sees only the attestation and ciphertext.
  if (cmd === "relay") {
    const tasks = JSON.parse(await Deno.readTextFile(paramsFile)), usage = secret(`${state}/usage-key`);
    Deno.serve({ hostname: "127.0.0.1", port: Number(Deno.args[3]) }, async (req) => {
      if (req.method !== "POST" || new URL(req.url).pathname !== "/release") return new Response("not found", { status: 404 });
      const { task_id, attestation } = await req.json(), t = tasks[task_id];
      if (!t) return Response.json({ error: "unknown task" }, { status: 404 });
      const js_params = { op: "release", task: { id: task_id, manifest: t.manifest, images: t.images }, wrapped: t.wrapped, task_id, attestation };
      try { return Response.json((await api("POST", "/lit_action", usage, { code, js_params })).response); }
      catch (e) { console.error(e.message); return Response.json({ error: e.message.slice(0, 2000) }, { status: 502 }); }
    });
  }
  if (cmd === "exec") {
    const js_params = JSON.parse(await Deno.readTextFile(paramsFile));
    console.log(JSON.stringify((await api("POST", "/lit_action", secret(`${state}/usage-key`), { code, js_params })).response));
  }
  if (cmd === "serve") {
    const tasks = JSON.parse(await Deno.readTextFile(paramsFile)), [host, port] = Deno.args.slice(3);
    Deno.serve({ hostname: host, port: Number(port) }, async (req) => {
      if (req.method !== "POST" || new URL(req.url).pathname !== "/release") return new Response("not found", { status: 404 });
      const js_params = releaseParams(tasks, await req.json());
      return Response.json((await api("POST", "/lit_action", secret(`${state}/usage-key`), { code, js_params })).response);
    });
  }
}
