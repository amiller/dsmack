// Build, register and run lit-action.js on Lit Chipotle. Deno:
//   deno run -A lit.mjs cid <policy.json>                 print the action's CID and size
//   deno run -A lit.mjs setup <policy.json>               group + action + execute-only usage key (account key)
//   deno run -A lit.mjs exec <policy.json> <params.json>  POST /lit_action with the usage key, print the response
// policy.json is {rpc, attest, canary}; it is inlined, so it is part of the CID and of the action key.
// LIT_ACCOUNT_KEY is the account key file (read in place, never printed); LIT_STATE is the directory for state.json
// and the usage key this script creates.
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

if (import.meta.main) {
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
  if (cmd === "exec") {
    const js_params = JSON.parse(await Deno.readTextFile(paramsFile));
    console.log(JSON.stringify((await api("POST", "/lit_action", secret(`${state}/usage-key`), { code, js_params })).response));
  }
}
