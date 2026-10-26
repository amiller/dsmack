// Lit (Chipotle) action wrapper. The deployed source is policy.mjs with its `export ` keywords removed, then this
// file, then `const POLICY = {rpc, attest, canary};` and `main`, so POLICY is part of the CID and the action key.
// The task secret is provisioned sealed to the action's P-256 key, under a label naming the task, so js_params
// (untrusted) cannot swap the task terms:
//   {op: "publicKey"} -> {pub}
//   {op: "release", task: {id, manifest, images}, wrapped: seal(pub, secret, litTaskLabel(task)), task_id, attestation}
//     -> seal(guest secret-key, secret, task_id)
const LIT_KEY = "dsmack.secret-release/lit-key/1";
const litTaskLabel = (t) => "dsmack.secret-release/lit-task/1" + JSON.stringify([t.id, t.manifest, t.images]);

async function actionKey() {
  const sk = unhex((await Lit.Actions.getLitActionPrivateKey()).replace(/^0x/, ""));
  const ikm = await crypto.subtle.importKey("raw", sk, "HKDF", false, ["deriveBits"]);
  const d = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: new TextEncoder().encode(LIT_KEY) }, ikm, 256));
  return p256Key(d);
}

async function main(params) {
  if (params.op === "publicKey") return { pub: hex((await actionKey()).pub) };
  must(params.op === "release" && params.task.id === params.task_id, "release names one task");
  const guest = await check(params, params.task, rpcChain(POLICY.rpc, POLICY.attest, POLICY.canary), Date.now());
  return seal(guest, await open(await actionKey(), params.wrapped, litTaskLabel(params.task)), params.task_id);
}
