import test from "node:test";
import assert from "node:assert/strict";
import { SavedWorkspace, authenticateSnapshot, newestWorkspace, workspaceKey } from "./workspaces.mjs";
import { hex, open } from "../../dstack-compat/secret-release/policy.mjs";

const dataKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const id = crypto.randomUUID(), genesis = "0".repeat(64), utf8 = new TextEncoder();
async function snapshot(version, previousHash = genesis) {
  const key = await workspaceKey(dataKey, id), nonce = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce,
    additionalData: utf8.encode(JSON.stringify([id, version, previousHash])) }, aes, utf8.encode("workspace archive")));
  const bytes = new Uint8Array(12 + encrypted.length); bytes.set(nonce); bytes.set(encrypted, 12);
  return { bytes, head: { workspaceId: id, version, previousHash,
    hash: hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))), size: bytes.length } };
}
function workspace(request, head) {
  const floors = new Map(), saved = [];
  const controller = new SavedWorkspace({ workspaceId: id, credit: { address: "0xabc" }, dataKey: () => dataKey, head,
    request, persist: async value => saved.push(value),
    floorStore: async (key, value) => value === undefined ? floors.get(key) : floors.set(key, value) });
  return { controller, floors, saved };
}
test("workspace subkeys separate conversations and reject altered ciphertext/AAD", async () => {
  const { bytes, head } = await snapshot(1), key = await workspaceKey(dataKey, id);
  assert.notDeepEqual(key, await workspaceKey(dataKey, crypto.randomUUID()));
  await authenticateSnapshot(bytes, head, key);
  await assert.rejects(authenticateSnapshot(bytes, { ...head, version: 2 }, key));
  const changed = bytes.slice(); changed[15] ^= 1;
  await assert.rejects(authenticateSnapshot(changed, head, key), /hash mismatch/);
});
test("an offline guest save must extend the synced head and authenticate before accepting its version", async () => {
  const first = await snapshot(1), second = await snapshot(2, first.head.hash);
  let remote = second;
  const { controller, saved } = workspace(async (op, args) => {
    if (op === "head") return { head: remote.head };
    if (op === "history") return { heads: [remote.head] };
    if (op === "read") return { head: remote.head, offset: args.offset, nextOffset: remote.bytes.length,
      data: Buffer.from(remote.bytes).toString("base64"), source: "mac", ipfsFetched: false };
    throw Error(op);
  }, first.head);
  await controller.latest();
  assert.equal(saved.at(-1).version, 2);
  remote = first;
  await assert.rejects(controller.latest(), /Older saved workspace/);
  remote = { ...second, head: { ...second.head, version: 3, previousHash: second.head.hash } };
  await assert.rejects(controller.latest());
  assert.equal(saved.length, 1);
});
test("bind releases only the derived subkey to the attested key under this guest stay's label", async () => {
  const recipient = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey)).slice(1);
  const { controller } = workspace(async () => ({ head: null }));
  await controller.latest();
  let binding;
  const client = { callTool: async ({ arguments: args }) => {
    binding = args.sealed; return { structuredContent: { restored: true } };
  } };
  assert.equal(await controller.bind(client, { secret_key: hex(pub) }, { sessionId: "stay-one" }), false);
  const clear = JSON.parse(new TextDecoder().decode(await open({ priv: recipient.privateKey, pub }, binding, "stay-one/workspace")));
  assert.equal(clear.workspaceId, id);
  assert.equal(clear.key, hex(await workspaceKey(dataKey, id)));
  assert.notEqual(clear.key, Buffer.from(dataKey, "base64url").toString("hex"));
  await assert.rejects(open({ priv: recipient.privateKey, pub }, binding, "stay-two/workspace"));
});
test("session conflict merging preserves the newest workspace and refuses a same-version fork", async () => {
  const first = await snapshot(1), second = await snapshot(2, first.head.hash);
  assert.equal(newestWorkspace(second.head, first.head), second.head);
  assert.throws(() => newestWorkspace(first.head, { ...first.head, hash: "f".repeat(64) }), /Conflicting/);
});
