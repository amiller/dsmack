import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const bundle = await build({ entryPoints: [resolve(here, "chat-storage.mjs")], bundle: true,
  platform: "node", format: "esm", write: false,
  alias: { "@pi-components": resolve(here, "node_modules/@earendil-works/pi-web-ui/dist") },
});
const { saveChat, exportChats } = await import("data:text/javascript;base64," + Buffer.from(bundle.outputFiles[0].text).toString("base64"));
import { createSessionPersistence } from "./artifact-persistence.mjs";
import { encodeSyncJson, decodeSyncJson } from "./sync-codec.mjs";

test("feedback and full tool traces survive session save, sync encoding and JSONL export", async () => {
  const records = new Map(), metadata = new Map();
  const storage = { sessions: {
    get: async id => structuredClone(records.get(id)),
    getMetadata: async id => structuredClone(metadata.get(id)),
    getAllMetadata: async () => structuredClone([...metadata.values()]),
    save: async (data, meta) => { records.set(data.id, structuredClone(data)); metadata.set(meta.id, structuredClone(meta)); },
  } };
  const session = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), dsmack: {}, feedback: [{
    id: crypto.randomUUID(), sessionId: "", messageIndex: 2, text: "The command output helped.",
    createdAt: new Date().toISOString(), pageVersion: "page-cid", guestId: "attached-guest",
  }] };
  session.feedback[0].sessionId = session.id;
  const agent = { state: { model: { id: "model" }, thinkingLevel: "off", messages: [
    { role: "user", content: "Inspect my code" },
    { role: "assistant", content: [{ type: "toolCall", id: "call", name: "bash", arguments: { command: "pwd" } }],
      usage: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0, totalTokens: 3,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } },
    { role: "toolResult", toolCallId: "call", content: [{ type: "text", text: "/workspace" }] },
  ] } };
  const persist = createSessionPersistence({ storage, save: saveChat });
  await persist(session, agent);
  const line = await exportChats(storage, "0xAbc", session.id);
  const record = JSON.parse(line);
  assert.deepEqual(record.data.feedback, session.feedback);
  assert.deepEqual(record.data.messages, agent.state.messages);
  assert.equal(record.metadata.messageCount, 3);
  assert.equal(record.metadata.title, "Inspect my code");
  const synced = await decodeSyncJson(await encodeSyncJson(record));
  records.clear(); metadata.clear();
  await storage.sessions.save(synced.data, synced.metadata);
  // An already-open session must not erase feedback saved by another tab.
  await persist({ ...session, feedback: undefined }, agent);
  assert.deepEqual(JSON.parse(await exportChats(storage, "0xAbc", session.id)).data.feedback, session.feedback);
  await persist({ id: "second", createdAt: session.createdAt, dsmack: {} }, agent);
  await persist({ id: "other-wallet", createdAt: session.createdAt, dsmack: { wallet: "0xdef" } }, agent);
  assert.deepEqual((await exportChats(storage, "0xabc")).trim().split("\n").map(JSON.parse).map(r => r.data.id), [session.id, "second"]);
  assert.equal((await exportChats(storage, "0xAbc", session.id)).trim().split("\n").length, 1);
});
