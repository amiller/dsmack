import test from "node:test";
import assert from "node:assert/strict";
import { createSessionPersistence } from "./artifact-persistence.mjs";

test("a later chat save preserves durable encrypted budget updates and targets the captured session", async () => {
  const records = new Map(), storage = { sessions: { get: async id => structuredClone(records.get(id)) } };
  const save = async (_, session, agent) => { const record = structuredClone({ ...session, messages: agent.messages }); records.set(session.id, record); return record; };
  const persist = createSessionPersistence({ storage, save });
  const a = { id: "a", dsmack: {} }, b = { id: "b", dsmack: {} }, agentA = { messages: ["A"] }, agentB = { messages: ["B"] };
  await persist(a, agentA);
  await persist(b, agentB);
  // Another tab reserved a model call while this tab's session object stayed old.
  records.get("a").dsmack.artifactState = { app: { v: 1, iv: "iv", ciphertext: "new-reservation" } };
  await persist(a, agentA);
  assert.equal(records.get("a").dsmack.artifactState.app.ciphertext, "new-reservation");
  await persist(a, agentA, { scope: "app", envelope: { v: 1, iv: "iv2", ciphertext: "completed-call" } });
  assert.equal(records.get("a").dsmack.artifactState.app.ciphertext, "completed-call");
  assert.deepEqual(records.get("b").messages, ["B"]);
  assert.deepEqual(records.get("b").dsmack.artifactState, {});
});
