import test from "node:test";
import assert from "node:assert/strict";
import { encodeSyncJson, decodeSyncJson, MAX_SYNC_PLAIN_BYTES } from "./sync-codec.mjs";

test("full repeated attestation evidence fits the existing sync blob limit after lossless compression", async () => {
  const evidence = "complete-attestation-evidence/".repeat(14000);
  const value = { data: { messages: [{ role: "assistant", content: "answer" }], dsmack: { evidence: Array.from({ length: 7 }, () => ({ full: evidence })) } } };
  const encoded = await encodeSyncJson(value);
  assert(encoded.length < 1024 * 1024, "Ciphertext plus base64 overhead must fit the existing 2 MiB sync request.");
  assert.deepEqual(await decodeSyncJson(encoded), value);
});
test("legacy uncompressed JSON remains readable and small values stay unwrapped", async () => {
  const value = { old: true }, legacy = new TextEncoder().encode(JSON.stringify(value));
  assert.deepEqual(await decodeSyncJson(legacy), value);
  assert.deepEqual(await encodeSyncJson(value), legacy);
});
test("malformed formats and truncated gzip cannot become a session", async () => {
  await assert.rejects(decodeSyncJson(new Uint8Array([68, 83, 89, 78, 2, 1])));
  await assert.rejects(decodeSyncJson(new Uint8Array([68, 83, 89, 78, 1, 1, 0])));
  const encoded = await encodeSyncJson({ text: "repeat".repeat(1000) });
  await assert.rejects(decodeSyncJson(encoded.subarray(0, encoded.length - 5)));
});
test("decompression stops when a gzip payload expands beyond the session bound", async () => {
  const oversized = new TextEncoder().encode(JSON.stringify("x".repeat(MAX_SYNC_PLAIN_BYTES)));
  const gzip = new Uint8Array(await new Response(new Blob([oversized]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
  const wrapped = new Uint8Array(gzip.length + 6); wrapped.set([68, 83, 89, 78, 1, 1]); wrapped.set(gzip, 6);
  await assert.rejects(decodeSyncJson(wrapped), /exceeds 16 MiB/);
});
