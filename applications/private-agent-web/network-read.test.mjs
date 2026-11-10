import { test } from "node:test";
import assert from "node:assert/strict";
import { readWithRetry } from "./network-read.mjs";

test("a lost browser read gets one retry, preserving the second failure", async () => {
  let calls = 0;
  assert.equal(await readWithRetry(() => { if (++calls === 1) throw new TypeError("Failed to fetch"); return "read"; }), "read");
  assert.equal(calls, 2);
  calls = 0;
  const second = new TypeError("second network failure");
  await assert.rejects(readWithRetry(() => { if (++calls === 1) throw new TypeError("Failed to fetch"); throw second; }), error => error === second);
  assert.equal(calls, 2);
});

test("HTTP failures, invalid replies and cancelled reads are never retried", async () => {
  for (const error of [Object.assign(Error("unavailable"), { status: 503 }), new SyntaxError("invalid JSON"), new DOMException("aborted", "AbortError")]) {
    let calls = 0;
    await assert.rejects(readWithRetry(() => { calls++; throw error; }), value => value === error);
    assert.equal(calls, 1);
  }
  const controller = new AbortController(); controller.abort();
  let calls = 0;
  await assert.rejects(readWithRetry(() => { calls++; throw new TypeError("Failed to fetch"); }, controller.signal));
  assert.equal(calls, 1);
});
