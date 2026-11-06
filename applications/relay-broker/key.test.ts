import assert from "node:assert/strict";
import { test } from "node:test";
import { keyPath } from "./key.ts";

test("the shared broker's GetKey paths are unchanged; the Layover broker's differ; a missing project throws", () => {
  assert.equal(keyPath("relay-broker", "payments-grants-v1"), "/tee-daemon/projects/relay-broker/payments-grants-v1");
  assert.equal(keyPath("relay-broker", "inference-env-v1"), "/tee-daemon/projects/relay-broker/inference-env-v1");
  assert.equal(keyPath("relay-broker-layover", "payments-grants-v1"), "/tee-daemon/projects/relay-broker-layover/payments-grants-v1");
  assert.throws(() => keyPath(undefined as unknown as string, "payments-grants-v1"), /signerProject is required/);
});
