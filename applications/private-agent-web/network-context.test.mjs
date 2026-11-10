import assert from "node:assert/strict";
import { test } from "node:test";
import { macName, sandboxLabel } from "./network-context.mjs";

test("each Mac gets a stable two-word name from its publisher key, shown in the sandbox label", () => {
  const mac = { publisher: "0xa43f9f32411358c1319cb36027650a206644c131", chip: "Apple M4 Pro" };
  assert.equal(macName(mac.publisher), macName(mac.publisher.toUpperCase().replace("0X", "0x")));
  assert.match(macName(mac.publisher), /^[a-z]+-[a-z]+$/);
  assert.notEqual(macName(mac.publisher), macName("0x1fbe7a7b3f7a37a967f3d927abd6f04db2766c5b"));
  assert.equal(sandboxLabel(mac), `Dsmack sandbox · ${macName(mac.publisher)}, M4 Pro`);
  assert.equal(sandboxLabel(undefined), "Dsmack sandbox");
});
