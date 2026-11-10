import assert from "node:assert/strict";
import { drain } from "./server.ts";

const hash = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))), x => x.toString(16).padStart(2, "0")).join("");

Deno.test("only the operator can drain and resume the broker", async () => {
  const b = {} as Parameters<typeof drain>[1] & { draining?: boolean };
  const operator = await hash("operator-fixture");
  const post = (auth?: string) => new Request("http://broker/drain", { method: "POST", headers: auth ? { authorization: auth } : {} });
  assert.equal((await drain(post(), b, operator)).status, 403);
  assert.equal((await drain(post("Bearer wrong"), b, operator)).status, 403);
  assert.equal((await drain(post("Bearer operator-fixture"), b, undefined)).status, 403);
  assert.equal(b.draining, undefined);
  assert.deepEqual(await (await drain(post("Bearer operator-fixture"), b, operator)).json(), { draining: true });
  assert.equal(b.draining, true);
  assert.equal((await drain(new Request("http://broker/drain", { method: "DELETE" }), b, operator)).status, 403);
  assert.deepEqual(await (await drain(new Request("http://broker/drain", { method: "DELETE", headers: { authorization: "Bearer operator-fixture" } }), b, operator)).json(), { draining: false });
  assert.equal(b.draining, false);
});
