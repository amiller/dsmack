import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "../payments/schema.mjs";
import { canonicalFleet, fleet } from "./fleet.mjs";
import { nodeStatus } from "./node-status.mjs";
import { signingKey } from "./grants.mjs";
import { hex } from "../../dstack-compat/secret-release/policy.mjs";

const post = body => new Request("https://broker.test/fleet", { method: "POST", body: JSON.stringify(body) });
const sign = async (wallet, body) => ({ ...body, signature: await wallet.signMessage("dsmack-fleet/1\n" + canonicalFleet(body)) });
function status(wallet, payout, updated_at) {
  return { publisher: wallet.address.toLowerCase(), payout, updated_at, version: "test-commit",
    hardware: { name: "Mac mini", model: "Mac16,11", chip: "Apple M4 Pro", mem_bytes: 64 * 2 ** 30, cores: 14 },
    config: { max_guests: 4, guest: { mem_mib: 4096, vcpus: 1 }, reserve: { mem_gb: 16, cores: 4 } },
    slots: [{ slot_id: 0, state: "ready", relay_peer: "guest", run_id: "run", jobs_served: 2 }],
    classes: ["0x" + "ab".repeat(32)], errors: [{ at: updated_at - 5, slot_id: 1, error: "guest job timed out" }] };
}

test("fleet authenticates publisher and pinned payout; replay cannot revive an offline Mac", async () => {
  const wallet = Wallet.createRandom(), other = Wallet.createRandom();
  const payout = other.address.toLowerCase(), publishers = { [wallet.address.toLowerCase()]: payout };
  let now = 1793372400;
  const heartbeat = await sign(wallet, status(wallet, payout, now));
  const send = value => fleet(post(value), publishers, undefined, () => now);
  assert.equal((await send({ ...heartbeat, payout: wallet.address.toLowerCase() })).status, 403);
  assert.equal((await send({ ...heartbeat, version: "forged" })).status, 400);
  assert.equal((await send(await sign(other, status(other, payout, now)))).status, 403);
  assert.equal((await send(heartbeat)).status, 200);
  const get = () => fleet(new Request("https://broker.test/fleet?payout=" + payout), publishers, undefined, () => now);
  let mac = (await (await get()).json())[0];
  assert.equal(mac.online, true); assert.equal(mac.errors[0].error, "guest job timed out");
  now += 20;
  assert.equal((await send(heartbeat)).status, 200);
  mac = (await (await get()).json())[0];
  assert.equal(mac.received_at, now - 20);
  now += 40;
  mac = (await (await get()).json())[0];
  assert.equal(mac.online, false); assert.equal(mac.status, "offline");
  assert.equal((await send(heartbeat)).status, 400);
  const response = await get();
  assert.equal(response.headers.get("access-control-allow-origin"), "*");
});

test("fleet keeps the signed heartbeat and offline timestamp across broker reload", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const path = dir + "/fleet.json", wallet = Wallet.createRandom(), payout = wallet.address.toLowerCase();
    const publishers = { [payout]: payout }, now = 1793372400;
    const heartbeat = await sign(wallet, status(wallet, payout, now));
    assert.equal((await fleet(post(heartbeat), publishers, path, () => now)).status, 200);
    const reloaded = await import("./fleet.mjs?reload=" + Date.now());
    const mac = (await (await reloaded.fleet(new Request("https://broker.test/fleet"), publishers, path, () => now + 61)).json())[0];
    assert.equal(mac.signature, heartbeat.signature); assert.equal(mac.online, false);
    assert.equal(mac.received_at, now);
  } finally { await Deno.remove(dir, { recursive: true }); }
});

test("four rotating slots retain their signed proofs and all ten full error bodies", async () => {
  const wallet = Wallet.createRandom(), payout = wallet.address.toLowerCase(), now = 1793372400;
  const body = status(wallet, payout, now);
  body.slots = Array.from({ length: 8 }, (_, i) => ({ slot_id: i % 4, state: i < 4 ? "ready" : "draining",
    attestation: { proof: "ab".repeat(3000) } }));
  body.errors = Array.from({ length: 10 }, (_, i) => ({ slot_id: i % 4, at: now, error: "broker HTTP 503", body: "x".repeat(4096) }));
  const heartbeat = await sign(wallet, body);
  assert(JSON.stringify(heartbeat).length > 65536);
  const response = await fleet(post(heartbeat), { [payout]: payout }, undefined, () => now);
  assert.equal(response.status, 200);
  const saved = await response.json();
  assert.deepEqual(saved.slots, body.slots); assert.deepEqual(saved.errors, body.errors);
});

test("guest workload counters require the attested receipt key signature", async () => {
  const key = await signingKey("61".repeat(32)), now = 1793372400;
  const value = { relay_peer: "guest", updated_at: now, busy: true, jobs_served: 4, last_error: "worker deadline_exceeded" };
  const signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.priv,
    new TextEncoder().encode("dsmack-node-status/1\n" + canonicalFleet(value)))));
  const registration = { relay_peer: "guest", receipt_key: key.public_key, telemetry: { ...value, signature } };
  assert.deepEqual(await nodeStatus(registration, now), registration.telemetry);
  await assert.rejects(nodeStatus({ ...registration, telemetry: { ...registration.telemetry, jobs_served: 99 } }, now), /telemetry/);
  await assert.rejects(nodeStatus(registration, now + 61), /telemetry/);
});
