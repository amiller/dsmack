import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "../payments/schema.mjs";
import { canonicalFleet, fleet } from "./fleet.mjs";
import { ownershipDomain, ownershipTypes } from "./ownership.mjs";
import { nodeStatus } from "./node-status.mjs";
import { signingKey } from "./grants.mjs";
import { hex } from "../../dstack-compat/secret-release/policy.mjs";

const post = body => new Request("https://broker.test/fleet", { method: "POST", body: JSON.stringify(body) });
const sign = async (wallet, body) => ({ ...body, signature: await wallet.signMessage("dsmack-fleet/1\n" + canonicalFleet(body)) });
function status(wallet, updated_at) {
  return { publisher: wallet.address.toLowerCase(), updated_at, version: "test-commit",
    hardware: { name: "Mac mini", model: "Mac16,11", chip: "Apple M4 Pro", mem_bytes: 64 * 2 ** 30, cores: 14 },
    config: { max_guests: 4, guest: { mem_mib: 4096, vcpus: 1 }, reserve: { mem_gb: 16, cores: 4 } },
    slots: [{ slot_id: 0, state: "ready", relay_peer: "guest", run_id: "run", jobs_served: 2 }],
    classes: ["0x" + "ab".repeat(32)], errors: [{ at: updated_at - 5, slot_id: 1, error: "guest job timed out" }] };
}

const escrow = "0x" + "17".repeat(20), domain = ownershipDomain(escrow);
async function link(wallet, operator = wallet, path) {
  const link = { kid: "0x" + wallet.address.slice(2).toLowerCase().padStart(64, "0"), publisher: wallet.address.toLowerCase(), operator: operator.address.toLowerCase(), nonce: "0" };
  const types = { MacLink: ownershipTypes.MacLink };
  const body = { link, operatorSignature: await operator.signTypedData(domain, types, link), publisherSignature: await wallet.signTypedData(domain, types, link) };
  assert.equal((await fleet(new Request("https://broker.test/fleet/link", { method: "POST", body: JSON.stringify(body) }), escrow, path)).status, 200);
}

test("fleet derives operator from the link; replay cannot revive an offline Mac", async () => {
  const wallet = Wallet.createRandom(), other = Wallet.createRandom();
  let now = 1793372400;
  const heartbeat = await sign(wallet, status(wallet, now));
  const send = value => fleet(post(value), escrow, undefined, () => now);
  assert.equal((await send(heartbeat)).status, 403);
  await link(wallet, other);
  assert.equal((await send(await sign(wallet, { ...status(wallet, now), operator: wallet.address.toLowerCase() }))).status, 400);
  assert.equal((await send(await sign(wallet, { ...status(wallet, now), payout: other.address.toLowerCase() }))).status, 400);
  assert.equal((await send({ ...heartbeat, version: "forged" })).status, 400);
  assert.equal((await send(await sign(other, status(other, now)))).status, 403);
  assert.equal((await send(heartbeat)).status, 200);
  const get = () => fleet(new Request("https://broker.test/fleet?operator=" + other.address.toLowerCase()), escrow, undefined, () => now);
  let mac = (await (await get()).json())[0];
  assert.equal(mac.online, true); assert.equal(mac.errors[0].error, "guest job timed out");
  assert.equal(mac.operator, other.address.toLowerCase()); assert.equal(mac.capacity, "reported");
  assert(!("payout" in mac));
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

test("fleet keeps link, signed heartbeat and offline timestamp across broker reload", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const path = dir + "/fleet.json", wallet = Wallet.createRandom(), now = 1793372400;
    await link(wallet, wallet, path);
    const heartbeat = await sign(wallet, status(wallet, now));
    assert.equal((await fleet(post(heartbeat), escrow, path, () => now)).status, 200);
    const reloaded = await import("./fleet.mjs?reload=" + Date.now());
    const mac = (await (await reloaded.fleet(new Request("https://broker.test/fleet"), escrow, path, () => now + 61)).json())[0];
    assert.equal(mac.signature, heartbeat.signature); assert.equal(mac.online, false);
    assert.equal(mac.received_at, now); assert.equal(mac.link.link.operator, wallet.address.toLowerCase());
  } finally { await Deno.remove(dir, { recursive: true }); }
});

test("unsigned legacy publisher payout records stay hidden until a signed link arrives", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const path = dir + "/fleet.json", wallet = Wallet.createRandom(), publisher = wallet.address.toLowerCase(), now = 1793372400;
    const heartbeat = await sign(wallet, { ...status(wallet, now), payout: publisher });
    await Deno.writeTextFile(path, JSON.stringify({ [publisher]: { ...heartbeat, received_at: now } }));
    const get = () => fleet(new Request("https://broker.test/fleet"), escrow, path, () => now);
    assert.deepEqual(await (await get()).json(), []);
    await link(wallet, wallet, path);
    const visible = (await (await get()).json())[0];
    assert.equal(visible.operator, publisher); assert(!("payout" in visible));
    const ownership = await (await fleet(new Request("https://broker.test/fleet/ownership?publisher=" + publisher), escrow, path)).json();
    assert.equal(ownership.links.length, 1); assert.equal(ownership.nonces.publishers[publisher], "0");
  } finally { await Deno.remove(dir, { recursive: true }); }
});

test("four rotating slots retain their signed proofs and all ten full error bodies", async () => {
  const wallet = Wallet.createRandom(), now = 1793372400;
  await link(wallet);
  const body = status(wallet, now);
  body.slots = Array.from({ length: 8 }, (_, i) => ({ slot_id: i % 4, state: i < 4 ? "ready" : "draining",
    attestation: { proof: "ab".repeat(3000) } }));
  body.errors = Array.from({ length: 10 }, (_, i) => ({ slot_id: i % 4, at: now, error: "broker HTTP 503", body: "x".repeat(4096) }));
  const heartbeat = await sign(wallet, body);
  assert(JSON.stringify(heartbeat).length > 65536);
  const response = await fleet(post(heartbeat), escrow, undefined, () => now);
  assert.equal(response.status, 200);
  const saved = await response.json();
  assert.deepEqual(saved.slots, body.slots); assert.deepEqual(saved.errors, body.errors);
});

test("signed optional regions accept whole-degree opt-in and reject precise or unsigned location", async () => {
  const wallet = Wallet.createRandom(), now = 1793372500;
  await link(wallet);
  const region = { name: "Michigan, US", lat: 42, lon: -84 };
  const send = value => fleet(post(value), escrow, undefined, () => now);
  const heartbeat = await sign(wallet, { ...status(wallet, now), region });
  const response = await send(heartbeat);
  assert.equal(response.status, 200); assert.deepEqual((await response.json()).region, region);
  assert.equal((await send({ ...heartbeat, region: { ...region, lat: 43 } })).status, 400);
  for (const bad of [{ ...region, lat: 42.1 }, { ...region, lon: 181 }, { ...region, name: "" },
    { ...region, ip: "private" }, null]) {
    assert.equal((await send(await sign(wallet, { ...status(wallet, now + 1), region: bad }))).status, 400);
  }
  const optedOut = await send(await sign(wallet, status(wallet, now + 2)));
  assert.equal(optedOut.status, 200); assert(!("region" in await optedOut.json()));
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
