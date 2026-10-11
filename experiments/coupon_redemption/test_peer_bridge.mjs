import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createCouponPeerService, COUPON_PROTOCOL, COUPON_PROTOCOL_V2, COUPON_PROTOCOL_V3, COUPON_PROTOCOL_V4, ISSUER_PROTOCOL, MAX_ISSUER_FRAME, MAX_FRAME } from './peer_bridge.mjs';

const context = peer => Object.freeze({ remotePeer: peer, localPeer: 'Host1',
  protocol: COUPON_PROTOCOL, authenticated: true, transport: 'noise' });

async function fixture(t, options = {}, extraConfig = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-bridge-'));
  const configPath = path.join(root, 'config.json');
  const config = { version: 1, state_dir: path.join(root, 'state'),
    sponsor_subject: 'peer:sponsor', observer_subject: 'peer:observer', provider: { mode: 'synthetic' },
    peers: { Sponsor1: { subject: 'peer:sponsor', roles: ['sponsor'] },
      Recipient1: { subject: 'peer:recipient', roles: ['recipient'] },
      Observer1: { subject: 'peer:observer', roles: ['observer'] } }, ...extraConfig };
  await fs.writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const bridge = await createCouponPeerService({ configPath, startupTimeoutMs: 10000, ...options });
  t.after(async () => { await bridge.close(); await fs.rm(root, { recursive: true, force: true }); });
  return { bridge, root, configPath, config };
}

async function dispatch(bridge, peer, frame) {
  let response;
  await bridge.service.handle({}, async value => { response = value; },
    async () => Buffer.isBuffer(frame) ? frame : Buffer.from(JSON.stringify(frame)), context(peer));
  return JSON.parse(response);
}

function query(root, sql) {
  const result = spawnSync('python3', ['-c', 'import sqlite3,sys,json; c=sqlite3.connect(sys.argv[1]); print(json.dumps(c.execute(sys.argv[2]).fetchall()))',
    path.join(root, 'state', 'state.sqlite'), sql], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

async function dispatchV2(bridge, peer, frame, localPeer = 'Host1') {
  let response;
  await bridge.serviceV2.handle({}, async value => { response = value; },
    async () => Buffer.from(JSON.stringify(frame)),
    { ...context(peer), protocol: COUPON_PROTOCOL_V2, localPeer });
  return JSON.parse(response);
}

async function dispatchV3(bridge, peer, frame, localPeer = 'Host1') {
  let response;
  await bridge.serviceV3.handle({}, async value => { response = value; },
    async () => Buffer.from(JSON.stringify(frame)),
    { ...context(peer), protocol: COUPON_PROTOCOL_V3, localPeer });
  return JSON.parse(response);
}

test('accountless mount binds first unknown peer and refuses role escalation or loser replay', async t => {
  const { bridge, root } = await fixture(t, {}, { issuer_peer_id: 'Host1' });
  const sponsor = { ...context('Sponsor1'), protocol: COUPON_PROTOCOL_V3 };
  const bundle = await bridge.provisionV3(sponsor, '5000000000', '2030-10-10T00:00:00Z');
  const { coupon, offer_hash } = bundle;
  const base = { id: 'r', coupon };
  for (const peer of ['GuestA', 'GuestB']) {
    assert.equal((await dispatchV3(bridge, peer, { ...base, op: 'offer' })).result.offer_hash, offer_hash);
    assert.equal((await dispatchV3(bridge, peer, { ...base, op: 'status' })).result.state, 'ready');
  }
  await assert.rejects(bridge.provisionV3({ ...sponsor, remotePeer: 'GuestA' }, '1', '2030-10-10T00:00:00Z'));
  const claim = { ...base, op: 'claim', offer_hash, recipient_key: Buffer.alloc(32, 9).toString('base64') };
  assert.equal((await dispatchV3(bridge, 'GuestA', { ...claim, roles: ['sponsor'] })).ok, false);
  assert.equal((await dispatchV3(bridge, 'GuestA', claim, 'WrongHost1')).ok, false);
  assert.equal((await dispatchV2(bridge, 'Recipient1', claim)).ok, false);
  assert.equal((await dispatch(bridge, 'Recipient1', { ...base, op: 'claim', recipient_key: claim.recipient_key })).ok, false);
  const expired = await bridge.provisionV3(sponsor, '1', '2000-10-10T00:00:00Z');
  assert.equal((await dispatchV3(bridge, 'GuestA', { ...claim, coupon: expired.coupon, offer_hash: expired.offer_hash })).ok, false);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[0]]);
  const results = await Promise.all(['GuestA', 'GuestB'].map(peer => dispatchV3(bridge, peer, claim)));
  assert.equal(results.filter(result => result.ok).length, 1);
  const winner = results[0].ok ? 'GuestA' : 'GuestB';
  const loser = winner === 'GuestA' ? 'GuestB' : 'GuestA';
  const first = results.find(result => result.ok);
  const envelope = JSON.parse(first.result.envelope);
  assert.equal(JSON.parse(Buffer.from(envelope.aad, 'base64')).domain, 'dsmack-coupon-delivery-v3');
  for (const op of ['offer', 'status']) assert.equal((await dispatchV3(bridge, loser, { ...base, op })).ok, false);
  assert.deepEqual(query(root, 'SELECT peer FROM service_v3_claims'), [[winner]]);
  await bridge.restart();
  assert.deepEqual(await dispatchV3(bridge, winner, claim), first);
  assert.equal((await dispatchV3(bridge, loser, claim)).ok, false);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[1]]);
  const observation = { ...base, op: 'observe', start: '2026-10-10T00:00:00Z',
    end: '2026-10-11T00:00:00Z', challenge: 'ab'.repeat(32) };
  assert.equal((await dispatchV3(bridge, winner, observation)).ok, false);
  assert.equal((await dispatchV3(bridge, loser, observation)).ok, false);
  const observed = await dispatchV3(bridge, 'Observer1', observation);
  assert.equal(observed.result.payload.domain, 'dsmack-coupon-observation-v3');
  assert.equal(observed.result.payload.offer_hash, offer_hash);
  assert.equal(typeof observed.result.payload.recipient_peer_sha256, 'string');
});

test('v2 worker pins issuer, stores accepted offers and separates old protocol coupons', async t => {
  const { bridge, root } = await fixture(t, {}, { issuer_peer_id: 'Host1' });
  const sponsor = { ...context('Sponsor1'), protocol: COUPON_PROTOCOL_V2 };
  const bundle = await bridge.provisionV2(sponsor, '9223372036854775807', 'Recipient1', '2030-10-10T00:00:00Z');
  const { coupon, offer_hash } = bundle;
  assert.equal(bundle.offer.budget_nano_usd, '9223372036854775807');
  assert.equal(bundle.offer.issuer.peer_id, 'Host1');
  const request = { id: 'o', op: 'offer', coupon };
  assert.equal((await dispatchV2(bridge, 'Recipient1', request)).result.offer_hash, offer_hash);
  assert.equal((await dispatchV2(bridge, 'Recipient1', request, 'WrongHost1')).ok, false);
  assert.equal((await dispatchV2(bridge, 'Unknown1', request)).ok, false);
  await assert.rejects(bridge.provisionV2({ ...sponsor, localPeer: 'WrongHost1' }, '1', 'Recipient1', '2030-10-10T00:00:00Z'));
  const recipient_key = Buffer.alloc(32, 9).toString('base64');
  const claim = { id: 'c', op: 'claim', coupon, recipient_key, offer_hash };
  assert.equal((await dispatch(bridge, 'Recipient1', { id: 'c', op: 'claim', coupon, recipient_key })).ok, false);
  assert.equal((await dispatchV2(bridge, 'Recipient1', { ...claim, offer_hash: 'ab'.repeat(32) })).ok, false);
  const v1 = await bridge.provision(context('Sponsor1'), 1, 'Recipient1');
  assert.equal((await dispatchV2(bridge, 'Recipient1', { ...claim, coupon: v1.coupon })).ok, false);
  const expired = await bridge.provisionV2(sponsor, '1', 'Recipient1', '2000-10-10T00:00:00Z');
  assert.equal((await dispatchV2(bridge, 'Recipient1', { ...claim, coupon: expired.coupon, offer_hash: expired.offer_hash })).ok, false);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[0]]);
  const delivered = await dispatchV2(bridge, 'Recipient1', claim);
  assert.equal(delivered.ok, true);
  const binding = JSON.parse(Buffer.from(JSON.parse(delivered.result.envelope).aad, 'base64'));
  assert.equal(binding.offer_hash, offer_hash);
  assert.equal(binding.domain, 'dsmack-coupon-delivery-v2');
  await bridge.restart();
  assert.deepEqual(await dispatchV2(bridge, 'Recipient1', claim), delivered);
  assert.deepEqual((await dispatchV2(bridge, 'Recipient1', request)).result,
    { offer: bundle.offer, offer_hash });
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[1]]);
  const observation = await dispatchV2(bridge, 'Observer1', { id: 'obs', op: 'observe', coupon,
    start: '2026-10-10T00:00:00Z', end: '2026-10-11T00:00:00Z', challenge: 'ab'.repeat(32) });
  assert.equal(observation.result.payload.offer_hash, offer_hash);
  assert.equal(observation.result.payload.domain, 'dsmack-coupon-observation-v2');
});

test('per-peer pacing shares a bounded bucket across both coupon protocols', async t => {
  const { bridge } = await fixture(t, { rateCapacity: 1, rateRefillPerSecond: 0.001 }, { issuer_peer_id: 'Host1' });
  const { coupon } = await bridge.provision(context('Sponsor1'), 1, 'Recipient1');
  assert.equal((await dispatch(bridge, 'Recipient1', { id: 's', op: 'status', coupon })).ok, true);
  let read = false, response;
  await bridge.serviceV2.handle({}, async value => { response = value; },
    async () => { read = true; return Buffer.from('{}'); },
    { ...context('Recipient1'), protocol: COUPON_PROTOCOL_V2 });
  assert.equal(read, false);
  assert.equal(JSON.parse(response).ok, false);
  assert.equal((await dispatch(bridge, 'Sponsor1', { id: 's', op: 'status', coupon })).ok, true);
});

test('bounded pacing identities age out so a later peer can be admitted', async t => {
  const { bridge } = await fixture(t, { rateCapacity: 1, rateRefillPerSecond: 10, maxRatePeers: 1 });
  const { coupon } = await bridge.provision(context('Sponsor1'), 1, 'Recipient1');
  assert.equal((await dispatch(bridge, 'Unknown1', { id: 's', op: 'status', coupon })).ok, false);
  assert.equal((await dispatch(bridge, 'Recipient1', { id: 's', op: 'status', coupon })).ok, false);
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal((await dispatch(bridge, 'Recipient1', { id: 's', op: 'status', coupon })).ok, true);
});

test('anonymous-pipe mount enforces ACL, exact frames, role boundaries and durable replay', async t => {
  const { bridge, root } = await fixture(t);
  const { coupon } = await bridge.provision(context('Sponsor1'), 5_000_000_000, 'Recipient1');
  await assert.rejects(bridge.provision(context('Recipient1'), 1, 'Recipient1'));
  await assert.rejects(bridge.provision(context('Unknown1'), 1, 'Recipient1'));
  for (const ctx of [null, { ...context('Sponsor1'), authenticated: false },
    { ...context('Sponsor1'), transport: 'plaintext' }, { ...context('Sponsor1'), protocol: '/wrong' }]) {
    await assert.rejects(bridge.provision(ctx, 1, 'Recipient1'));
  }
  const recipient_key = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)).toString('base64');
  const claim = { id: 'claim1', op: 'claim', coupon, recipient_key };
  for (const peer of ['Sponsor1', 'Observer1', 'Unknown1']) {
    assert.equal((await dispatch(bridge, peer, claim)).ok, false);
  }
  for (const frame of [Buffer.alloc(MAX_FRAME + 1), Buffer.from('{"id":"a","id":"b"}'),
    { ...claim, principal: { subject: 'peer:recipient', roles: ['recipient'] } },
    { ...claim, op: 'provision' }]) {
    assert.equal((await dispatch(bridge, 'Recipient1', frame)).ok, false);
  }
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[0]]);
  const first = await dispatch(bridge, 'Recipient1', claim);
  assert.equal(first.ok, true);
  assert.equal(JSON.stringify(first).includes('synthetic-only-'), false);
  const before = await fs.readFile(path.join(root, 'state', 'observer.key'));
  await bridge.restart();
  assert.deepEqual(await dispatch(bridge, 'Recipient1', claim), first);
  assert.deepEqual(await fs.readFile(path.join(root, 'state', 'observer.key')), before);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[1]]);
  const observation = { id: 'obs1', op: 'observe', coupon, start: '2026-10-10T00:00:00Z',
    end: '2026-10-11T00:00:00Z', challenge: 'ab'.repeat(32) };
  assert.equal((await dispatch(bridge, 'Recipient1', observation)).ok, false);
  assert.equal((await dispatch(bridge, 'Observer1', { ...observation, rows: [] })).ok, false);
  assert.equal((await dispatch(bridge, 'Observer1', observation)).result.payload.environment, 'local-unattested');
  assert.equal((await dispatch(bridge, 'Sponsor1', { id: 's', op: 'status', coupon })).result.deposit_release_authorized, false);
});

test('single store lock and concurrent operator lifecycle fail closed', async t => {
  const { bridge, configPath } = await fixture(t);
  await assert.rejects(createCouponPeerService({ configPath }));
  const restarting = bridge.restart();
  await assert.rejects(bridge.restart(), /busy/);
  await restarting;
  await bridge.close();
  await assert.rejects(bridge.provision(context('Sponsor1'), 1, 'Recipient1'));
  await assert.rejects(bridge.restart(), /closed/);
});

test('queue admission is bounded and does not dispatch rejected requests', async t => {
  const { bridge, root } = await fixture(t, { maxQueue: 1 });
  const first = bridge.provision(context('Sponsor1'), 1, 'Recipient1');
  await assert.rejects(bridge.provision(context('Sponsor1'), 1, 'Recipient1'), /unavailable/);
  await first;
  assert.deepEqual(query(root, 'SELECT count(*) FROM coupons'), [[1]]);
});

test('worker inherits only the documented environment allowlist', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-env-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const wrapper = path.join(temporary, 'python');
  const captured = path.join(temporary, 'environment.json');
  await fs.writeFile(wrapper, `#!/usr/bin/env python3
import os,sys,json,pathlib
pathlib.Path(${JSON.stringify(captured)}).write_text(json.dumps(dict(os.environ)))
sys.path.insert(0,os.getcwd())
from experiments.coupon_redemption.peer_worker import main
raise SystemExit(main(sys.argv[3:]))
`, { mode: 0o700 });
  const original = Object.fromEntries(['COUPON_ENV_CANARY', 'PYTHONPATH', 'PYTHONHOME']
    .map(key => [key, process.env[key]]));
  try {
    process.env.COUPON_ENV_CANARY = 'synthetic-host-token';
    process.env.PYTHONPATH = '/synthetic/untrusted/imports';
    process.env.PYTHONHOME = '/synthetic/untrusted/runtime';
    const { bridge } = await fixture(t, { python: wrapper });
    await bridge.close();
    const environment = JSON.parse(await fs.readFile(captured, 'utf8'));
    for (const key of Object.keys(original)) assert.equal(environment[key], undefined);
    assert.equal(environment.PYTHONUNBUFFERED, '1');
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('stream read and send deadlines abort without retaining the handler', async t => {
  const { bridge } = await fixture(t, { timeoutMs: 150 });
  let aborts = 0;
  const lp = { unwrap: () => ({ abort: () => { aborts++; } }) };
  await bridge.service.handle(lp, async () => {}, () => new Promise(() => {}), context('Recipient1'));
  await assert.rejects(bridge.service.handle(lp, () => new Promise(() => {}), async () => Buffer.from('{}'), context('Recipient1')), /timeout/);
  assert.equal(aborts, 2);
});

test('worker timeout kills descendants and preserves nonretryable issuing through restart', async t => {
  const { bridge, root, configPath } = await fixture(t, { timeoutMs: 250 });
  const { coupon } = await bridge.provision(context('Sponsor1'), 1, 'Recipient1');
  await bridge.close();
  const wrapper = path.join(root, 'slow-python');
  await fs.writeFile(wrapper, `#!/usr/bin/env python3
import sys,time,subprocess,pathlib,os,signal
sys.path.insert(0,os.getcwd())
from experiments.coupon_redemption import peer_worker
original=peer_worker.SyntheticProvider.create_key
def slow(self,name,budget):
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    self.store.db.execute("INSERT INTO synthetic_events VALUES ('attempt')")
    child=subprocess.Popen(['sleep','60'])
    pathlib.Path(${JSON.stringify(path.join(root, 'descendant.pid'))}).write_text(str(child.pid))
    time.sleep(60)
    return original(self,name,budget)
peer_worker.SyntheticProvider.create_key=slow
raise SystemExit(peer_worker.main(sys.argv[3:]))
`, { mode: 0o700 });
  const slow = await createCouponPeerService({ configPath, python: wrapper, timeoutMs: 250, startupTimeoutMs: 10000 });
  t.after(() => slow.close());
  const claim = { id: 'c', op: 'claim', coupon, recipient_key: Buffer.alloc(32, 9).toString('base64') };
  assert.equal((await dispatch(slow, 'Recipient1', claim)).ok, false);
  await slow.close();
  const pid = Number(await fs.readFile(path.join(root, 'descendant.pid'), 'utf8'));
  const proc = await fs.readFile(`/proc/${pid}/stat`, 'utf8').catch(() => 'gone');
  assert.ok(proc === 'gone' || proc.split(' ')[2] === 'Z', 'provider descendant must be stopped');
  const recovered = await createCouponPeerService({ configPath });
  t.after(() => recovered.close());
  assert.equal((await dispatch(recovered, 'Recipient1', claim)).ok, false);
  assert.equal((await recovered.pending(context('Sponsor1'))).pending[0].state, 'issuing');
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='attempt'"), [[1]]);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[0]]);
  await recovered.close();
});


test('issuer discovery is pre-bearer, binds actual signer and peer, and v4 cannot bypass legacy routes', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-issuer-v4-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const exported = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_issuer_fixture'], { encoding: 'utf8' });
  assert.equal(exported.status, 0, exported.stderr);
  const vector = JSON.parse(exported.stdout);
  const compose = path.join(temporary, 'compose.json');
  await fs.writeFile(compose, vector.app_compose, { mode: 0o600 });
  const wrapper = path.join(temporary, 'python');
  await fs.writeFile(wrapper, `#!/usr/bin/env python3
import sys,os
sys.path.insert(0,os.getcwd())
from experiments.coupon_redemption import peer_worker
from experiments.coupon_redemption.test_issuer_fixture import synthetic_worker
peer_worker.Worker=synthetic_worker
raise SystemExit(peer_worker.main(sys.argv[3:]))
`, { mode: 0o700 });
  const issuer = 'IssuerPeer00000001';
  const { bridge, root } = await fixture(t, { python: wrapper }, { issuer_peer_id: issuer,
    issuer_evidence: { identity_policy_sha256: vector.identity_policy_sha256,
      issuance_policy_sha256: vector.issuance_policy_sha256, socket_path: '/synthetic/test-only.sock', compose_file: compose } });
  const call = async (service, protocol, peer, request, localPeer = issuer) => {
    let response;
    await service.handle({}, async value => { response = value; }, async () => Buffer.from(JSON.stringify(request)),
      { ...context(peer), localPeer, protocol });
    return JSON.parse(response);
  };
  assert.equal(bridge.issuerService.maxDataLength, MAX_ISSUER_FRAME);
  assert.equal(bridge.serviceV4.maxDataLength, MAX_FRAME);
  const info = (await call(bridge.issuerService, ISSUER_PROTOCOL, 'UnknownGuest', { id: 'i', op: 'info' })).result;
  assert.equal(info.identity_policy_sha256, vector.identity_policy_sha256);
  assert.deepEqual(query(root, 'SELECT count(*) FROM coupons'), [[0]]);
  const binding = { version: 2, peer_id: issuer, public_key_hex: info.issuer_public_key_hex,
    challenge_hex: 'ab'.repeat(32), policy_sha256: info.identity_policy_sha256 };
  const evidence = await call(bridge.issuerService, ISSUER_PROTOCOL, 'UnknownGuest', { id: 'e', op: 'evidence', binding });
  assert.equal(evidence.ok, true);
  assert.deepEqual(evidence.result.binding, binding);
  for (const change of [{ peer_id: 'OtherIssuer000001' }, { policy_sha256: '00'.repeat(32) }, { public_key_hex: '00'.repeat(32) }])
    assert.equal((await call(bridge.issuerService, ISSUER_PROTOCOL, 'UnknownGuest', { id: 'e', op: 'evidence', binding: { ...binding, ...change } })).ok, false);
  assert.equal((await call(bridge.issuerService, ISSUER_PROTOCOL, 'UnknownGuest', { id: 'i', op: 'info' }, 'WrongLocalPeer')).ok, false);
  const sponsor = { ...context('Sponsor1'), localPeer: issuer, protocol: COUPON_PROTOCOL_V4 };
  const bundle = await bridge.provisionV4(sponsor, '5000000000', '2030-10-10T00:00:00Z');
  const claim = { id: 'c', op: 'claim', coupon: bundle.coupon, offer_hash: bundle.offer_hash, recipient_key: Buffer.alloc(32, 9).toString('base64') };
  const first = await call(bridge.serviceV4, COUPON_PROTOCOL_V4, 'GuestWinner', claim);
  assert.equal(first.ok, true);
  assert.equal(JSON.parse(Buffer.from(JSON.parse(first.result.envelope).aad, 'base64')).version, 4);
  await bridge.restart();
  assert.deepEqual(await call(bridge.serviceV4, COUPON_PROTOCOL_V4, 'GuestWinner', claim), first);
  assert.equal((await call(bridge.serviceV4, COUPON_PROTOCOL_V4, 'GuestLoser', claim)).ok, false);
  assert.equal((await call(bridge.serviceV3, COUPON_PROTOCOL_V3, 'GuestWinner', claim)).ok, false);
  assert.equal((await call(bridge.serviceV2, COUPON_PROTOCOL_V2, 'Recipient1', claim)).ok, false);
  assert.deepEqual(query(root, "SELECT count(*) FROM synthetic_events WHERE kind='create'"), [[1]]);
});


test('separate startup deadline kills a hung worker group before advertising readiness', async t => {
  const { bridge, configPath, root } = await fixture(t);
  await bridge.close();
  const wrapper = path.join(root, 'hung-startup');
  const parentFile = path.join(root, 'startup-parent.pid'), childFile = path.join(root, 'startup-child.pid');
  await fs.writeFile(wrapper, `#!/usr/bin/env python3
import os,pathlib,signal,subprocess,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pathlib.Path(${JSON.stringify(parentFile)}).write_text(str(os.getpid()))
child=subprocess.Popen(['sleep','60'])
pathlib.Path(${JSON.stringify(childFile)}).write_text(str(child.pid))
time.sleep(60)
`, { mode: 0o700 });
  await assert.rejects(createCouponPeerService({ configPath, python: wrapper, timeoutMs: 10000, startupTimeoutMs: 1000 }), /unavailable/);
  // startup rejection starts shutdown; wait for the documented bounded reap.
  const parent = Number(await fs.readFile(parentFile, 'utf8'));
  const child = Number(await fs.readFile(childFile, 'utf8'));
  await new Promise(resolve => setTimeout(resolve, 750));
  for (const pid of [parent, child]) {
    const state = await fs.readFile(`/proc/${pid}/stat`, 'utf8').catch(() => 'gone');
    assert.ok(state === 'gone' || state.split(' ')[2] === 'Z', 'hung startup descendant must be stopped');
  }
});


test('async /4 fixture mount holds claims in progress, delivers once, never auto-retries', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-async-v4-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const exported = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_issuer_fixture'], { encoding: 'utf8' });
  assert.equal(exported.status, 0, exported.stderr);
  const vector = JSON.parse(exported.stdout);
  const compose = path.join(temporary, 'compose.json');
  await fs.writeFile(compose, vector.app_compose, { mode: 0o600 });
  // Exactly the client lane's mounting convention: patch peer_worker.Worker.
  const wrapper = path.join(temporary, 'python');
  await fs.writeFile(wrapper, `#!/usr/bin/env python3
import sys,os
sys.path.insert(0,os.getcwd())
from experiments.coupon_redemption import peer_worker
from experiments.coupon_redemption.test_async_fixture import async_fixture_worker
peer_worker.Worker=async_fixture_worker
raise SystemExit(peer_worker.main(sys.argv[3:]))
`, { mode: 0o700 });
  const issuer = 'IssuerPeer00000001';
  const { bridge, root } = await fixture(t, { python: wrapper, startupTimeoutMs: 20000 }, { issuer_peer_id: issuer,
    issuer_evidence: { identity_policy_sha256: vector.identity_policy_sha256,
      issuance_policy_sha256: vector.issuance_policy_sha256, socket_path: '/synthetic/test-only.sock', compose_file: compose } });
  const gate = path.join(root, 'state', 'async-issuance-gate');
  const effects = path.join(root, 'state', 'async-provider-effects');
  const effectCount = async () => (await fs.readFile(effects, 'utf8').catch(() => '')).split('\n').filter(Boolean).length;
  const call = async (peer, request, localPeer = issuer) => {
    let response;
    await bridge.serviceV4.handle({}, async value => { response = value; }, async () => Buffer.from(JSON.stringify(request)),
      { ...context(peer), localPeer, protocol: COUPON_PROTOCOL_V4 });
    return JSON.parse(response);
  };
  const until = async (predicate, timeoutMs = 15000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const value = await predicate();
      if (value) return value;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('async fixture deadline');
  };
  const waitForState = (peer, request, state) => until(async () => {
    const response = await call(peer, request);
    return response.ok && response.result?.state === state ? response : null;
  });
  const sponsor = { ...context('Sponsor1'), localPeer: issuer, protocol: COUPON_PROTOCOL_V4 };
  const bundle = await bridge.provisionV4(sponsor, '5000000000', '2030-10-10T00:00:00Z');
  const claim = { id: 'c', op: 'claim', coupon: bundle.coupon, offer_hash: bundle.offer_hash,
    recipient_key: Buffer.alloc(32, 9).toString('base64') };
  const status = identifier => ({ ...claim, id: identifier, op: 'status' });
  // Held issuance: the claim is admitted and stays in progress while polling
  // never creates a provider key.
  await fs.writeFile(gate, 'hold');
  assert.equal((await call('GuestWinner', claim)).result.state, 'in_progress');
  assert.equal((await waitForState('GuestWinner', status('s1'), 'in_progress')).result.state, 'in_progress');
  assert.equal(await effectCount(), 0);
  await fs.writeFile(gate, 'grant');
  assert.equal((await waitForState('GuestWinner', status('s2'), 'delivered')).result.state, 'delivered');
  assert.equal(await effectCount(), 1);
  // The winner's replay is the effect-free completion carrying the envelope.
  const replay = await call('GuestWinner', { ...claim, id: 'c2' });
  assert.equal(replay.ok, true);
  assert.equal(typeof replay.result.envelope, 'string');
  assert.equal(JSON.parse(Buffer.from(JSON.parse(replay.result.envelope).aad, 'base64')).version, 4);
  assert.equal(await effectCount(), 1);
  // A crash after the durable intent requires reconciliation and a restart
  // with a granting gate must never resume the interrupted effect.
  const second = await bridge.provisionV4(sponsor, '5000000000', '2030-10-10T00:00:00Z');
  await fs.writeFile(gate, 'crash');
  const crashed = { ...claim, id: 'c3', coupon: second.coupon, offer_hash: second.offer_hash };
  assert.equal((await call('GuestSecond', crashed)).result.state, 'in_progress');
  assert.equal((await waitForState('GuestSecond', { ...crashed, id: 's3', op: 'status' }, 'reconciliation_required')).result.state, 'reconciliation_required');
  await bridge.restart();
  await fs.writeFile(gate, 'grant');
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal((await call('GuestSecond', { ...crashed, id: 's4', op: 'status' })).result.state, 'reconciliation_required');
  assert.equal((await call('GuestSecond', { ...crashed, id: 'c4' })).ok, false);
  assert.equal(await effectCount(), 1, 'interrupted issuance must never auto-retry');
  assert.equal((await bridge.pendingV4(sponsor)).pending.length, 1);
});
