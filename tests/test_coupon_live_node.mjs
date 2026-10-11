// Staging node admission and lifecycle over the explicit synthetic live fixture.
// Runs against the source tree by default, or an exported package via
// DSMACK_PACKAGE_DIR/DSMACK_FIXTURE_DIR like tests/test_coupon_node_issuer.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const sourceRoot = fileURLToPath(new URL('..', import.meta.url));
const packageRoot = process.env.DSMACK_PACKAGE_DIR;
const fixtureRoot = process.env.DSMACK_FIXTURE_DIR ?? sourceRoot;
const root = packageRoot ?? sourceRoot;
const { probeLiveIdentity, prepareStagingDirectory, admitStagingFiles, STAGING_ADMISSION,
  startLiveCouponNode } = await import(pathToFileURL(path.join(root, 'node/coupon-live-node.mjs')));
const { COUPON_PROTOCOL_V4 } = await import(pathToFileURL(path.join(root, 'experiments/coupon_redemption/peer_bridge.mjs')));
const requirePeer = createRequire(path.join(root, 'vendor/abalone/package.json'));
const { generateKeyPairFromSeed } = await import(pathToFileURL(requirePeer.resolve('@libp2p/crypto/keys')));
const { peerIdFromPrivateKey } = await import(pathToFileURL(requirePeer.resolve('@libp2p/peer-id')));

const NOISE_SEED = '42'.repeat(32);
const GATE_NAME = 'async-issuance-gate';

async function temporary(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-live-node-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

async function script(t, dir, name, body) {
  const file = path.join(dir, name);
  await fs.writeFile(file, body, { mode: 0o700 });
  return file;
}

// The bridge worker wrapper: packaged runtime first, fixture mount for the
// synthetic live fixture (test files are never packaged).
async function workerWrapper(t, dir) {
  // coupon_redemption is a regular package, so only the first sys.path entry
  // supplies it: the fixture root must come before the package cwd or the
  // unpackaged test fixture cannot import inside the exported image.
  return script(t, dir, 'worker', `#!/usr/bin/env python3
import sys, os
sys.path[:0] = [${JSON.stringify(fixtureRoot)}, os.getcwd()]
from experiments.coupon_redemption import peer_worker, test_live_fixture
test_live_fixture.install()
raise SystemExit(peer_worker.main(sys.argv[3:]))
`);
}

// The fixture's deterministic noise seed maps to the operator-visible PeerId.
async function issuerIdentity() {
  const key = await generateKeyPairFromSeed('Ed25519', Buffer.from(NOISE_SEED, 'hex'));
  return peerIdFromPrivateKey(key).toString();
}

test('probe publishes only public SDK metadata and derives the issuer identity', async t => {
  const dir = await temporary(t);
  const seed = Buffer.from(NOISE_SEED, 'hex');
  const expected = peerIdFromPrivateKey(await generateKeyPairFromSeed('Ed25519', seed)).toString();
  const worker = await script(t, dir, 'probe', `#!/bin/sh
printf '{"noise_seed_hex":"${NOISE_SEED}","issuer_public_key_hex":"${'ab'.repeat(32)}","app_id":"0505...","compose_hash":"0101...","guest_version":"0.5.9"}'
`);
  const value = await probeLiveIdentity({ pythonWorker: worker });
  assert.equal(value.issuer_peer_id, expected);
  assert.equal(value.evidence_status, 'unverified-sdk-public-metadata');
  assert.equal(value.provider_effects, 0);
  assert.equal(value.guest_version, '0.5.9');
  // The private seed never appears in the published object or JSON form.
  assert.equal(value.noise_seed_hex, undefined);
  assert.equal(JSON.stringify(value).includes(NOISE_SEED), false);
});

test('probe refuses failed, malformed or oversized SDK output', async t => {
  const dir = await temporary(t);
  const failed = await script(t, dir, 'failed', '#!/bin/sh\nexit 1\n');
  const malformed = await script(t, dir, 'malformed', `#!/bin/sh\nprintf '{"issuer_public_key_hex":"ab"}'\n`);
  const oversized = await script(t, dir, 'oversized', '#!/bin/sh\nhead -c 300000 /dev/zero\necho\n');
  for (const worker of [failed, malformed, oversized]) {
    await assert.rejects(probeLiveIdentity({ pythonWorker: worker }), /SDK probe failed/);
  }
});

test('staging admission accepts only the exact signed envelope shapes', async t => {
  const dir = await temporary(t);
  const issuerPeerId = await issuerIdentity();
  const envelopes = await fs.mkdtemp(path.join(dir, 'signed-'));
  const generated = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_live_fixture',
    'envelopes', '--dir', envelopes, '--issuer-peer-id', issuerPeerId],
    { cwd: fixtureRoot, encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const pair = [envelopes, envelopes].map((_, index) =>
    fs.readFile(path.join(envelopes, STAGING_ADMISSION[index].file)));
  await prepareStagingDirectory(path.join(dir, 'operator'));
  await admitStagingFiles(path.join(dir, 'operator'), (async function* () { yield* pair; })());
  for (const [index, expected] of (await Promise.all(pair)).entries()) {
    const admitted = await fs.readFile(path.join(dir, 'operator', STAGING_ADMISSION[index].file));
    assert.deepEqual(admitted, expected);
    assert.equal((await fs.stat(path.join(dir, 'operator', STAGING_ADMISSION[index].file))).mode & 0o777, 0o600);
  }
  // Wrong domain, non-buffer input, broken JSON, extra fields and malformed
  // signatures are all refused before any file is written.
  const refusal = path.join(dir, 'refusal');
  await prepareStagingDirectory(refusal);
  const good = await Promise.all(pair);
  const cases = [
    (async function* () { yield good[0]; yield Buffer.from(JSON.stringify({ ...JSON.parse(good[1].toString()), domain: 'wrong' })); })(),
    (async function* () {})(),
    (async function* () { yield 'not a buffer'; })(),
    (async function* () { yield Buffer.from('not json'); })(),
    (async function* () { yield Buffer.from(JSON.stringify({ ...JSON.parse(good[0].toString()), extra: true })); })(),
    (async function* () { yield Buffer.from(JSON.stringify({ ...JSON.parse(good[0].toString()), signature_hex: 'zz' })); })(),
  ];
  for (const lines of cases) {
    await assert.rejects(admitStagingFiles(refusal, lines), /staging admission input required/);
  }
});

test('bootstrap-staging end to end: admission, /4 service, delivery, restart identity', async t => {
  const dir = await temporary(t);
  const issuerPeerId = await issuerIdentity();
  const operator = path.join(dir, 'operator');
  await prepareStagingDirectory(operator);
  // The signed config points its durable state at the operator directory.
  const generated = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_live_fixture',
    'envelopes', '--dir', operator, '--issuer-peer-id', issuerPeerId],
    { cwd: fixtureRoot, encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const approvalSha256 = JSON.parse(generated.stdout).approval_sha256;
  const wrapper = await workerWrapper(t, dir);
  await admitStagingFiles(operator, (async function* () {
    for (const name of ['approval.json', 'config.json']) yield await fs.readFile(path.join(operator, name));
  })());
  const node = await startLiveCouponNode({ dir: operator, python: wrapper });
  t.after(() => node.close());
  // The published staging profile carries no private/rollback qualification.
  assert.deepEqual(node.ready, { ready: true, environment: 'private-debug-staging',
    issuer_peer_id: issuerPeerId, addresses: node.ready.addresses,
    protocols: [COUPON_PROTOCOL_V4, '/dsmack/coupon/issuer/2'], approval_sha256: approvalSha256,
    private_issuance_qualified: false, rollback_qualified: false, deposit_release_authorized: false });
  assert.ok(node.ready.addresses.length >= 1);
  assert.ok(node.ready.addresses.every(address => address.includes('127.0.0.1')));
  const bundle = await node.provision('5000000000', '2030-10-10T00:00:00Z');
  assert.equal(bundle.offer.version, 4);
  assert.equal(bundle.offer.issuer.peer_id, issuerPeerId);
  assert.equal(bundle.deposit_release_authorized, false);
  const until = async predicate => {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      const value = await predicate();
      if (value) return value;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('live node state deadline');
  };
  let response;
  const call = async request => {
    await node.bridge.serviceV4.handle({}, async value => { response = value; },
      async () => Buffer.from(JSON.stringify(request)),
      { authenticated: true, transport: 'noise', protocol: COUPON_PROTOCOL_V4,
        remotePeer: 'ClaimantGuest0001', localPeer: issuerPeerId });
    return JSON.parse(response);
  };
  const claim = { id: 'c', op: 'claim', coupon: bundle.coupon, offer_hash: bundle.offer_hash,
    recipient_key: Buffer.alloc(32, 9).toString('base64') };
  assert.equal((await call(claim)).result.state, 'in_progress');
  const delivered = await until(async () => {
    const status = await call({ ...claim, id: 's', op: 'status' });
    return status.ok && status.result.state === 'delivered' ? status : null;
  });
  const keyId = delivered.result.key_id;
  assert.ok(keyId.startsWith('synthetic-live-'));
  const replay = await call({ ...claim, id: 'c2' });
  assert.equal(replay.result.key_id, keyId);
  assert.equal(JSON.parse(Buffer.from(JSON.parse(replay.result.envelope).aad, 'base64')).version, 4);
  assert.deepEqual((await node.pending()).pending, []);
  // Identity and approval stay pinned across a full restart on the same state.
  await node.close();
  const restarted = await startLiveCouponNode({ dir: operator, python: wrapper });
  t.after(() => restarted.close());
  assert.equal(restarted.ready.issuer_peer_id, issuerPeerId);
  assert.equal(restarted.ready.approval_sha256, approvalSha256);
  assert.deepEqual((await restarted.pending()).pending, []);
});

test('wrong-authority staging control files refuse startup before any state', async t => {
  const dir = await temporary(t);
  const issuerPeerId = await issuerIdentity();
  const operator = path.join(dir, 'operator');
  await prepareStagingDirectory(operator);
  const generated = spawnSync('python3', ['-c', `
import json, os, sys
sys.path.insert(0, os.getcwd())
from experiments.coupon_redemption import test_live_fixture as fixture
fixture.SIGNING_SEED = bytes.fromhex('88' * 32)
print(json.dumps(fixture.write_envelopes(sys.argv[1], sys.argv[2], expect_valid=False)))`,
    operator, issuerPeerId], { cwd: fixtureRoot, encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  await admitStagingFiles(operator, (async function* () {
    for (const name of ['approval.json', 'config.json']) yield await fs.readFile(path.join(operator, name));
  })());
  const wrapper = await workerWrapper(t, dir);
  await assert.rejects(startLiveCouponNode({ dir: operator, python: wrapper }), /unavailable/);
  assert.equal(await fs.stat(path.join(operator, 'state')).then(() => true, error => error.code === 'ENOENT'), true,
    'refusal must happen before any durable state exists');
});

test('close terminates the whole worker group during a held issuance job', async t => {
  const dir = await temporary(t);
  const issuerPeerId = await issuerIdentity();
  const operator = path.join(dir, 'operator');
  await prepareStagingDirectory(operator);
  const generated = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_live_fixture',
    'envelopes', '--dir', operator, '--issuer-peer-id', issuerPeerId],
    { cwd: fixtureRoot, encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const wrapper = await workerWrapper(t, dir);
  await admitStagingFiles(operator, (async function* () {
    for (const name of ['approval.json', 'config.json']) yield await fs.readFile(path.join(operator, name));
  })());
  const node = await startLiveCouponNode({ dir: operator, python: wrapper });
  const configPath = path.join(operator, 'config.json');
  const lingering = async () => {
    const found = [];
    for (const entry of await fs.readdir('/proc')) {
      if (!/^[0-9]+$/.test(entry)) continue;
      const cmdline = await fs.readFile(`/proc/${entry}/cmdline`).catch(() => null);
      if (cmdline?.includes(configPath)) found.push(Number(entry));
    }
    return found;
  };
  try {
    const bundle = await node.provision('5000000000', '2030-10-10T00:00:00Z');
    await fs.writeFile(path.join(operator, 'state', GATE_NAME), 'hold');
    let response;
    await node.bridge.serviceV4.handle({}, async value => { response = value; },
      async () => Buffer.from(JSON.stringify({ id: 'c', op: 'claim', coupon: bundle.coupon,
        offer_hash: bundle.offer_hash, recipient_key: Buffer.alloc(32, 9).toString('base64') })),
      { authenticated: true, transport: 'noise', protocol: COUPON_PROTOCOL_V4,
        remotePeer: 'ClaimantGuest0001', localPeer: issuerPeerId });
    assert.equal(JSON.parse(response).result.state, 'in_progress');
    // Worker plus its forked issuance job both reference the admitted config.
    const deadline = Date.now() + 15000;
    while ((await lingering()).length < 2 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.ok((await lingering()).length >= 2, 'held job must keep its process group alive');
  } finally {
    await node.close();
  }
  const deadline = Date.now() + 15000;
  while ((await lingering()).length > 0 && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.deepEqual(await lingering(), [], 'close must reap the whole worker process group');
});
