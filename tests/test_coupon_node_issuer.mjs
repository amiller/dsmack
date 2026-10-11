// Runs against the actual exported node/module closure, with a named fixture worker.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const packageRoot = process.env.DSMACK_PACKAGE_DIR;
const fixtureRoot = process.env.DSMACK_FIXTURE_DIR;
if (!packageRoot || !fixtureRoot) throw new Error('explicit exported package and fixture roots required');
const { initializeSynthetic, startCouponNode } = await import(pathToFileURL(path.join(packageRoot, 'node/coupon-node.mjs')));

test('actual packaged node selects /4 operator context only for configured issuer profile', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-node-issuer-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const operator = path.join(root, 'operator');
  await initializeSynthetic(operator);
  const configPath = path.join(operator, 'config.json');
  const config = JSON.parse(await fs.readFile(configPath, 'utf8'));
  const exported = spawnSync('python3', ['-m', 'experiments.coupon_redemption.test_issuer_fixture'], { cwd: fixtureRoot, encoding: 'utf8' });
  assert.equal(exported.status, 0, exported.stderr);
  const vector = JSON.parse(exported.stdout);
  const compose = path.join(root, 'compose.json');
  await fs.writeFile(compose, vector.app_compose, { mode: 0o600 });
  config.issuer_evidence = { identity_policy_sha256: vector.identity_policy_sha256,
    issuance_policy_sha256: vector.issuance_policy_sha256, socket_path: '/synthetic/test-only.sock', compose_file: compose };
  await fs.writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const wrapper = path.join(root, 'fixture-worker');
  await fs.writeFile(wrapper, `#!/usr/bin/python3
import sys,os
sys.path[:0]=[${JSON.stringify(fixtureRoot)},${JSON.stringify(path.join(packageRoot, 'python-deps'))}]
from experiments.coupon_redemption import peer_worker
from experiments.coupon_redemption.test_issuer_fixture import synthetic_worker
peer_worker.Worker=synthetic_worker
raise SystemExit(peer_worker.main(sys.argv[3:]))
`, { mode: 0o700 });
  const node = await startCouponNode({ dir: operator, workerExecutable: wrapper });
  t.after(() => node.close());
  assert.ok(node.ready.protocols.includes('/dsmack/coupon/4'));
  assert.ok(node.ready.protocols.includes('/dsmack/coupon/issuer/2'));
  const bundle = await node.provision('5000000000', '2030-10-10T00:00:00Z');
  assert.equal(bundle.offer.version, 4);
  assert.equal(bundle.offer.issuer.peer_id, config.issuer_peer_id);
  assert.deepEqual((await node.pending()).pending, []);
  await node.close();
  const restarted = await startCouponNode({ dir: operator, workerExecutable: wrapper });
  t.after(() => restarted.close());
  assert.deepEqual((await restarted.pending()).pending, []);
  assert.equal(restarted.ready.issuer_peer_id, node.ready.issuer_peer_id);
});
