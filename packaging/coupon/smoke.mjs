// Runs from the exported package/image: actual node process and Noise peers.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { couponAccountlessClient, couponAccountlessRecipient } from '../../vendor/abalone/lib/coupon-accountless.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const requirePeer = createRequire(new URL('../../vendor/abalone/package.json', import.meta.url));
const { generateKeyPair } = await import(pathToFileURL(requirePeer.resolve('@libp2p/crypto/keys')));
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'coupon-package-smoke-'));
const dir = path.join(temporary, 'operator');
const secrets = [], stderr = [];
const database = path.join(dir, 'state/state.sqlite');
const sql = (code, ...args) => execFileSync('/usr/bin/python3', ['-c', code, database, ...args], { encoding: 'utf8' }).trim();
let processNode, clients = [];

async function start(extra = []) {
  const child = spawn(process.execPath, ['node/coupon-node.mjs', 'serve', '--dir', dir, ...extra], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  processNode = child;
  let buffer = '', waiters = [], values = [];
  child.stdout.on('data', chunk => {
    buffer += chunk.toString();
    for (let newline; (newline = buffer.indexOf('\n')) >= 0;) {
      const value = JSON.parse(buffer.slice(0, newline)); buffer = buffer.slice(newline + 1);
      if (waiters.length) waiters.shift()(value); else values.push(value);
    }
  });
  child.stderr.on('data', chunk => stderr.push(chunk.toString()));
  const read = async () => {
    const value = values.length ? Promise.resolve(values.shift()) : new Promise(resolve => waiters.push(resolve));
    let timer;
    try { return await Promise.race([value, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('packaged node response timeout')), 10000); })]); }
    finally { clearTimeout(timer); }
  };
  const ready = await read();
  assert.equal(ready.ready, true); assert.equal(ready.attestation, 'local-unattested');
  return { ready, async provision(id) {
    child.stdin.write(JSON.stringify({ id, op: 'provision', budget_nano_usd: '1', claim_expires_at: '2030-10-10T00:00:00Z' }) + '\n');
    const response = await read(); assert.equal(response.ok, true); assert.equal(response.id, id);
    secrets.push(response.result.coupon); return response.result.coupon;
  } };
}

async function stop() {
  const child = processNode; processNode = undefined;
  if (!child) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  child.kill('SIGTERM');
  let timer;
  try {
    const result = await Promise.race([exited, new Promise((_, reject) => { timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('node did not stop')); }, 5000); })]);
    assert.equal(result.code, 0);
  } finally { clearTimeout(timer); }
}

try {
  await assert.rejects(fs.access(path.join(root, '.operator-canary')));
  for (const directory of ['experiments/coupon_redemption', 'vendor/abalone/lib', 'packaging/coupon']) {
    await assert.rejects(fs.access(path.join(root, directory, 'operator_secret.py')));
  }
  const initialized = JSON.parse(execFileSync(process.execPath, ['node/coupon-node.mjs', 'init-synthetic', '--dir', dir], { cwd: root, encoding: 'utf8' }));
  assert.equal(initialized.environment, 'synthetic-development');
  assert.throws(() => execFileSync(process.execPath, ['node/coupon-node.mjs', 'init-synthetic', '--dir', dir], { cwd: root, stdio: 'pipe' }));
  const keys = await Promise.all([generateKeyPair('Ed25519'), generateKeyPair('Ed25519')]);
  let node = await start();
  const identity = node.ready.issuer_peer_id;
  const connect = async () => {
    clients = await Promise.all(keys.map(privateKey => couponAccountlessClient(node.ready.addresses[0], { dev: true }, { privateKey })));
  };
  await connect();
  const coupon = await node.provision('first');
  const offer = await clients[0].offer(coupon), recipient = couponAccountlessRecipient();
  const delivered = await clients[0].claim(coupon, recipient, offer);
  const credential = recipient.decryptDelivery(coupon, delivered, offer); secrets.push(credential);
  assert.ok(credential.startsWith('synthetic-only-'));
  await assert.rejects(clients[1].status(coupon));
  assert.equal(sql("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"SELECT COUNT(*) FROM synthetic_events WHERE kind='create'\").fetchone()[0])"), '1');
  await Promise.all(clients.map(client => client.close())); clients = [];
  await stop();
  node = await start(); assert.equal(node.ready.issuer_peer_id, identity);
  await connect();
  const retained = await clients[0].offer(coupon); assert.deepEqual(retained, offer);
  assert.deepEqual(await clients[0].claim(coupon, recipient, retained), delivered);
  await assert.rejects(clients[1].offer(coupon));

  // Test-only DB trigger models a recorded synthetic upstream effect followed
  // by failure. It does not add a fault flag or alternate provider to the runtime.
  sql("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"CREATE TRIGGER synthetic_interrupt AFTER INSERT ON synthetic_events WHEN NEW.kind='create' BEGIN SELECT RAISE(FAIL,'synthetic interruption after effect'); END\"); c.commit()");
  const ambiguous = await node.provision('ambiguous'), ambiguousOffer = await clients[0].offer(ambiguous);
  await assert.rejects(clients[0].claim(ambiguous, recipient, ambiguousOffer));
  assert.equal((await clients[0].status(ambiguous)).state, 'reconciliation_required');
  await assert.rejects(clients[1].status(ambiguous));
  assert.equal(sql("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"SELECT COUNT(*) FROM synthetic_events WHERE kind='create'\").fetchone()[0])"), '2');
  await Promise.all(clients.map(client => client.close())); clients = []; await stop();
  node = await start(); await connect();
  await assert.rejects(clients[0].claim(ambiguous, recipient, await clients[0].offer(ambiguous)));
  assert.equal((await clients[0].status(ambiguous)).state, 'reconciliation_required');
  await assert.rejects(clients[1].status(ambiguous));
  assert.equal(sql("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"SELECT COUNT(*) FROM synthetic_events WHERE kind='create'\").fetchone()[0])"), '2');
  await Promise.all(clients.map(client => client.close())); clients = []; await stop();
  // Fail readiness for a mismatched private identity; do not replace durable state.
  await fs.writeFile(path.join(dir, 'identity.key'), Buffer.alloc(32, 0x42), { mode: 0o600 });
  assert.throws(() => execFileSync(process.execPath, ['node/coupon-node.mjs', 'serve', '--dir', dir], { cwd: root, stdio: 'pipe', timeout: 5000 }));
  assert.ok(stderr.every(line => secrets.every(secret => !line.includes(secret))));
  console.log(JSON.stringify({ mode: 'packaged-synthetic-dsmack-node', authenticated_noise: true, issuer_restart_stable: true,
    delivered_ciphertext_replayed: true, provider_creates: 2, ambiguous_retry_disabled: true, loser_denied: true,
    wrong_identity_rejected: true, attestation: 'local-unattested', deposit_release_authorized: false }));
} finally {
  await Promise.allSettled(clients.map(client => client.close()));
  await stop(); await fs.rm(temporary, { recursive: true, force: true });
}
