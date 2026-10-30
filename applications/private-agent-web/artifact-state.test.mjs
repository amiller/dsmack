import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { ArtifactState } from './artifact-state.mjs';
import { ArtifactBridge } from './artifact-bridge.mjs';
globalThis.crypto ??= webcrypto;
const dataKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const scope = JSON.stringify(['conversation-a', 'todo.html']);
function storage(records = new Map(), save) {
  return new ArtifactState({ dataKey, getRecord: id => records.get(id),
    saveRecord: save || (async (id, envelope) => { records.set(id, envelope); }) });
}

test('encrypts artifact values and budget and reloads them with the device key', async () => {
  const records = new Map(), state = storage(records);
  assert.deepEqual(await state.list(scope), []);
  assert.equal(await state.get(scope, 'missing'), undefined);
  const secret = 'private todo: send birthday surprise';
  await state.put(scope, 'todo', { text: secret, done: false });
  await state.update(scope, value => { value.budget.limitNanoUsd = '20000000'; });
  const serialized = JSON.stringify(records.get(scope));
  assert(!serialized.includes(secret));assert(!serialized.includes('budget'));
  const restored = storage(records);
  assert.deepEqual(await restored.get(scope, 'todo'), { text: secret, done: false });
  assert.deepEqual(await restored.list(scope), ['todo']);
  assert.deepEqual((await restored.read(scope)).budget, { limitNanoUsd: '20000000', spentNanoUsd: '0', reservedNanoUsd: '0' });
  await restored.put(scope, '__proto__', 'ordinary key');
  assert.equal(await restored.get(scope, '__proto__'), 'ordinary key');
});

test('refuses a record moved to another artifact scope or altered ciphertext', async () => {
  const records = new Map(), state = storage(records);
  await state.put(scope, 'secret', 'private value');
  const other = JSON.stringify(['conversation-b', 'todo.html']);
  records.set(other, records.get(scope));
  await assert.rejects(state.read(other));
  const envelope = { ...records.get(scope) };
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');ciphertext[0] ^= 1;
  records.set(scope, { ...envelope, ciphertext: ciphertext.toString('base64url') });
  await assert.rejects(state.read(scope));
  records.set(scope, null);await assert.rejects(state.read(scope));
});

test('serializes concurrent updates and awaits durable storage before completion', async () => {
  const records = new Map();let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const hold = new Promise(resolve => { release = resolve; });
  let saves = 0;
  const state = storage(records, async (id, envelope) => {
    if (++saves === 1) { entered();await hold; }
    records.set(id, envelope);
  });
  let finished = false;
  const first = state.put(scope, 'first', 1).then(() => { finished = true; });
  await started;assert.equal(finished, false);
  const second = state.put(scope, 'second', 2);
  release();await Promise.all([first, second]);
  assert.deepEqual(await state.list(scope), ['first', 'second']);
  assert.equal(await state.get(scope, 'first'), 1);assert.equal(await state.get(scope, 'second'), 2);
});

test('propagates persistence failure without poisoning later updates', async () => {
  const records = new Map();let fail = true;
  const state = storage(records, async (id, envelope) => {
    if (fail) { fail = false;throw new Error('disk unavailable'); }
    records.set(id, envelope);
  });
  await assert.rejects(state.put(scope, 'lost', 1), /disk unavailable/);
  await state.put(scope, 'saved', 2);
  assert.deepEqual(await state.list(scope), ['saved']);
});

test('aggregate values quota refuses a write before saving and valid overwrites still work', async () => {
  const records = new Map(), state = storage(records), value = 'x'.repeat(200 * 1024);
  await state.put(scope, 'first', value);
  await state.put(scope, 'second', value);
  const before = records.get(scope);
  await assert.rejects(state.put(scope, 'third', value), error => error.code === 'INVALID_ARGS');
  assert.equal(records.get(scope), before, 'quota failure must not save a new envelope');
  assert.equal(await state.get(scope, 'third'), undefined);
  assert.equal(await state.get(scope, 'first'), value);
  await state.put(scope, 'first', 'small');
  await state.put(scope, 'third', value);
  assert.equal(await state.get(scope, 'first'), 'small');
  assert.equal(await state.get(scope, 'third'), value);
});

test('per-value storage limit counts UTF-8 bytes rather than JavaScript characters', async () => {
  const state = storage(), bridge = new ArtifactBridge({ scope, state });
  const put = async value => {
    let response;
    await bridge.handleMessage({ type: 'dsmack-request', version: 1, requestId: 'unicode',
      method: 'storage.put', params: { key: 'unicode', value } }, result => { response = result; });
    return response;
  };
  const fits = '界'.repeat(Math.floor((256 * 1024 - 2) / 3));
  assert.equal((await put(fits)).ok, true);
  assert.equal((await put(fits + '界')).error.code, 'INVALID_ARGS');
  assert.equal(await state.get(scope, 'unicode'), fits);
});
