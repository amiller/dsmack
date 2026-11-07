// Authentic signed entries captured from Rekor. Index replies contain the recorded
// UUIDs; entry lookup accepts any batching/order. Unknown requests never fall back
// to the network. LIVE_TESTS=1 explicitly opts into the public service.
import { readFile } from 'node:fs/promises';
import { env } from 'node:process';
const liveFetch = globalThis.fetch.bind(globalThis);
const recording = JSON.parse(await readFile(new URL('./rekor-responses.json', import.meta.url)));
export async function rekorFetch(url, init = {}) {
  if (env.LIVE_TESTS === '1') return liveFetch(url, { ...init, signal: AbortSignal.timeout(60000) });
  const body = JSON.parse(init.body || '{}');
  if (String(url) === 'https://rekor.sigstore.dev/api/v1/index/retrieve' && Object.hasOwn(recording.index, body.hash)) {
    return Response.json(recording.index[body.hash]);
  }
  if (String(url) === 'https://rekor.sigstore.dev/api/v1/log/entries/retrieve' &&
      Array.isArray(body.entryUUIDs) && body.entryUUIDs.every(id => Object.hasOwn(recording.entries, id))) {
    return Response.json(body.entryUUIDs.map(id => ({ [id]: recording.entries[id] })));
  }
  throw Error('Unrecorded Rekor request: ' + url + ' ' + init.body);
}
