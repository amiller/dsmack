import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPageVersion } from './page-version.mjs';
const ownCID = 'bafkrei' + 'a'.repeat(52), published = 'bafkrei'+'b'.repeat(52);
test('version change shows both CIDs; same version clears the notice', async () => {
  const banner = {};
  await checkPageVersion({ ownCID, banner, latest: async () => published });
  assert.equal(banner.hidden, false);
  assert(banner.textContent.includes(ownCID) && banner.textContent.includes(published));
  await checkPageVersion({ ownCID, banner, latest: async () => ownCID });
  assert.equal(banner.hidden, true);
});
test('registry failure propagates', async () => {
  await assert.rejects(checkPageVersion({ ownCID, banner: {}, latest: async () => {throw Error('RPC unavailable');} }), /RPC unavailable/);
});
