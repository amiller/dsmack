import { strict as assert } from 'node:assert';
import { rekorFetch } from './fixtures/rekor.mjs';
Deno.test({ name: 'offline Rekor replay rejects unrecorded requests instead of using the network',
  ignore: Deno.env.get('LIVE_TESTS') === '1',
  fn: async () => {
    await assert.rejects(() => rekorFetch('https://rekor.sigstore.dev/api/v1/index/retrieve', {
      body: JSON.stringify({ hash: 'sha256:' + '00'.repeat(32) }),
    }), /Unrecorded Rekor request/);
  },
});
