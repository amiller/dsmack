import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { report, model, nonce, recording, responseFor } from './test-fixtures/near.mjs';
const envelope = { provider: 'near', model, mode: 'broker-e2ee', report };
const key = report.model_attestations[0].signing_public_key;
test('authenticates recorded NEAR CPU, gateway SPKI, compose manager, model key and NVIDIA evidence without broker verdict', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: recording.now });
  const originalFetch = globalThis.fetch, originalNow = Date.now;
  // Rekor is live: its entries are append-only, so image provenance needs no recording.
  globalThis.fetch = async (url, init) => { if (String(url).startsWith('https://rekor.sigstore.dev/')) return originalFetch(url, init); const r = responseFor(String(url)); assert(r, 'recorded network response'); return new Response(Buffer.from(r.body,'base64'), {status:r.status,headers:r.headers}); };
  Date.now = () => recording.now;
  try {
    const { checkEvidence } = await import('./evidence.mjs');
    await assert.rejects(checkEvidence({ ...envelope, verification: 'verified', report: undefined }, model, recording.now, nonce, key), /TLS key binding/);
    await assert.rejects(checkEvidence(envelope, model, recording.now, '12'.repeat(32), key), /nonce/);
    const { IMAGES } = await import('../relay-broker/near-policy.mjs'), cloudApi = IMAGES['nearaidev/cloud-api'];
    delete IMAGES['nearaidev/cloud-api'];
    await assert.rejects(checkEvidence(envelope, model, recording.now, nonce, key), /provenance/);
    IMAGES['nearaidev/cloud-api'] = cloudApi;
    await assert.rejects(checkEvidence(envelope, model, recording.now, nonce, Wallet.createRandom().signingKey.publicKey), /differs from the attested/);
    const unboundGateway = { ...report, gateway_attestation: { ...report.gateway_attestation, tls_cert_fingerprint: '00'.repeat(32) } };
    await assert.rejects(checkEvidence({ ...envelope, report: unboundGateway }, model, recording.now, nonce, key), /signerTlsBinding/);
    const checked = await checkEvidence({ ...envelope, verification: 'untrusted' }, model, recording.now, nonce, key);
    assert.equal(checked.browser.fullQuoteVerifiedBy, 'browser');
    assert.equal(checked.models[0].gpuEvidence, 'verified');
    assert.equal(checked.tls.livePeerSpki, 'not-observable-in-browser');

  } finally { globalThis.fetch=originalFetch; Date.now=originalNow; }
});
