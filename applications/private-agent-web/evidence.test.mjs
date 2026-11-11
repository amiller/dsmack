import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { rekorFetch } from '../relay-broker/fixtures/rekor.mjs';
import { report, model, nonce, recording, responseFor } from './test-fixtures/near.mjs';
const envelope = { provider: 'near', model, mode: 'broker-e2ee', report };
const key = report.model_attestations[0].signing_public_key;
test('authenticates recorded NEAR CPU, gateway SPKI, compose manager, model key and NVIDIA evidence without broker verdict', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: recording.now });
  const originalFetch = globalThis.fetch, originalNow = Date.now;
  // Replay signed provenance by default; LIVE_TESTS=1 opts into live Rekor.
  globalThis.fetch = async (url, init) => { if (String(url).startsWith('https://rekor.sigstore.dev/')) return rekorFetch(url, init); const r = responseFor(String(url)); assert(r, 'recorded network response'); return new Response(Buffer.from(r.body,'base64'), {status:r.status,headers:r.headers}); };
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
    assert.equal(checked.gateway.instanceId, '3d54f35174ba0a06695f68af499fe77188d627af');
    assert.match(checked.models[0].instanceId, /^[0-9a-f]{40}$/);
    // An event type the SDK replays without binding its name and payload must not supply an identity.
    const forged = structuredClone(report), log = forged.gateway_attestation.info.tcb_info;
    const tcb = typeof log === 'string' ? JSON.parse(log) : log;
    for (const e of tcb.event_log) if (e.event === 'instance-id') { e.event_type = 0; e.event_payload = 'f0'.repeat(20); }
    forged.gateway_attestation.info.tcb_info = typeof log === 'string' ? JSON.stringify(tcb) : tcb;
    const forgedCheck = await checkEvidence({ ...envelope, report: forged }, model, recording.now, nonce, key);
    assert.equal(forgedCheck.gateway.instanceId, undefined);
    assert.equal(checked.tls.livePeerSpki, 'not-observable-in-browser');

  } finally { globalThis.fetch=originalFetch; Date.now=originalNow; }
});
