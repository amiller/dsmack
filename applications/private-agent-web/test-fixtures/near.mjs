import { readFile } from 'node:fs/promises';
import { rekorFetch } from '../../relay-broker/fixtures/rekor.mjs';
export const report = JSON.parse(await readFile(new URL('./near/report.json', import.meta.url)));
export const recording = JSON.parse(await readFile(new URL('./near/responses.json', import.meta.url)));
export const model = report.model_attestations[0].model_name;
export const nonce = report.gateway_attestation.request_nonce;
export function responseFor(url) {
  return recording.responses[url.replace('https://cloud.near.ai/api/proxy/nras', 'https://nras.attestation.nvidia.com')];
}
export async function replayNear(page) {
  await page.route('https://rekor.sigstore.dev/**', async route => {
    const request = route.request();
    const response = await rekorFetch(request.url(), { method: request.method(), body: request.postData() });
    await route.fulfill({ status: response.status, headers: {
      'content-type': 'application/json', 'access-control-allow-origin': '*',
    }, body: await response.text() });
  });
  await page.clock.setFixedTime(recording.now);
  // Recorded quotes carry this fixed challenge. Production always uses random
  // challenges; only the offline browser fixture supplies the recorded one.
  await page.addInitScript(nonce => {
    const original = crypto.getRandomValues.bind(crypto);
    crypto.getRandomValues = bytes => {
      if (bytes.length !== 32) return original(bytes);
      bytes.set(nonce.match(/../g).map(b => parseInt(b,16))); return bytes;
    };
  }, nonce);
  await page.route(/https:\/\/(cloud.near.ai|nras.attestation.nvidia.com)\//, route => {
    const response = responseFor(route.request().url());
    if (!response) throw Error('Unrecorded NEAR request: ' + route.request().url());
    const headers = { ...response.headers, 'access-control-allow-origin': '*' };
    for (const key of ['content-encoding', 'content-length', 'transfer-encoding']) delete headers[key];
    return route.fulfill({ status: response.status, headers, body: Buffer.from(response.body, 'base64') });
  });
}
