import { cidFor, decode } from './continuity.mjs';
import { canonicalFleet } from './fleet.mjs';
import { InferenceError } from './inference.mjs';
export const maxArtifactCiphertextBytes = 512 * 1024;
const need = (ok, code, message, status = 400) => { if (!ok) throw new InferenceError(code, message, status); };
const validCid = cid => typeof cid === 'string' && /^bafkre[a-z2-7]{53}$/.test(cid);
const zeroWallet = '0x' + '0'.repeat(40);
function ciphertextBytes(ciphertext) {
  need(typeof ciphertext === 'string' && ciphertext.length <= Math.ceil(maxArtifactCiphertextBytes * 4 / 3),
    'ARTIFACT_SHARE_SIZE', 'encrypted artifact must be at most 512 KiB');
  let bytes;
  try { bytes = decode(ciphertext); } catch { throw new InferenceError('ARTIFACT_SHARE_CIPHERTEXT', 'base64url ciphertext required'); }
  need(bytes.length >= 29 && bytes.length <= maxArtifactCiphertextBytes,
    'ARTIFACT_SHARE_SIZE', 'encrypted artifact must contain 29 bytes to 512 KiB');
  return bytes;
}
export function artifactStoreRemote({ url, key, fetch: request = fetch, now = () => Math.floor(Date.now() / 1000) }) {
  return async (action, fields) => {
    need(url && key, 'ARTIFACT_STORE_UNAVAILABLE', 'artifact IPFS store is not configured', 503);
    const unsigned = { action, issuedAt: now(), nonce: crypto.randomUUID().replaceAll('-', ''), ...fields };
    const sig = await key.signMessage('dsmack-workspace-store/1\n' + canonicalFleet(unsigned));
    const response = await request(url.replace(/\/$/, '') + '/' + action, { method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...unsigned, sig }), signal: AbortSignal.timeout(120000) });
    const chunks = [];let size = 0;
    for await (const chunk of response.body) {
      size += chunk.byteLength;need(size <= 1024 * 1024, 'ARTIFACT_STORE_RESPONSE', 'artifact store response exceeds 1 MiB', 502);chunks.push(chunk);
    }
    const raw = new Uint8Array(size);let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset);offset += chunk.byteLength; }
    let value;try { value = JSON.parse(new TextDecoder().decode(raw)); }
    catch { throw new InferenceError('ARTIFACT_STORE_RESPONSE', 'artifact store returned invalid JSON', 502); }
    need(response.ok, value.error?.code ?? 'ARTIFACT_STORE_UNAVAILABLE', value.error?.message ?? 'artifact store refused request', response.status);
    return value;
  };
}
export class ArtifactShares {
  constructor({ continuity, remote }) { Object.assign(this, { continuity, remote }); }
  async publish(request) {
    let wallet;
    try { wallet = this.continuity.authorize(request, 'artifact-share'); }
    catch (error) { throw new InferenceError('ARTIFACT_SHARE_SIGNATURE', error.message, error.status ?? 403); }
    need(Object.keys(request).every(k => ['action', 'wallet', 'nonce', 'issuedAt', 'sig', 'ciphertext'].includes(k)),
      'ARTIFACT_SHARE_REQUEST', 'only encrypted artifact bytes may be published');
    const bytes = ciphertextBytes(request.ciphertext), cid = await cidFor(bytes);
    const result = await this.remote('raw-put', { wallet, cid, ciphertext: request.ciphertext });
    need(result.cid === cid && result.pinned === true, 'ARTIFACT_PIN_UNCONFIRMED', 'artifact IPFS pin was not confirmed', 502);
    return { cid, pinned: true };
  }
  async read(cid) {
    need(validCid(cid), 'ARTIFACT_SHARE_CID', 'raw SHA256 CIDv1 required');
    // The store admits reads only for its published permanent artifact pins.
    const result = await this.remote('raw-get', { wallet: zeroWallet, cid });
    need(result.cid === cid && await cidFor(ciphertextBytes(result.ciphertext)) === cid,
      'ARTIFACT_SHARE_CID', 'artifact store ciphertext CID mismatch', 502);
    return { cid, ciphertext: result.ciphertext };
  }
}
