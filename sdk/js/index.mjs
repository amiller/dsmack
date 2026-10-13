// dsmack-sdk JS client: the Python dsmack_sdk's wire and derivation, over node:net (see ../python/dsmack_sdk).
// Context fields are ABI words, as node/shared/SDK.swift encodes them.
import net from 'node:net';
import { hkdfSync } from 'node:crypto';

export const SOCKET = '/var/run/dsmack.sock';
const TAGS = ['ed25519', 'secp256k1', 'p256', 'raw'];
const hkdf = (ikm, salt, info) => Buffer.from(hkdfSync('sha256', ikm, salt.length ? salt : Buffer.alloc(32), info, 32));
const lp = (b) => Buffer.concat([Buffer.from([0, 0, 0, 0].map((_, i) => (b.length >>> (8 * (3 - i))) & 255)), b]);
const hex = (h) => Buffer.from(h.replace(/^0x/, ''), 'hex');
const u = (n, bytes) => hex(BigInt(n).toString(16).padStart(bytes * 2, '0'));

const sized = (h, n, what) => { const b = hex(h); if (b.length !== n) throw new Error(`${what} width`); return b; };
const address = (a) => Buffer.concat([Buffer.alloc(12), sized(a, 20, 'address')]);

export function context(chainId, registry, appRegistry, scope, keyEpoch, appId) {
  return Buffer.concat([u(chainId, 32), address(registry), address(appRegistry), sized(scope, 32, 'scope'), u(keyEpoch, 32), sized(appId, 32, 'app_id')]);
}
export const appRoot = (groupScalar, chainId, registry, appRegistry, scope, keyEpoch, appId) =>
  hkdf(groupScalar, context(chainId, registry, appRegistry, scope, keyEpoch, appId), Buffer.from('dsmack-sdk/v1/app'));
export function leaf(root, path, purpose) {
  const [tag, ...rest] = purpose.split(':');
  if (!rest.length || !TAGS.includes(tag)) throw new Error(`purpose must start with one of ${TAGS.map((t) => t + ':').join(', ')}`);
  return hkdf(root, Buffer.alloc(0), Buffer.concat([Buffer.from('dsmack-sdk/v1/key'), lp(Buffer.from(path)), lp(Buffer.from(purpose))]));
}

export class DsmackError extends Error {}

export class Client {
  constructor(path = SOCKET) { this.path = path; }
  call(op, args = {}) {
    return new Promise((resolve, reject) => {
      const s = net.createConnection(this.path);
      let buf = '';
      s.on('error', reject);
      s.on('data', (d) => {
        buf += d;
        const i = buf.indexOf('\n');
        if (i < 0) return;
        s.end();
        const reply = JSON.parse(buf.slice(0, i));
        reply.error ? reject(new DsmackError(reply.error)) : resolve(reply);
      });
      s.write(JSON.stringify({ v: 1, op, ...args }) + '\n');
    });
  }
  getKey(path, purpose, epoch) { return this.call('get_key', { path, purpose, ...(epoch === undefined ? {} : { epoch }) }); }
  evidence(reportData) {
    if (reportData.length > 64) throw new Error('report_data is at most 64 bytes');
    return this.call('evidence', { report_data: Buffer.from(reportData).toString('hex') });
  }
  info() { return this.call('info'); }
}
