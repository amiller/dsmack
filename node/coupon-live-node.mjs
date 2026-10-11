// Same node service registry; staging approval is enforced before credentials.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { createCouponPeerService, COUPON_PROTOCOL_V4, ISSUER_PROTOCOL } from '../experiments/coupon_redemption/peer_bridge.mjs';
import { servePeer } from '../vendor/abalone/lib/p2p.mjs';
import { privateFile, directory } from './coupon-node.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const requirePeer = createRequire(new URL('../vendor/abalone/package.json', import.meta.url));
const { generateKeyPairFromSeed } = await import(pathToFileURL(requirePeer.resolve('@libp2p/crypto/keys')));
const { peerIdFromPrivateKey } = await import(pathToFileURL(requirePeer.resolve('@libp2p/peer-id')));

// A fixed measured compose keeps this process alive: it first publishes the
// SDK's public metadata, then admits the two signed control files through the
// protected operator pipe. The compose and image never change between phases.
export const STAGING_ADMISSION = Object.freeze([
  { file: 'approval.json', domain: 'dsmack-coupon-staging-approval-v1' },
  { file: 'config.json', domain: 'dsmack-coupon-staging-config-v1' }]);

export async function probeLiveIdentity({ pythonWorker = path.join(root, 'packaging/coupon/python-worker') } = {}) {
  const proc = spawn(pythonWorker, ['-m', 'experiments.coupon_redemption.dstack_bootstrap'],
    { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' } });
  const chunks = []; let size = 0, failed = false;
  const kill = () => { try { process.kill(-proc.pid, 'SIGKILL'); } catch {} };
  const timer = setTimeout(() => { failed = true; kill(); }, 90000);
  proc.stderr.on('data', () => {});
  proc.stdout.on('data', chunk => { size += chunk.length; if (size > 200000) { failed = true; kill(); } else chunks.push(chunk); });
  try {
    await new Promise((resolve, reject) => { proc.once('error', reject); proc.once('exit', code => code === 0 && !failed ? resolve() : reject(new Error('SDK probe failed'))); });
    const value = JSON.parse(Buffer.concat(chunks).toString());
    if (!/^[0-9a-f]{64}$/.test(value.noise_seed_hex)) throw new Error('SDK probe failed');
    const seed = Buffer.from(value.noise_seed_hex, 'hex');
    let key;
    try { key = await generateKeyPairFromSeed('Ed25519', seed); } finally { seed.fill(0); }
    delete value.noise_seed_hex;
    return { ...value, issuer_peer_id: peerIdFromPrivateKey(key).toString(),
      evidence_status: 'unverified-sdk-public-metadata', provider_effects: 0 };
  } finally { clearTimeout(timer); kill(); for (const chunk of chunks) chunk.fill(0); }
}

export async function prepareStagingDirectory(dir) {
  if (!path.isAbsolute(dir)) throw new Error('absolute operator directory required');
  await fs.mkdir(dir, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
  await directory(dir);
}

export async function admitStagingFiles(dir, lines) {
  if (!path.isAbsolute(dir)) throw new Error('absolute operator directory required');
  for (const expected of STAGING_ADMISSION) {
    const { value, done } = await lines.next();
    if (done || !Buffer.isBuffer(value)) throw new Error('staging admission input required');
    let envelope;
    try { envelope = JSON.parse(value.toString('utf8')); } catch { throw new Error('staging admission input required'); }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || Object.keys(envelope).sort().join(',') !== 'domain,payload,signature_hex'
        || envelope.domain !== expected.domain
        || !envelope.payload || typeof envelope.payload !== 'object' || Array.isArray(envelope.payload)
        || typeof envelope.signature_hex !== 'string' || !/^[0-9a-f]{128}$/.test(envelope.signature_hex)) {
      throw new Error('staging admission input required');
    }
    // Signature and policy are verified by the worker against the measured
    // approval root before credentials; this writes the exact signed bytes.
    const file = await fs.open(path.join(dir, expected.file),
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
    try {
      const { bytesWritten } = await file.write(value);
      if (bytesWritten !== value.length) throw new Error('staging admission input required');
      await file.sync();
    } finally { await file.close(); }
  }
}

export async function startLiveCouponNode({ dir, listen = ['/ip4/127.0.0.1/tcp/0'],
  python = path.join(root, 'packaging/coupon/python-worker') } = {}) {
  if (!path.isAbsolute(dir)) throw new Error('protected operator directory required');
  await directory(dir);
  await privateFile(path.join(dir, 'config.json')); // File metadata, no config authority inferred here.
  let privateKey, issuer, sponsorPeer, approvalHash;
  const bridge = await createCouponPeerService({ configPath: path.join(dir, 'config.json'), cwd: root,
    python, startupTimeoutMs: 120000, readyEnvironment: 'debug-staging', onBootstrap: async value => {
      if (Object.keys(value).sort().join(',') !== 'approval_sha256,environment,issuer_peer_id,noise_seed_hex,ready,sponsor_peer' ||
          !/^[0-9a-f]{64}$/.test(value.noise_seed_hex) || !/^[0-9a-f]{64}$/.test(value.approval_sha256) ||
          !/^[A-Za-z0-9]{16,128}$/.test(value.sponsor_peer)) throw new Error('SDK bootstrap refused');
      const seed = Buffer.from(value.noise_seed_hex, 'hex');
      let key;
      try { key = await generateKeyPairFromSeed('Ed25519', seed); } finally { seed.fill(0); }
      const actual = peerIdFromPrivateKey(key).toString();
      if (actual !== value.issuer_peer_id || (issuer && actual !== issuer) ||
          (approvalHash && value.approval_sha256 !== approvalHash) ||
          (sponsorPeer && value.sponsor_peer !== sponsorPeer)) throw new Error('SDK issuer mismatch');
      privateKey = key; issuer = actual; sponsorPeer = value.sponsor_peer; approvalHash = value.approval_sha256;
    } });
  let peer;
  try {
    peer = await servePeer({ listen, privateKey, evidence: () => () => ({ type: 'dev' }),
      handle: async (_request, response) => { response.writeHead(404); response.end(); },
      services: { [COUPON_PROTOCOL_V4]: bridge.serviceV4, [ISSUER_PROTOCOL]: bridge.issuerService } });
    for (const protocol of ['/abalone/redeem/1', '/abalone/infer/1', '/abalone/status/1']) await peer.unhandle(protocol);
  } catch (error) {
    try { await peer?.stop(); } finally { await bridge.close(); }
    throw error;
  }
  let closing;
  const close = () => closing ??= (async () => { try { await peer.stop(); } finally { await bridge.close(); } })();
  const context = Object.freeze({ authenticated: true, transport: 'noise', remotePeer: sponsorPeer,
    localPeer: issuer, protocol: COUPON_PROTOCOL_V4 });
  return { peer, bridge, close,
    ready: { ready: true, environment: 'private-debug-staging', issuer_peer_id: issuer,
      addresses: peer.getMultiaddrs().map(String), protocols: [COUPON_PROTOCOL_V4, ISSUER_PROTOCOL],
      approval_sha256: approvalHash, private_issuance_qualified: false, rollback_qualified: false,
      deposit_release_authorized: false },
    provision: (budget, expires) => bridge.provisionV4(context, budget, expires),
    pending: () => bridge.pendingV4(context) };
}
