// Development profile of a dsmack node: authenticated service registry, not an HTTP app.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createCouponPeerService, COUPON_PROTOCOL, COUPON_PROTOCOL_V2, COUPON_PROTOCOL_V3, COUPON_PROTOCOL_V4, ISSUER_PROTOCOL } from '../experiments/coupon_redemption/peer_bridge.mjs';
import { servePeer } from '../vendor/abalone/lib/p2p.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const requirePeer = createRequire(new URL('../vendor/abalone/package.json', import.meta.url));
const { generateKeyPairFromSeed } = await import(pathToFileURL(requirePeer.resolve('@libp2p/crypto/keys')));
const { peerIdFromPrivateKey } = await import(pathToFileURL(requirePeer.resolve('@libp2p/peer-id')));
const PROTOCOLS = [COUPON_PROTOCOL, COUPON_PROTOCOL_V2, COUPON_PROTOCOL_V3];
process.umask(0o077);

export async function privateFile(filename, max = 100000) {
  const file = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.nlink !== 1 || stat.size > max) throw new Error('protected input required');
    const data = await file.readFile();
    if (data.length > max) throw new Error('protected input too large');
    return data;
  } finally { await file.close(); }
}

export async function directory(dir) {
  if (!path.isAbsolute(dir)) throw new Error('absolute operator directory required');
  const stat = await fs.lstat(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('private directory required');
}

export async function initializeSynthetic(dir) {
  if (!path.isAbsolute(dir)) throw new Error('absolute operator directory required');
  // Never initialize or reset an existing directory.
  await fs.mkdir(dir, { mode: 0o700 });
  const seeds = [crypto.randomBytes(32), crypto.randomBytes(32), crypto.randomBytes(32)];
  const keys = await Promise.all(seeds.map(seed => generateKeyPairFromSeed('Ed25519', seed)));
  const [issuer, sponsor, observer] = keys.map(key => peerIdFromPrivateKey(key).toString());
  for (const [index, name] of ['identity.key', 'sponsor-peer.key', 'observer-peer.key'].entries()) await fs.writeFile(path.join(dir, name), seeds[index], { mode: 0o600, flag: 'wx' });
  await fs.writeFile(path.join(dir, 'config.json'), JSON.stringify({ version: 1, state_dir: path.join(dir, 'state'), issuer_peer_id: issuer,
    sponsor_subject: 'dev:sponsor', observer_subject: 'dev:observer', peers: {
      [sponsor]: { subject: 'dev:sponsor', roles: ['sponsor'] },
      [observer]: { subject: 'dev:observer', roles: ['observer'] },
    }, provider: { mode: 'synthetic' } }), { mode: 0o600, flag: 'wx' });
  return { initialized: true, environment: 'synthetic-development', issuer_peer_id: issuer, deposit_release_authorized: false };
}

export async function startCouponNode({ dir, listen = ['/ip4/127.0.0.1/tcp/0'], workerExecutable = path.join(root, 'packaging/coupon/python-worker') }) {
  await directory(dir);
  const configPath = path.join(dir, 'config.json');
  const config = JSON.parse((await privateFile(configPath)).toString('utf8'));
  if (config.provider?.mode !== 'synthetic') throw new Error('only synthetic development profile is qualified');
  // The callback key and the durably pinned issuer must agree before any peer listens.
  const seed = await privateFile(path.join(dir, 'identity.key'), 32);
  if (seed.length !== 32) throw new Error('invalid private identity');
  const privateKey = await generateKeyPairFromSeed('Ed25519', seed);
  const issuer = peerIdFromPrivateKey(privateKey).toString();
  if (config.issuer_peer_id !== issuer) throw new Error('issuer identity mismatch');
  const sponsorPeer = Object.entries(config.peers ?? {}).find(([, grant]) => grant.subject === config.sponsor_subject && grant.roles.includes('sponsor'))?.[0];
  if (!sponsorPeer) throw new Error('protected sponsor mapping required');
  const bridge = await createCouponPeerService({ configPath, cwd: root, python: workerExecutable });
  let peer;
  try {
    peer = await servePeer({ listen, privateKey, evidence: () => () => ({ type: 'dev' }),
      // Legacy inference/redeem routes have no authority in this service profile.
      handle: async (_request, response) => { response.writeHead(404); response.end(); },
      services: { [COUPON_PROTOCOL]: bridge.service, [COUPON_PROTOCOL_V2]: bridge.serviceV2, [COUPON_PROTOCOL_V3]: bridge.serviceV3,
        ...(config.issuer_evidence ? { [COUPON_PROTOCOL_V4]: bridge.serviceV4, [ISSUER_PROTOCOL]: bridge.issuerService } : {}) } });
    // The routing profile's legacy handlers are not offered by this node.
    for (const protocol of ['/abalone/redeem/1', '/abalone/infer/1', '/abalone/status/1']) await peer.unhandle(protocol);
  } catch (error) {
    try { await peer?.stop(); } finally { await bridge.close(); }
    throw error;
  }
  let closing;
  const close = () => closing ??= (async () => { try { await peer.stop(); } finally { await bridge.close(); } })();
  const context = Object.freeze({ authenticated: true, transport: 'noise', remotePeer: sponsorPeer, localPeer: issuer, protocol: config.issuer_evidence ? COUPON_PROTOCOL_V4 : COUPON_PROTOCOL_V3 });
  return { peer, bridge, close,
    ready: { ready: true, environment: 'synthetic-development', attestation: 'local-unattested', issuer_peer_id: issuer,
      addresses: peer.getMultiaddrs().map(String), protocols: config.issuer_evidence ? [...PROTOCOLS, COUPON_PROTOCOL_V4, ISSUER_PROTOCOL] : PROTOCOLS, deposit_release_authorized: false },
    // This protected host method is local operator authority, never remote authentication.
    provision: (budget, expiry) => config.issuer_evidence ? bridge.provisionV4(context, budget, expiry) : bridge.provisionV3(context, budget, expiry),
    pending: () => config.issuer_evidence ? bridge.pendingV4(context) : bridge.pendingV3(context) };
}

function options(args) {
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!['--dir', '--listen', '--control-port', '--relay'].includes(key) || !args[index + 1] || result[key] !== undefined) throw new Error('invalid options');
    result[key] = args[index + 1];
  }
  if (!result['--dir']) throw new Error('operator directory required');
  return result;
}

async function* operatorLines(input = process.stdin) {
  // One shared bounded reader for the whole process lifetime: bootstrap
  // admission lines and later operator frames use the same protected pipe.
  let buffer = Buffer.alloc(0);
  for await (const chunk of input) {
    if (buffer.length + chunk.length > 65536) throw new Error('operator frame too large');
    buffer = Buffer.concat([buffer, chunk]);
    let end;
    while ((end = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, end);
      buffer = buffer.subarray(end + 1);
      yield line;
    }
  }
}

export async function main(args = process.argv.slice(2)) {
  if (args.length === 0 || args[0] === '--help') {
    console.log('dsmack coupon node: init-synthetic --dir ABS | serve --dir ABS [--listen MULTIADDR] | serve-staging --dir ABS [--listen PRIVATE_MULTIADDR] | bootstrap-staging --dir ABS [--listen PRIVATE_MULTIADDR]\nStaging requires measured approval root, signed approval/config, genuine SDK and finalized guard. bootstrap-staging prints public SDK metadata, then admits the two signed control files on stdin before serving; compose and image stay fixed. stdin/stdout are protected operator pipes.');
    return;
  }
  const [command, ...rest] = args;
  if (command === 'probe-staging' && rest.length === 0) {
    console.log(JSON.stringify(await (await import('./coupon-live-node.mjs')).probeLiveIdentity())); return;
  }
  const opts = options(rest), dir = opts['--dir'];
  if (command === 'init-synthetic' && !opts['--listen']) { console.log(JSON.stringify(await initializeSynthetic(dir))); return; }
  if (!['serve', 'serve-staging', 'bootstrap-staging', 'bootstrap-mac'].includes(command)) throw new Error('unsupported command');
  if (opts['--control-port'] && command !== 'bootstrap-mac') throw new Error('Mac control only');
  if (opts['--relay'] && command !== 'bootstrap-mac') throw new Error('Mac relay only');
  let control, lines, controlChallenge;
  if (command === 'bootstrap-mac') {
    const module = await import('./mac-coupon-control.mjs');
    control = await module.connectMacControl(Number(opts['--control-port']));
    lines = operatorLines(control);
    controlChallenge = await module.readControlChallenge(lines);
  } else lines = operatorLines();
  let service, stopped = false, shutdown;
  const stop = () => {
    stopped = true;
    process.stdin.destroy();
    control?.destroy();
    return service ? shutdown ??= service.close() : Promise.resolve();
  };
  const onSignal = () => { void stop().catch(() => { process.exitCode = 1; }); };
  // Capture shutdown even during startup, while the bridge owns a detached
  // worker group. Once startup returns, close it before advertising readiness.
  process.once('SIGTERM', onSignal); process.once('SIGINT', onSignal);
  const write = async value => {
    let timer;
    try {
      if (control && Object.hasOwn(value, 'noise_seed_hex')) throw new Error('private seed cannot leave bootstrap child');
      await Promise.race([new Promise((resolve, reject) => (control ?? process.stdout).write(JSON.stringify(value) + '\n', error => error ? reject(error) : resolve())),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('operator pipe timeout')), 5000); })]);
    } finally { clearTimeout(timer); }
  };
  try {
    let start = startCouponNode, admit = null;
    if (command !== 'serve') {
      const live = await import('./coupon-live-node.mjs');
      start = live.startLiveCouponNode;
      if (command === 'bootstrap-staging' || command === 'bootstrap-mac') {
        // Public SDK metadata first: the operator signs approval and boot
        // configuration against these exact measurements, then pipes the two
        // signed control files back through the same protected operator pipe.
        await live.prepareStagingDirectory(dir);
        const mac = command === 'bootstrap-mac';
        const metadata = await live.probeLiveIdentity({ profile: mac ? 'mac' : 'tdx', ...(mac ? { controlChallenge } : {}) });
        if (mac) {
          control.write(JSON.stringify({ binding: metadata.control_binding, evidence: metadata.control_evidence,
            possession_signature_hex: metadata.control_possession_signature_hex }) + '\n');
          control.setTimeout(0);
        }
        await write({ op: 'bootstrap_metadata', ...metadata, admission: mac ? live.MAC_ADMISSION : live.STAGING_ADMISSION });
        admit = (directory, input) => live.admitStagingFiles(directory, input, mac ? live.MAC_ADMISSION : live.STAGING_ADMISSION);
      }
    }
    if (admit) await admit(dir, lines);
    service = await start({ dir, ...(opts['--listen'] ? { listen: [opts['--listen']] } : {}),
      ...(opts['--relay'] ? { macRelay: opts['--relay'] } : {}) });
    if (stopped) return;
    await write(service.ready);
    for await (const frame of lines) {
      if (stopped) break;
      let request, result;
      try {
        request = JSON.parse(frame.toString());
        if (!request || typeof request.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(request.id)) throw new Error('invalid operator frame');
        const fields = Object.keys(request).sort().join(',');
        if (request.op === 'provision' && fields === 'budget_nano_usd,claim_expires_at,id,op') result = await service.provision(request.budget_nano_usd, request.claim_expires_at);
        else if (request.op === 'pending' && fields === 'id,op') result = await service.pending();
        else throw new Error('invalid operator operation');
        await write({ id: request.id, ok: true, result });
      } catch { await write({ id: typeof request?.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(request.id) ? request.id : null, ok: false, error: 'operator_request_failed' }); }
    }
  } catch (error) {
    // Destroying an awaited pipe during an explicit shutdown can end iteration
    // with ERR_STREAM_PREMATURE_CLOSE; it is not a failed service operation.
    if (!stopped) throw error;
  } finally {
    process.removeListener('SIGTERM', onSignal); process.removeListener('SIGINT', onSignal);
    await stop();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => { console.error('coupon node failed'); process.exitCode = 1; });
