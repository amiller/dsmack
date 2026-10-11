/** Experimental mount for an authenticated Abalone service callback.
 * Anonymous pipes are a capability of this trusted host process, not a public
 * JSON authentication mechanism. Never expose request/provision to peer frames.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const COUPON_PROTOCOL = '/dsmack/coupon/1';
export const COUPON_PROTOCOL_V2 = '/dsmack/coupon/2';
export const COUPON_PROTOCOL_V3 = '/dsmack/coupon/3';
export const COUPON_PROTOCOL_V4 = '/dsmack/coupon/4';
export const ISSUER_PROTOCOL = '/dsmack/coupon/issuer/2';
export const MAX_ISSUER_FRAME = 2 * 1024 * 1024;
export const MAX_FRAME = 65536;
const MAX_BRIDGE = 3 * 1024 * 1024;
const MAX_COUPON_BRIDGE = 100000;
const FAILED = Buffer.from('{"id":null,"ok":false,"error":"request_failed"}');

function authenticatedPeer(context, expectedProtocol = COUPON_PROTOCOL) {
  if (!context || context.authenticated !== true || context.transport !== 'noise' ||
      context.protocol !== expectedProtocol || typeof context.remotePeer !== 'string' ||
      !/^[A-Za-z0-9]{1,200}$/.test(context.remotePeer) ||
      typeof context.localPeer !== 'string' || !context.localPeer) {
    throw new Error('authenticated peer context required');
  }
  return context.remotePeer;
}

export async function createCouponPeerService({ configPath, python = 'python3',
  cwd = fileURLToPath(new URL('../..', import.meta.url)), timeoutMs = 15000,
  startupTimeoutMs = timeoutMs, maxQueue = 32, rateCapacity = 60, rateRefillPerSecond = 1, maxRatePeers = 1024,
  readyEnvironment = 'local-unattested', onBootstrap = undefined } = {}) {
  if (typeof configPath !== 'string' || !configPath.startsWith('/') ||
      !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 120000 ||
      !Number.isInteger(startupTimeoutMs) || startupTimeoutMs < 50 || startupTimeoutMs > 120000 ||
      !Number.isInteger(maxQueue) || maxQueue < 1 || maxQueue > 256 ||
      !Number.isInteger(rateCapacity) || rateCapacity < 1 || rateCapacity > 10000 ||
      !Number.isFinite(rateRefillPerSecond) || rateRefillPerSecond <= 0 || rateRefillPerSecond > 1000 ||
      !Number.isInteger(maxRatePeers) || maxRatePeers < 1 || maxRatePeers > 10000 ||
      !['local-unattested', 'debug-staging'].includes(readyEnvironment) ||
      (readyEnvironment === 'debug-staging' && typeof onBootstrap !== 'function')) {
    throw new Error('invalid coupon bridge configuration');
  }
  let child, startup, buffer = Buffer.alloc(0), sequence = 0, pending, queued = 0;
  let chain = Promise.resolve();
  let closed = false, stopping, restarting = false;
  const rates = new Map();

  function admit(peer) {
    const now = performance.now();
    let bucket = rates.get(peer);
    if (!bucket) {
      if (rates.size >= maxRatePeers) {
        for (const [key, old] of rates) {
          if ((now - old.at) * rateRefillPerSecond / 1000 >= rateCapacity) rates.delete(key);
        }
      }
      if (rates.size >= maxRatePeers) return false;
      bucket = { tokens: rateCapacity, at: now };
      rates.set(peer, bucket);
    }
    bucket.tokens = Math.min(rateCapacity, bucket.tokens + (now - bucket.at) * rateRefillPerSecond / 1000);
    bucket.at = now;
    if (bucket.tokens < 1) return false;
    bucket.tokens--;
    return true;
  }

  function signalGroup(proc, signal) {
    if (!proc?.pid) return;
    try { process.kill(-proc.pid, signal); } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  }

  async function stop() {
    if (stopping) return stopping;
    const proc = child;
    child = undefined;
    if (!proc) return;
    // The provider HTTPS helper may have its own worker: stop the entire group.
    signalGroup(proc, 'SIGTERM');
    stopping = new Promise((resolve, reject) => {
      const timer = setTimeout(() => signalGroup(proc, 'SIGKILL'), 500);
      const reapTimer = setTimeout(() => reject(new Error('coupon worker did not exit')), 2500);
      proc.once('exit', () => {
        clearTimeout(timer); clearTimeout(reapTimer); signalGroup(proc, 'SIGKILL'); resolve();
      });
      if (proc.exitCode !== null || proc.signalCode !== null) {
        clearTimeout(timer); clearTimeout(reapTimer); signalGroup(proc, 'SIGKILL'); resolve();
      }
    });
    await stopping;
    stopping = undefined;
    buffer = Buffer.alloc(0);
  }

  function failure() {
    const error = new Error('coupon worker unavailable');
    startup?.reject(error);
    startup = undefined;
    pending?.reject(error);
    pending = undefined;
    void stop().catch(() => {});
  }

  async function start() {
    if (stopping) await stopping;
    if (closed) throw new Error('coupon bridge closed');
    buffer = Buffer.alloc(0);
    const proc = spawn(python, ['-m', 'experiments.coupon_redemption.peer_worker', '--config', configPath], {
      cwd, stdio: ['pipe', 'pipe', 'pipe'], shell: false, detached: true,
      env: Object.fromEntries(Object.entries({ PATH: process.env.PATH,
        LANG: process.env.LANG, LC_ALL: process.env.LC_ALL, PYTHONUNBUFFERED: '1' })
        .filter(([, value]) => value !== undefined)),
    });
    child = proc;
    proc.stderr.on('data', () => {}); // Drain without logging credential/setup errors.
    const failCurrent = () => { if (child === proc) failure(); };
    proc.once('error', failCurrent);
    proc.once('exit', () => { if (child === proc) failure(); });
    proc.stdin.on('error', failCurrent);
    const ready = new Promise((resolve, reject) => { startup = { resolve, reject }; });
    const timer = setTimeout(failure, startupTimeoutMs);
    proc.stdout.on('data', data => {
      if (child !== proc) return;
      buffer = Buffer.concat([buffer, data]);
      if (buffer.length > MAX_BRIDGE) return failure();
      let newline;
      while ((newline = buffer.indexOf(10)) !== -1) {
        const line = buffer.subarray(0, newline);
        buffer = buffer.subarray(newline + 1);
        if (line.length > (pending?.maxBridge ?? 4096)) return failure();
        let value;
        try { value = JSON.parse(line.toString('utf8')); } catch { return failure(); }
        if (startup) {
          if (value.ready !== true || value.environment !== readyEnvironment) return failure();
          const current = startup;
          Promise.resolve().then(() => onBootstrap?.(value)).then(() => {
            if (startup === current) { current.resolve(); startup = undefined; }
          }, () => failure());
        } else if (pending && value.seq === pending.seq && typeof value.ok === 'boolean') {
          const current = pending; pending = undefined;
          if (value.ok) current.resolve(value.result);
          else current.reject(new Error('coupon request failed'));
        } else return failure();
      }
    });
    try { await ready; } finally { clearTimeout(timer); }
  }

  function request(kind, context, fields = {}, expectedProtocol = COUPON_PROTOCOL) {
    let peer;
    try { peer = authenticatedPeer(context, expectedProtocol); } catch (error) { return Promise.reject(error); }
    if (expectedProtocol !== COUPON_PROTOCOL) {
      fields = { ...fields, protocol: expectedProtocol, local_peer: context.localPeer };
    }
    if (closed || !child || queued >= maxQueue) return Promise.reject(new Error('coupon worker unavailable'));
    queued++;
    const operation = chain.then(async () => {
      if (closed || !child) throw new Error('coupon worker unavailable');
      const seq = ++sequence;
      const encoded = Buffer.from(JSON.stringify({ seq, kind, peer, ...fields }) + '\n');
      const maxBridge = expectedProtocol === ISSUER_PROTOCOL ? MAX_BRIDGE : MAX_COUPON_BRIDGE;
      if (encoded.length > maxBridge) throw new Error('coupon bridge frame too large');
      const response = new Promise((resolve, reject) => { pending = { seq, resolve, reject, maxBridge }; });
      const timer = setTimeout(failure, timeoutMs);
      child.stdin.write(encoded);
      try { return await response; } finally { clearTimeout(timer); }
    });
    chain = operation.catch(() => {});
    return operation.finally(() => { queued--; });
  }

  async function streamStep(lp, operation) {
    let timer;
    try {
      return await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          try { lp?.unwrap?.().abort(new Error('coupon stream timeout')); } catch {}
          reject(new Error('coupon stream timeout'));
        }, timeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }

  const makeHandle = (expectedProtocol, maxFrame = MAX_FRAME) => async (lp, send, recv, context) => {
    let response = FAILED;
    try {
      const peer = authenticatedPeer(context, expectedProtocol); // Validate transport context before reading.
      if (!admit(peer)) throw new Error('coupon peer rate exceeded');
      const frame = await streamStep(lp, recv);
      if (!(frame instanceof Uint8Array) || frame.byteLength > maxFrame) throw new Error('invalid coupon frame');
      const kind = expectedProtocol === COUPON_PROTOCOL ? 'dispatch' :
        expectedProtocol === COUPON_PROTOCOL_V2 ? 'dispatch_v2' :
        expectedProtocol === COUPON_PROTOCOL_V3 ? 'dispatch_v3' :
        expectedProtocol === COUPON_PROTOCOL_V4 ? 'dispatch_v4' : 'issuer_dispatch';
      const result = await request(kind,
        context, { frame: Buffer.from(frame).toString('base64') }, expectedProtocol);
      response = Buffer.from(result.frame, 'base64');
      if (response.length > maxFrame) throw new Error('invalid coupon response');
    } catch { response = FAILED; }
    await streamStep(lp, () => send(response));
  };

  await start();
  return {
    service: Object.freeze({ handle: makeHandle(COUPON_PROTOCOL), maxDataLength: MAX_FRAME, raw: true, timeoutMs: timeoutMs * 2 }),
    serviceV2: Object.freeze({ handle: makeHandle(COUPON_PROTOCOL_V2), maxDataLength: MAX_FRAME, raw: true, timeoutMs: timeoutMs * 2 }),
    serviceV3: Object.freeze({ handle: makeHandle(COUPON_PROTOCOL_V3), maxDataLength: MAX_FRAME, raw: true, timeoutMs: timeoutMs * 2 }),
    serviceV4: Object.freeze({ handle: makeHandle(COUPON_PROTOCOL_V4), maxDataLength: MAX_FRAME, raw: true, timeoutMs: timeoutMs * 2 }),
    issuerService: Object.freeze({ handle: makeHandle(ISSUER_PROTOCOL, MAX_ISSUER_FRAME), maxDataLength: MAX_ISSUER_FRAME, raw: true, timeoutMs: timeoutMs * 2 }),
    provisionV4: (context, budgetNanoUsd, claimExpiresAt) => {
      if (typeof budgetNanoUsd !== 'string' || !/^[1-9][0-9]{0,18}$/.test(budgetNanoUsd) ||
          BigInt(budgetNanoUsd) > 9223372036854775807n || typeof claimExpiresAt !== 'string') {
        return Promise.reject(new Error('invalid coupon provision request'));
      }
      return request('provision_v4', context, { budget: budgetNanoUsd, claim_expires_at: claimExpiresAt }, COUPON_PROTOCOL_V4);
    },
    pendingV4: context => request('pending_v4', context, {}, COUPON_PROTOCOL_V4),
    provision: (context, budgetNanoUsd, recipientPeer) => {
      if (!Number.isSafeInteger(budgetNanoUsd) || budgetNanoUsd <= 0 || typeof recipientPeer !== 'string') {
        return Promise.reject(new Error('invalid coupon provision request'));
      }
      return request('provision', context, { budget: budgetNanoUsd, recipient_peer: recipientPeer });
    },
    pending: context => request('pending', context),
    provisionV2: (context, budgetNanoUsd, recipientPeer, claimExpiresAt) => {
      if (typeof budgetNanoUsd !== 'string' || !/^[1-9][0-9]{0,18}$/.test(budgetNanoUsd) ||
          BigInt(budgetNanoUsd) > 9223372036854775807n || typeof recipientPeer !== 'string' ||
          typeof claimExpiresAt !== 'string') return Promise.reject(new Error('invalid coupon provision request'));
      return request('provision_v2', context, { budget: budgetNanoUsd,
        recipient_peer: recipientPeer, claim_expires_at: claimExpiresAt }, COUPON_PROTOCOL_V2);
    },
    pendingV2: context => request('pending_v2', context, {}, COUPON_PROTOCOL_V2),
    provisionV3: (context, budgetNanoUsd, claimExpiresAt) => {
      if (typeof budgetNanoUsd !== 'string' || !/^[1-9][0-9]{0,18}$/.test(budgetNanoUsd) ||
          BigInt(budgetNanoUsd) > 9223372036854775807n || typeof claimExpiresAt !== 'string') {
        return Promise.reject(new Error('invalid coupon provision request'));
      }
      return request('provision_v3', context, { budget: budgetNanoUsd,
        claim_expires_at: claimExpiresAt }, COUPON_PROTOCOL_V3);
    },
    pendingV3: context => request('pending_v3', context, {}, COUPON_PROTOCOL_V3),
    close: async () => { closed = true; failure(); await stop(); },
    restart: async () => {
      if (closed) throw new Error('coupon bridge closed');
      if (queued || pending || restarting) throw new Error('coupon bridge busy');
      restarting = true;
      try { await stop(); await start(); } finally { restarting = false; }
    },
  };
}
