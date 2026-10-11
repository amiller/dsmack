#!/usr/bin/env node
// Private Mac-only bootstrap holder. Never publish its directory or stdout.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyMacRunner } from '../runner/verify/macrunner.mjs';

const DOMAIN = 'dsmack-coupon-mac-control-v1';
const canonical = v => JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))));
export function verifyControl(value, { challenge, composeHash, cdhash, now = new Date(), verifyRunner = verifyMacRunner }) {
  if (!value || Object.keys(value).sort().join(',') !== 'binding,evidence,possession_signature_hex') throw new Error('control refused');
  const b = value.binding;
  if (!b || Object.keys(b).sort().join(',') !== 'challenge_hex,compose_hash,public_key_hex,version'
      || b.version !== 1 || b.challenge_hex !== challenge || b.compose_hash !== composeHash
      || typeof b.public_key_hex !== 'string' || !/^[0-9a-f]{64}$/.test(b.public_key_hex)
      || typeof value.possession_signature_hex !== 'string' || !/^[0-9a-f]{128}$/.test(value.possession_signature_hex)) throw new Error('control refused');
  const data = DOMAIN + '|' + crypto.createHash('sha256').update(canonical(b)).digest('hex');
  verifyRunner(value.evidence, { cdhashes: [cdhash], composeHashes: [composeHash], expectData: data, now });
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b.public_key_hex, 'hex')]), format: 'der', type: 'spki' });
  if (!crypto.verify(null, Buffer.from(DOMAIN + '\0' + data), publicKey, Buffer.from(value.possession_signature_hex, 'hex'))) throw new Error('control refused');
  return { issuer_public_key_hex: b.public_key_hex, compose_hash: composeHash, cdhash,
    scope: 'verified-mac-control-signer; not coupon permission', observed_at_unix: Math.floor(now.getTime() / 1000) };
}

async function privateFile(filename) {
  const f = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.uid !== process.getuid() || (s.mode & 0o077) || s.nlink !== 1 || s.size > 65535) throw new Error('private control required');
    return await f.readFile();
  } finally { await f.close(); }
}

export async function hold({ dir, composeHash, cdhash, port, verifyRunner = verifyMacRunner, input = process.stdin }) {
  if (!path.isAbsolute(dir) || !/^[0-9a-f]{64}$/.test(composeHash) || !/^[0-9a-f]{64}$/.test(cdhash)
      || !Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('invalid control target');
  const stat = await fs.lstat(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('private control directory required');
  const marker = await fs.open(path.join(dir, 'holder-started.json'), 'wx', 0o600);
  await marker.writeFile(JSON.stringify({ pid: process.pid, compose_hash: composeHash, port })); await marker.sync(); await marker.close();
  const output = await fs.open(path.join(dir, 'operator-output.jsonl'), 'wx', 0o600);
  let authenticated = false, active, outputBytes = 0;
  const server = net.createServer(socket => {
    if (active || authenticated) { socket.destroy(); return; }
    active = socket;
    const challenge = crypto.randomBytes(32).toString('hex');
    socket.setTimeout(15000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('close', () => { if (active === socket) active = undefined; });
    let buffer = Buffer.alloc(0), verifiedSession = false, processing = Promise.resolve(), receivedBytes = 0;
    const forward = chunk => { if (!socket.destroyed) socket.write(chunk); };
    socket.once('close', () => input.removeListener('data', forward));
    async function sendControls() {
      const deadline = Date.now() + 900000;
      let frames;
      while (!socket.destroyed && Date.now() < deadline) {
        try { frames = [await privateFile(path.join(dir, 'approval.json')), await privateFile(path.join(dir, 'config.json'))]; break; }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      if (!frames || socket.destroyed) throw new Error('control unavailable');
      for (const frame of frames) {
        JSON.parse(frame.toString()); socket.write(frame); socket.write('\n'); frame.fill(0);
      }
      input.on('data', forward);
    }
    socket.on('data', chunk => {
      receivedBytes += chunk.length;
      if (receivedBytes > 1048576) { socket.destroy(); return; }
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 65536) { socket.destroy(); return; }
      let end;
      while ((end = buffer.indexOf(10)) >= 0) {
        const line = Buffer.from(buffer.subarray(0, end));
        buffer = buffer.subarray(end + 1);
        processing = processing.then(async () => {
          if (socket.destroyed) return;
          try {
            if (line.length > 65535) throw new Error('control frame refused');
            const value = JSON.parse(line.toString());
            if (!verifiedSession) {
              const verified = verifyControl(value, { challenge, composeHash, cdhash, verifyRunner });
              authenticated = verifiedSession = true; socket.setTimeout(0);
              await fs.writeFile(path.join(dir, 'verified-control.json'), JSON.stringify(verified), { flag: 'wx', mode: 0o600 });
              void sendControls().catch(() => socket.destroy());
            } else {
              // Raw grants/envelopes belong only in this protected operator
              // journal, never console/Runner stdout/publicstatus.
              if (!value || typeof value !== 'object' || Array.isArray(value)
                  || Object.hasOwn(value, 'noise_seed_hex') || outputBytes + line.length + 1 > 1048576) throw new Error('control reply refused');
              await output.write(Buffer.concat([line, Buffer.from('\n')])); await output.sync();
              outputBytes += line.length + 1;
            }
          } catch { socket.destroy(); }
          finally { line.fill(0); }
        });
      }
    });
    socket.write(JSON.stringify({ op: 'challenge', challenge_hex: challenge }) + '\n');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { close: async () => { active?.destroy(); await new Promise(resolve => server.close(resolve)); await output.close(); } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [dir, composeHash, cdhash, textPort] = process.argv.slice(2);
  hold({ dir, composeHash, cdhash, port: Number(textPort) }).then(holder => {
    process.once('SIGTERM', () => holder.close()); process.once('SIGINT', () => holder.close());
  }).catch(() => { console.error('Mac control holder refused.'); process.exitCode = 1; });
}
