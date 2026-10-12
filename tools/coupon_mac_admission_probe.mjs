#!/usr/bin/env node
// Coupon-free Mac issuer admission using an explicitly pinned public client checkout.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const refused = () => new Error('Mac public admission probe refused');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function read(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) throw refused();
    const bytes = Buffer.alloc(65537);
    const size = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (size < 1 || size > 65536) throw refused();
    return bytes.subarray(0, size);
  } finally { fs.closeSync(fd); }
}
function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 65536, stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

export async function probe(args) {
  if (args.length !== 7 || args[0] !== '--source-revision' || !/^[0-9a-f]{40}$/.test(args[1])) throw refused();
  const [, revision, sourceRoot, pinPath, approvalPath, approvalRoot, peer] = args;
  if (![sourceRoot, pinPath, approvalPath].every(value => path.isAbsolute(value)) || !hash(approvalRoot)
      || !/^\/dns4\/[A-Za-z0-9.-]+\/tcp\/443\/wss\/p2p\/[A-Za-z0-9]{16,128}$/.test(peer)) throw refused();
  // A matching HEAD with edited source would not be a pinned client. Dependencies
  // remain the operator's reviewed installation; this is not a node_modules audit.
  if (git(sourceRoot, 'rev-parse', 'HEAD') !== revision
      || git(sourceRoot, 'status', '--porcelain', '--untracked-files=all') !== '') throw refused();
  const entry = 'lib/coupon-attested.mjs';
  if (git(sourceRoot, 'ls-files', '--error-unmatch', entry) !== entry) throw refused();
  const pin = JSON.parse(read(pinPath));
  if (!exact(pin, ['identityPolicy', 'expectedIdentityPolicySha256', 'expectedIssuancePolicySha256', 'expectedIssuerPublicKeySha256'])
      || pin.identityPolicy?.profile !== 'mac-appattest-coupon-v1'
      || !['expectedIdentityPolicySha256', 'expectedIssuancePolicySha256', 'expectedIssuerPublicKeySha256'].every(key => hash(pin[key]))) throw refused();
  const approval = read(approvalPath);
  const { couponAttestedClient } = await import(pathToFileURL(path.join(sourceRoot, entry)));
  let client;
  try {
    client = await couponAttestedClient(peer, { ...pin, stagingApproval: { bytes: approval, approvalRoot } }, { timeoutMs: 30000 });
    const identity = client.identity, admission = client.stagingAdmission;
    if (identity.evidenceStatus !== 'verified-apple-appattest-issuer-identity'
        || client.issuerProfile !== 'mac-appattest-coupon-v1' || admission.issuerProfile !== client.issuerProfile) throw refused();
    const result = { version: 1, observed_at_unix: Math.floor(Date.now() / 1000), profile: client.issuerProfile,
      evidenceStatus: identity.evidenceStatus, peer: client.peerId, appleAppId: identity.appleAppId,
      cdhash: identity.cdhash, composeSha256: identity.composeSha256, runtimeAppAttested: identity.runtimeAppAttested,
      ...(identity.runtimeAppAttested ? { runtimeApp: identity.runtimeApp } : {}),
      identityPolicySha256: identity.policySha256, issuancePolicySha256: identity.issuancePolicySha256,
      approvalSha256: admission.approval_sha256, custody: identity.custody,
      privateIssuanceQualified: false, rollbackQualified: false, couponRead: false, bearerSent: false,
      providerAdmitted: false, providerEffects: false };
    await client.close(); client = undefined;
    return result;
  } finally { await client?.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { process.stdout.write(JSON.stringify(await probe(process.argv.slice(2))) + '\n'); }
  catch {
    process.stderr.write('Mac public admission probe refused; no coupon or provider request was made.\n');
    process.exitCode = 1;
  }
}
