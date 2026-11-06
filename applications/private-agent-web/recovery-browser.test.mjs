import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chromium } from 'playwright';
import { recoveryControl } from './email-gate-crypto.mjs';
import { sealArtifact } from './artifact-share.mjs';
const evidence = resolve(process.env.EVIDENCE || 'local-data/recovery');
await mkdir(evidence, { recursive: true });
const tls = await mkdtemp(resolve(evidence, 'tls-'));
const keyPath = resolve(tls, 'key.pem'), certPath = resolve(tls, 'cert.pem');
await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', keyPath, '-out', certPath]);
const server = createServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, async (req, res) => {
  try {
    assert.equal(req.method, 'GET');
    const path = new URL(req.url, 'http://local').pathname.replace(/^\/private-agent\//, '').replace(/^\/?a\//, '') || 'index.html';
    const file = resolve('dist', path); assert(file.startsWith(resolve('dist') + '/'));
    const data = await readFile(file);
    res.writeHead(200, { 'content-type': ({ '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.json': 'application/json' })[extname(file)] });
    res.end(data);
  } catch (e) { res.writeHead(404); res.end(e.message); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const base = `https://127.0.0.1:${server.address().port}/private-agent/`;
process.env.BASE_URL = base;
const { backend, ready } = await import('./test-fixtures/browser-broker.mjs');
const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}), args: ['--no-sandbox', '--ignore-certificate-errors'] });
const results = [];
try {
  for (const width of [390, 1280]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 } });
    const page = await context.newPage(), errors = [], logs = [], calls = [];
    page.setDefaultTimeout(15000);
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', msg => logs.push(msg.type() + ': ' + msg.text()));
    await page.route('**/*', route => new URL(route.request().url()).origin === new URL(base).origin ? route.continue() : route.abort());
    await backend(page, 'ux');
    let pending = null, dk, cancels = 0, recoveryBase = new URL(base).pathname.replace(/\/$/, '');
    await page.route('**/continuity/email/*', async route => {
      const path = new URL(route.request().url()).pathname;
      const action = path.split('/').at(-1);
      assert.equal(path, recoveryBase+'/continuity/email/'+action, 'recovery controls stay scoped to the page project path');
      assert(['status', 'cancel'].includes(action), 'only recovery controls are used by the existing device');
      const body = route.request().postDataJSON(); calls.push({ action, ...body });
      assert.equal(body.auth, (await recoveryControl(dk, action, body.id, body.ts)).auth, 'control request authenticates the saved DK');
      if (action === 'cancel') {
        assert.equal(body.id, pending.id); pending = null; cancels++;
      }
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ pending }) });
    });
    try {
      await ready(page); await page.locator('#start-fresh').click();
      await page.waitForFunction(() => !!document.querySelector('#chat-credit').dataset.remainingNanoUsd);
      dk = await page.evaluate(async () => {
        const db = await new Promise((resolve, reject) => { const r = indexedDB.open('dsmack-private-agent', 1); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
        try { return await new Promise(resolve => { const r = db.transaction('wallet').objectStore('wallet').get('continuity.keys'); r.onsuccess = () => resolve(r.result.dk); }); }
        finally { db.close(); }
      });
      pending = { id: 'requested-on-another-device', releaseAt: Date.now() + 48 * 60 * 60_000 };
      await ready(page);
      const notice = page.locator('#email-recovery-notice');
      await notice.waitFor({ state: 'visible' });
      assert.equal(await page.locator('#advanced').getAttribute('open'), null, 'notice is outside advanced settings');
      assert.match(await notice.innerText(), /Someone requested your wallet and chats/);
      await page.screenshot({ path: resolve(evidence, `pending-${width}.png`), fullPage: true });
      await page.locator('#cancel-email-recovery').click();
      await notice.getByText(/Email recovery cancelled/).waitFor();
      assert.equal(cancels, 1, 'one click cancels');
      assert(await page.locator('#cancel-email-recovery').isHidden());
      await page.screenshot({ path: resolve(evidence, `cancelled-${width}.png`), fullPage: true });
      await ready(page);
      await page.waitForFunction(() => document.querySelector('#email-recovery-notice').hidden);
      pending = { id: 'second-request', releaseAt: Date.now() + 48 * 60 * 60_000 };
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await notice.waitFor({ state: 'visible' });
      await page.locator('#cancel-email-recovery').click();
      await notice.getByText(/Email recovery cancelled/).waitFor();
      assert.equal(cancels, 2, 'returning to the tab discovers a new request');
      const shared = await sealArtifact('<!doctype html><p>Recovery routing check</p>');
      await page.route('**/relay-broker/artifacts/share/'+shared.cid, route => route.fulfill({
        contentType:'application/json',body:JSON.stringify({cid:shared.cid,ciphertext:shared.ciphertext})}));
      for (const sharedUrl of [new URL('a/',base),new URL('/a/',base)]) {
        recoveryBase = sharedUrl.pathname === '/a/' ? '' : '/private-agent';
        sharedUrl.hash = new URLSearchParams({cid:shared.cid,k:shared.key}).toString();
        const before = calls.length;
        await page.goto(sharedUrl.href);
        await page.waitForFunction(() => document.documentElement.dataset.ready === 'true');
        await page.waitForFunction(() => document.querySelector('#email-recovery-notice').hidden);
        assert(calls.length>before, 'shared app checks recovery at its owning page path');
      }
      recoveryBase = '/private-agent';
      await ready(page);
      // A new browser retains its ephemeral private key and pending request
      // in IndexedDB across reload, without creating a wallet during the wait.
      await page.evaluate(async () => {
        const request = { id: 'saved-request', email: 'test@example.com', userId: 'test@example.com',
          nonce: 'saved-request', releaseAt: Date.now() + 48 * 60 * 60_000,
          privateKey: (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])).privateKey };
        const db = await new Promise(resolve => { const r = indexedDB.open('dsmack-private-agent', 1); r.onsuccess = () => resolve(r.result); });
        try {
          await new Promise((resolve, reject) => {
            const tx = db.transaction('wallet', 'readwrite'), store = tx.objectStore('wallet');
            for (const key of ['continuity.keys', 'burner']) store.delete(key);
            store.put(request, 'continuity.pendingEmail');
            tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
          });
        } finally { db.close(); }
      });
      await ready(page);
      await page.locator('#finish-email-recovery').waitFor({ state: 'visible' });
      assert.match(await page.locator('#continuity-status').innerText(), /Return to this browser after 48 hours/);
      assert(await page.locator('#welcome').isVisible(), 'waiting does not import keys');
      await page.screenshot({ path: resolve(evidence, `waiting-${width}.png`), fullPage: true });
      assert.deepEqual(errors, []);
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal overflow');
      results.push({ width, status: 'passed', cancellations: cancels, requests: calls.length });
    } catch (e) {
      results.push({ width, status: 'failed', error: e.stack, pageErrors: errors });
      await page.screenshot({ path: resolve(evidence, `failed-${width}.png`), fullPage: true });
    } finally {
      await writeFile(resolve(evidence, `recovery-${width}.log`), logs.join('\n') + '\n' + JSON.stringify(calls));
      await context.close();
    }
    console.log(JSON.stringify(results.at(-1)));
  }
} finally {
  await browser.close(); server.closeAllConnections(); await new Promise(done => server.close(done));
  await rm(tls, { recursive: true });
  await writeFile(resolve(evidence, 'recovery-results.json'), JSON.stringify(results, null, 2));
}
assert(results.every(r => r.status === 'passed'), 'All recovery notice flows pass');
