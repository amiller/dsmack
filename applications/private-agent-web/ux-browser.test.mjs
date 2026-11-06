import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { createCipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { Wallet, SigningKey } from 'ethers';
import { chromium } from 'playwright';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const evidence = resolve(process.env.EVIDENCE || 'local-data/ux');
await mkdir(evidence, { recursive: true });
const tls = await mkdtemp(resolve(evidence, 'tls-'));
const keyPath = resolve(tls, 'key.pem'), certPath = resolve(tls, 'cert.pem');
await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', keyPath, '-out', certPath]);
import { model } from './test-fixtures/near.mjs';
function encrypt(text, publicKey) {
  const ephemeral = Wallet.createRandom(), nonce = randomBytes(12);
  const point = Buffer.from(new SigningKey(ephemeral.privateKey).computeSharedSecret('0x04' + publicKey).slice(2), 'hex');
  const key = Buffer.from(hkdfSync('sha256', point.subarray(1, 33), Buffer.alloc(0), Buffer.from('ecdsa_encryption'), 32));
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([Buffer.from(ephemeral.signingKey.publicKey.slice(2), 'hex'), nonce,
    cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('hex');
}
let mode, turns, closedStreams = 0;
const server = createServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/relay-broker/inference/chat') {
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw), publicKey = body.headers['x-client-pub-key'];
      turns++;
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
      const frame = delta => res.write('data: ' + JSON.stringify({ model, choices: [{ delta }] }) + '\n\n');
      if (['cancel', 'cancel-billing'].includes(mode) && turns === 1) {
        frame({ content: encrypt('Reply in progress…', publicKey) });
        res.on('close', () => closedStreams++); return;
      }
      if (['guest', 'orphan', 'empty', 'busy'].includes(mode) && turns === 1) {
        frame({ tool_calls: [{ index: 0, id: 'call-one', type: 'function', function: {
          name: encrypt('bash', publicKey), arguments: encrypt(JSON.stringify({ command: 'which python3 python; python3 -V' }), publicKey),
        } }] });
        if (mode === 'orphan') { setTimeout(() => res.destroy(), 200); return; }
      } else frame({ content: encrypt('Reply complete.', publicKey) });
      res.end('data: [DONE]\n\n'); return;
    }
    if (req.url.startsWith('/relay-broker/')) { res.writeHead(500); res.end('Unmocked broker route'); return; }
    const path = new URL(req.url, 'http://local').pathname.replace(/^\/private-agent\//, '') || 'index.html';
    const file = resolve('dist', path); assert(file.startsWith(resolve('dist') + '/'));
    const data = await readFile(file);
    res.writeHead(200, { 'content-type': ({ '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.json': 'application/json' })[extname(file)] });
    res.end(data);
  } catch (e) { res.writeHead(404); res.end(e.message); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const base = `https://127.0.0.1:${server.address().port}/private-agent/`;
process.env.BASE_URL = base;
const { backend, ready, send, publicHeaders } = await import('./test-fixtures/browser-broker.mjs');
const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}), args: ['--no-sandbox', '--ignore-certificate-errors'] });
const results = [];
try {
  for (const width of [390, 1280]) for (const scenario of ['cancel', 'cancel-billing', 'guest', 'orphan', 'empty', 'busy', 'local-only']) {
    mode = scenario; turns = 0;
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 } });
    const page = await context.newPage(), errors = [], logs = [];
    page.setDefaultTimeout(15000);
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', msg => logs.push(msg.type() + ': ' + msg.text()));
    // NEAR image provenance is read from the public Rekor log.
    await page.route('**/*', route => [new URL(base).origin, 'https://rekor.sigstore.dev'].includes(new URL(route.request().url()).origin) ? route.continue() : route.abort());
    const calls = await backend(page, 'ux');
    if (scenario === 'local-only') {
      const localConfig = await (await page.request.get(new URL('config.json', base).href)).json();
      localConfig.broker = new URL('/relay-broker', base).href;
      delete localConfig.syncAnchor; delete localConfig.syncAnchorCodeHash;
      await page.route('**/config.json', route => route.fulfill({headers:publicHeaders,body:JSON.stringify(localConfig)}));
    }
    const pendingSync = [];
    let holdUsage = scenario === 'cancel-billing', pendingUsage = 0, observedUsage;
    let usageStarted = new Promise(resolve => observedUsage = resolve);
    if (['cancel', 'cancel-billing'].includes(scenario)) {
      await page.route('**/relay-broker/sync/blob', route => { pendingSync.push(route); });
      await page.route('**/relay-broker/inference/usage', route => {
        if (!holdUsage) return route.fallback();
        pendingUsage++;
        observedUsage();
        return route.fulfill({status:409,headers:publicHeaders,body:JSON.stringify({error:{code:'USAGE_PENDING',message:'Provider cost accounting is pending'}})});
      });
    }
    try {
      await ready(page); await page.locator('#start-fresh').click();
      await page.waitForFunction(() => !!document.querySelector('#chat-credit').dataset.remainingNanoUsd);
      assert.equal(await page.locator('#advanced').getAttribute('open'), null);
      assert(await page.locator('message-editor #repo').isVisible(), 'attachment in composer');
      if (scenario === 'guest') await page.evaluate(() => {
        document.querySelector('#chat').session.state.tools.find(t => t.name === 'bash').execute = async (_id, _args, _signal, update) => {
          update({ content: [{ type: 'text', text: 'Guest started command…' }] });
          await new Promise(resolve => { window.killGuest = resolve; });
          throw Error('Guest stream closed before a result was received. Execution was not retried.');
        };
      });
      if (['empty', 'busy'].includes(scenario)) await page.route('**/relay-broker/nodes*', route => {
        const all = new URL(route.request().url()).searchParams.get('all');
        return route.fulfill({ status: all ? 200 : 503, headers: publicHeaders,
          body: JSON.stringify(all ? scenario === 'empty' ? [] : [{ kind: 'compute', available: false }]
            : { error: { code: scenario === 'empty' ? 'FLEET_EMPTY' : 'FLEET_BUSY', retryAfterSeconds: 2 } }) });
      });
      await send(page, 'Please inspect my code.');
      await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.some(m => m.role === 'assistant') || document.querySelector('#chat').session.state.isStreaming);
      const waitIdle = () => page.waitForFunction(() => !document.querySelector('#chat').session.state.isStreaming);
      const cancel = () => page.locator('message-editor').getByRole('button', { name: /abort|cancel|stop/i }).click();
      if (['cancel', 'cancel-billing'].includes(scenario)) {
        await page.getByText('Reply in progress…', { exact: true }).waitFor();
        await cancel(); await waitIdle();
        if (scenario === 'cancel-billing') {
          await usageStarted;
          assert(pendingUsage>0,'composer becomes idle while provider billing remains pending');
          const cancelled=await page.evaluate(()=>document.querySelector('#chat').session.state.messages.find(m=>m.stopReason==='aborted'));
          assert.equal(cancelled.billing.settled,false);
          assert(BigInt(cancelled.billing.reservedNanoUsd)>0n);
          usageStarted=new Promise(resolve=>observedUsage=resolve);
          await send(page,'A fresh message while the cancelled charge settles.');
          await usageStarted;
          assert.equal(turns,1,'pending provider billing cannot dispatch another model request');
          holdUsage=false;
          await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.filter(m => m.role === 'assistant').length === 2 && !document.querySelector('#chat').session.state.isStreaming);
          assert.equal(turns,2);
          assert.equal(await page.locator('user-message').count(),2);
        } else {
          await page.locator('#retry-reply').click();
          await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.filter(m => m.role === 'assistant').length === 2 && !document.querySelector('#chat').session.state.isStreaming);
          assert.equal(await page.locator('user-message').count(), 1);
          await send(page, 'A fresh message after cancelling.');
          await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.filter(m => m.role === 'assistant').length === 3 && !document.querySelector('#chat').session.state.isStreaming);
          assert.equal(turns, 3);
        }
        assert(closedStreams > 0);
        assert(pendingSync.length > 0, "cancel, retry and send finish while remote sync is stalled");
      } else if (scenario === 'local-only') {
        await waitIdle();
        await page.waitForFunction(() => document.querySelector('#chat').dataset.saved === 'true');
        await page.locator('#sync-status').getByText('Chats save on this device.',{exact:true}).waitFor({state:'attached'});
        assert(await page.locator('#alert').isHidden());
        await ready(page);
        await page.locator('user-message').getByText('Please inspect my code.',{exact:true}).waitFor();
        assert(await page.locator('#alert').isHidden());
        const sessionId = await page.locator('#chat').getAttribute('data-session-id');
        const feedbackText = 'The answer needs a concrete example.';
        const feedback = page.locator('assistant-message message-feedback').first();
        await feedback.getByRole('button', { name: 'Feedback', exact: true }).click();
        await feedback.getByRole('textbox', { name: 'Message feedback' }).fill(feedbackText);
        await feedback.getByRole('button', { name: 'Save', exact: true }).click();
        await page.waitForFunction(() => document.querySelector('#chat').dataset.saved === 'true');
        await ready(page);
        await page.locator('.feedback-note').getByText(feedbackText, { exact: true }).waitFor();
        const download = async name => {
          const pending = page.waitForEvent('download');
          await page.getByRole('button', { name, exact: true }).click();
          const file = await pending;
          assert.match(file.suggestedFilename(), /\.jsonl$/);
          return (await readFile(await file.path(), 'utf8')).trim().split('\n').map(JSON.parse);
        };
        await page.locator('#sessions').click();
        const [exported] = await download('Current chat');
        assert.equal(exported.data.id, sessionId);
        assert.equal(exported.metadata.messageCount, exported.data.messages.length);
        const [record] = exported.data.feedback;
        assert.equal(record.text, feedbackText);
        assert.equal(record.sessionId, sessionId);
        assert.equal(exported.data.messages[record.messageIndex].role, 'assistant');
        assert.match(record.id, /^[0-9a-f-]{36}$/);
        assert(record.pageVersion && record.createdAt);
        assert.equal(record.guestId, undefined);
        await page.keyboard.press('Escape');
        await page.locator('#new-chat').click();
        await page.waitForFunction(id => document.querySelector('#chat').dataset.sessionId !== id, sessionId);
        await page.locator('#sessions').click();
        const all = await download('All chats');
        assert.equal(all.length, 2);
        assert.deepEqual(all.find(r => r.data.id === sessionId).data.feedback, exported.data.feedback);
        const [current] = await download('Current chat');
        assert.notEqual(current.data.id, sessionId);
        assert(!current.data.messages.some(message => ['user', 'assistant', 'toolResult'].includes(message.role)));
        await page.keyboard.press('Escape');
        assert(!JSON.stringify(calls).includes(feedbackText), 'feedback and exports stay in the browser');
        assert(!calls.some(call=>call.path.startsWith('/sync/')),'local-only chats never request chain sync');
      } else if (['empty', 'busy'].includes(scenario)) {
        await page.locator('#capacity-status').getByText(scenario === 'empty' ? /No Macs are connected/ : /All Macs are busy, retry in 2 seconds/).waitFor();
        assert.doesNotMatch(await page.locator('#capacity-status').innerText(), /FLEET_BUSY|broker|Busy,/);
        await page.screenshot({ path: resolve(evidence, `${scenario}-${width}.png`), fullPage: true });
        await cancel(); await waitIdle();
      } else {
        if (scenario === 'guest') {
          await page.waitForFunction(() => !!window.killGuest);
          assert.equal(await page.locator('tool-message').filter({ hasText: 'bash · running' }).count(), 1);
          await page.screenshot({ path: resolve(evidence, `guest-running-${width}.png`), fullPage: true });
          await page.evaluate(() => window.killGuest());
        }
        await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.some(m => m.role === 'toolResult'));
        await waitIdle();
        const messages = await page.evaluate(() => document.querySelector('#chat').session.state.messages);
        const settled = messages.filter(m => m.role === 'toolResult' && m.toolCallId === 'call-one');
        assert.equal(settled.length, 1); assert.equal(settled[0].isError, true);
        assert.equal(await page.locator('tool-message').filter({ hasText: 'bash · running' }).count(), 0);
        assert.equal(await page.locator('tool-message').filter({ hasText: 'bash · failed' }).count(), 1);
        if (scenario === 'guest') {
          const toolFeedback = page.locator('tool-message message-feedback');
          await toolFeedback.getByRole('button', { name: 'Feedback', exact: true }).click();
          await toolFeedback.getByRole('textbox', { name: 'Message feedback' }).fill('Please explain the tool failure.');
          await toolFeedback.getByRole('button', { name: 'Save', exact: true }).click();
          await toolFeedback.getByText('Please explain the tool failure.', { exact: true }).waitFor();
        }
        if (scenario === 'orphan') {
          await page.locator('#retry-reply').click();
          await page.waitForFunction(() => !document.querySelector('#chat').session.state.isStreaming && document.querySelector('#chat').session.state.messages.filter(m => m.role === 'assistant').length === 2);
          assert.equal(await page.locator('tool-message').filter({ hasText: 'bash · failed' }).count(), 1);
        }
      }
      assert.deepEqual(errors, []);
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal overflow');
      if (!['empty', 'busy'].includes(scenario)) await page.screenshot({ path: resolve(evidence, `${scenario}-${width}.png`), fullPage: true });
      results.push({ scenario, width, status: 'passed', modelRequests: turns });
    } catch (e) {
      results.push({ scenario, width, status: 'failed', error: e.stack, pageErrors: errors, messages: await page.evaluate(() => document.querySelector('#chat')?.session?.state.messages) });
      await page.screenshot({ path: resolve(evidence, `${scenario}-${width}-failed.png`), fullPage: true });
    } finally {
      await writeFile(resolve(evidence, `${scenario}-${width}.log`), logs.join('\n') + '\n' + JSON.stringify(calls.map(c => c.path)));
      for (const route of pendingSync) await route.fulfill({ status: 503, body: '{}' });
      await context.close();
    }
    console.log(JSON.stringify(results.at(-1)));
  }
} finally {
  await browser.close(); server.closeAllConnections(); await new Promise(done => server.close(done));
  await rm(tls, { recursive: true });
  await writeFile(resolve(evidence, 'ux-results.json'), JSON.stringify(results, null, 2));
}
assert(results.every(r => r.status === 'passed'), 'All browser UX flows pass');
