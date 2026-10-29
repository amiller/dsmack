import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';

// Run inside the recorder. Only public deployment data and synthetic text leave it.
const {chromium} = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE));
const out = process.env.EVIDENCE || '/output';
await mkdir(out, {recursive:true});
const base = process.env.BASE_URL || 'https://pod.dstack.soc1024.com/private-agent/';
const marker = 'W4_CHAT_' + randomBytes(12).toString('hex');
const report = {url:base, startedAt:new Date().toISOString(), marker,
  freshProfile:true, realProvider:true, transactionsAllowed:false,
  requests:[], errors:[], phases:[], cases:[]};
const browser = await chromium.launch({headless:false,
  executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',
  args:['--no-sandbox','--disable-dev-shm-usage','--no-first-run']});
const context = await browser.newContext({viewport:{width:1440,height:1100}});
const page = await context.newPage();
const observations = [];
let prepared, usage, wire, before, after;
page.on('pageerror', e => report.errors.push(e.message));
page.on('request', req => {
  const url = new URL(req.url());
  if (url.origin !== new URL(base).origin) return;
  const raw = req.postData() || '';
  report.requests.push({path:url.pathname,method:req.method(),
    plaintextMarker:raw.includes(marker)});
});
// Enforce this run's explicit no-transaction instruction at the network boundary.
await context.route('**/*', async route => {
  const raw = route.request().postData() || '';
  if (/"(?:eth_sendRawTransaction|eth_sendTransaction)"/.test(raw)) {
    report.errors.push('Forbidden transaction attempt blocked');
    return route.abort('blockedbyclient');
  }
  return route.continue();
});
page.on('response', res => {
  const path = new URL(res.url()).pathname;
  if (path.endsWith('/inference/prepare') && res.ok()) {
    observations.push(res.json().then(value => { prepared=value; }));
  }
  if (path.endsWith('/inference/usage') && res.ok()) {
    observations.push(res.json().then(value => { usage=value; }));
  }
  if (path.endsWith('/inference/chat')) {
    observations.push(res.text().then(raw => {wire={http:res.status(),
      inferenceId:res.headers()['inference-id'],bytes:Buffer.byteLength(raw),
      plaintextMarker:raw.includes(marker)};}));
  }
});
async function phase(label) {
  report.phases.push({label,at:new Date().toISOString()});
  await page.evaluate(text => {
    let el=document.getElementById('w4-recording-label');
    if (!el) {
      el=document.createElement('div'); el.id='w4-recording-label';
      el.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#142b45;color:white;padding:10px;font:16px sans-serif';
      document.body.append(el);
    }
    el.textContent=text;
  },label);
  await page.waitForTimeout(2500);
}
async function shot(name) {await page.screenshot({path:out+'/'+name+'.png',fullPage:true});}
async function refused(id, text, name) {
  const start=report.requests.length;
  await page.locator('#'+id).click();
  await page.waitForFunction(pattern=>new RegExp(pattern,'i').test(document.querySelector('#alert').textContent),text);
  const message=await page.locator('#alert').textContent();
  assert(!report.requests.slice(start).some(r=>r.method==='POST' && /sandbox\/jobs|payments\/(?:allocate|grant)/.test(r.path)));
  report.cases.push({name,result:'PASS',message,noJobOrAllocationSent:true});
  await shot(name);
}
try {
  await page.goto(base,{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>document.documentElement.dataset.ready==='true',null,{timeout:60000});
  await page.waitForFunction(()=>document.querySelector('#service').textContent.startsWith('Chat ready'),null,{timeout:60000});
  assert.equal(await page.locator('#wallet').textContent(),'No wallet connected');
  await phase('SC1 · Fresh browser. New transactions prohibited: paid top-up and finality wait are skipped.');
  await page.locator('#burner').click();
  await page.waitForFunction(()=>BigInt(document.querySelector('#chat-credit').dataset.remainingNanoUsd||'0')>0n);
  report.wallet=await page.locator('#wallet').textContent();
  before=await page.locator('#chat-credit').evaluate(e=>({...e.dataset}));
  await shot('01-fresh-wallet');
  await phase('SC2 · Real NEAR TEE chat. Fresh attestation, browser encryption, provider usage.');
  const input=page.locator('#chat-editor textarea');
  await input.fill('Reply only with '+marker+'.');
  await input.press('Enter');
  await page.waitForFunction(()=>BigInt(document.querySelector('#chat-credit').dataset.spentNanoUsd||'0')>0n,null,{timeout:180000});
  await Promise.all(observations);
  after=await page.locator('#chat-credit').evaluate(e=>({...e.dataset}));
  assert.equal(prepared.attestation.verification,'verified');
  assert.equal(wire.http,200); assert(!wire.plaintextMarker);
  assert(report.requests.every(r=>!r.plaintextMarker));
  assert.equal(BigInt(before.remainingNanoUsd)-BigInt(after.remainingNanoUsd),BigInt(usage.spentNanoUsd));
  assert.equal(usage.spentNanoUsd,after.spentNanoUsd);
  assert.equal(usage.reservedNanoUsd,'0'); assert(BigInt(usage.usedTokens)>0n);
  const conversation=await page.locator('#messages').innerText();
  const markerEchoed=conversation.split(marker).length>=3;
  report.chat={result:markerEchoed?'PASS':'FAIL',markerEchoed,conversation,before,after,usage,attestation:prepared.attestation,
    modelPublicKey:prepared.modelPublicKey,wire};
  await shot('02-verified-chat');
  await page.locator('#attestations details').first().evaluate(e=>e.open=true);
  await page.locator('#attestations').scrollIntoViewIfNeeded();
  await phase('SC2 · Answer evidence. Browser checks nonce and model key; broker checks quote and TLS.');
  await shot('03-attestation');
  await page.locator('#sample').click();
  await page.locator('#job-prompt').fill('Change greet.txt to say Hello from the private agent.');
  await phase('SC3 · Sandbox attempt on the real page. Confirmed paid credit is required.');
  await refused('run','CREDIT_NOT_CONFIRMED','04-sandbox-credit-refused');
  await page.locator('#discover').click();
  await page.waitForFunction(()=>!document.querySelector('#alert').hidden,null,{timeout:60000});
  report.discovery={alert:await page.locator('#alert').textContent(),nodeStatus:await page.locator('#node-status').textContent()};
  await shot('05-node-discovery');
  await phase('SC7 · Chat debit reconciled in nano-USD. ETH purchase, payout and refund were not performed.');
  await page.locator('#reconcile').click();
  await page.waitForTimeout(3000);
  await page.locator('#refund').scrollIntoViewIfNeeded();
  report.refund={buttonVisible:await page.locator('#refund').isVisible(),clicked:false,
    reason:'No purchase; transactions prohibited by task instruction'};
  await shot('06-reconciliation');
  report.result='PARTIAL';
} catch(e) {
  report.result='FAIL'; report.error=e.message;
  report.alert=await page.locator('#alert').textContent().catch(()=>null);
  await shot('failure').catch(()=>{});
} finally {
  report.finishedAt=new Date().toISOString();
  await writeFile(out+'/journey.json',JSON.stringify(report,null,2)+'\n');
  await context.close(); await browser.close();
}
console.log(JSON.stringify({result:report.result,error:report.error,chat:report.chat?.result}));
if (report.result==='FAIL') process.exitCode=1;
