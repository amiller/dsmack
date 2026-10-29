import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {randomBytes,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const {chromium}=await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE));
const out=process.env.EVIDENCE || '/output';
const base='https://pod.dstack.soc1024.com/private-agent/';
await mkdir(out,{recursive:true});
const marker='W4_PRIVATE_'+randomBytes(12).toString('hex'),reply='PRIVATE_CHAT_READY';
const report={url:base,startedAt:new Date().toISOString(),result:'FAIL',freshProfile:true,realServices:true,
 steps:{wallet:'NOT_RUN',chat:'NOT_RUN',sandbox:'NOT_RUN',credit:'NOT_RUN'},requests:[],errors:[],phases:[],transactionsAttempted:0};
const browser=await chromium.launch({headless:false,executablePath:'/usr/bin/chromium',
 args:['--no-sandbox','--disable-dev-shm-usage','--no-first-run','--window-size=1440,1100']});
const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
const page=await context.newPage(),observations=[];
let prepared,usage,wire,attestationNonce;
await context.route('**/*',async route=>{
 const raw=route.request().postData() || '';
 if (/"(?:eth_sendRawTransaction|eth_sendTransaction)"/.test(raw)) {report.transactionsAttempted++;return route.abort('blockedbyclient');}
 return route.continue();
});
page.on('pageerror',e=>report.errors.push(e.message));
page.on('request',req=>{
 const path=new URL(req.url()).pathname;if(!path.includes('/relay-broker/'))return;
 const raw=req.postData() || '',item={path,method:req.method(),plaintextMarkerHits:Number(raw.includes(marker))};
 if(path.endsWith('/inference/prepare')&&raw)attestationNonce=JSON.parse(raw).attestationNonce;
 if(req.method()==='POST'&&/inference\/chat|sandbox\/jobs/.test(path)){
  item.bytes=Buffer.byteLength(raw);item.sha256=createHash('sha256').update(raw).digest('hex');
 }
 report.requests.push(item);
});
page.on('response',res=>{
 const path=new URL(res.url()).pathname;
 if(path.endsWith('/inference/prepare')&&res.ok())observations.push(res.json().then(v=>{prepared=v;}));
 if(path.endsWith('/inference/usage')&&res.ok())observations.push(res.json().then(v=>{usage=v;}));
 if(path.endsWith('/inference/chat'))observations.push(res.text().then(raw=>{
  wire={http:res.status(),bytes:Buffer.byteLength(raw),plaintextReplyHits:Number(raw.includes(reply)),
   sha256:createHash('sha256').update(raw).digest('hex'),inferenceId:res.headers()['inference-id']};
 }));
});
async function phase(label){
 report.phases.push({label,utc:new Date().toISOString()});
 await page.evaluate(text=>{
  let e=document.getElementById('w4-recording-label');
  if(!e){e=document.createElement('div');e.id='w4-recording-label';
   e.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#142b45;color:white;padding:10px;font:16px sans-serif';document.body.append(e);}
  e.textContent=text;
 },label);
 await page.waitForTimeout(3000);
}
async function shot(name){await page.screenshot({path:out+'/'+name+'.png',fullPage:true});}
try{
 await page.goto(base,{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>document.documentElement.dataset.ready==='true',null,{timeout:60000});
 await page.waitForFunction(()=>document.querySelector('#service').textContent.startsWith('Chat ready'),null,{timeout:60000});
 assert.equal(await page.locator('#wallet').textContent(),'No wallet connected');
 assert.match(await page.locator('#node-status').textContent(),/Approved sandbox policy included/);
 assert.equal(await page.locator('#policy').inputValue(),'');assert.equal(await page.locator('#repo').inputValue(),'');
 await phase('Fresh browser · Live page · First chat and sandbox job included; no ETH purchase.');await shot('01-first-visit');
 await page.locator('#burner').click();
 await page.waitForFunction(()=>document.querySelector('#chat-credit').dataset.remainingNanoUsd==='10000000');
 report.wallet=await page.locator('#wallet').textContent();
 report.creditBefore=await page.locator('#chat-credit').evaluate(e=>({...e.dataset}));
 report.sandboxCreditBefore=await page.locator('#sandbox-credit').textContent();report.steps.wallet='PASS';
 await phase('New browser wallet · $0.010000 chat credit · One sandbox job included.');await shot('02-wallet-credit');
 const editor=page.locator('#chat-editor textarea');
 await editor.fill('Reply with exactly '+reply+'. Do not repeat this private marker: '+marker);await editor.press('Enter');
 await page.waitForFunction(value=>[...document.querySelectorAll('#messages assistant-message')].some(e=>e.textContent.includes(value))||!document.querySelector('#alert').hidden,reply,{timeout:180000});
 assert(await page.locator('#alert').isHidden(),await page.locator('#alert').textContent());
 await page.waitForFunction(()=>BigInt(document.querySelector('#chat-credit').dataset.spentNanoUsd||'0')>0n,null,{timeout:60000});
 await Promise.all(observations);
 report.creditAfter=await page.locator('#chat-credit').evaluate(e=>({...e.dataset}));
 assert.equal(prepared.attestation.nonce,attestationNonce);assert.equal(prepared.attestation.verification,'verified');
 assert.equal(wire.http,200);assert.equal(wire.plaintextReplyHits,0);assert.equal(usage.reservedNanoUsd,'0');assert(BigInt(usage.usedTokens)>0n);
 assert.equal(BigInt(report.creditBefore.remainingNanoUsd)-BigInt(report.creditAfter.remainingNanoUsd),BigInt(usage.spentNanoUsd));
 assert(BigInt(report.creditAfter.remainingNanoUsd)>0n);
 report.chat={reply:await page.locator('#messages assistant-message').last().innerText(),attestation:prepared.attestation,modelPublicKey:prepared.modelPublicKey,usage,wire};
 report.steps.chat='PASS';report.steps.credit='PASS';
 await phase('Real NEAR TEE answer · Fresh attestation checked · Credit decreased by '+usage.spentNanoUsd+' nano-USD.');await shot('03-verified-chat');
 await page.locator('#attestations details').first().evaluate(e=>e.open=true);
 await page.locator('#attestations').scrollIntoViewIfNeeded();
 await phase('Answer evidence · Browser checks nonce and model key; broker verifies hardware quote and pinned TLS.');await shot('04-model-evidence');
 await page.locator('#attestations details').first().evaluate(e=>e.open=false);
 await page.locator('#job-prompt').scrollIntoViewIfNeeded();
 await phase('Run included task · Verify Mac guest automatically · Seal repository and prompt to the guest.');
 await page.locator('#run').click();
 await page.waitForFunction(()=>document.querySelector('#job-status').dataset.patchApplied==='true'||!document.querySelector('#alert').hidden,null,{timeout:360000});
 assert(await page.locator('#alert').isHidden(),await page.locator('#alert').textContent());
 assert.equal(await page.locator('#updated-files pre[data-file="greet.txt"]').innerText(),'Hello from the private agent.\n');
 assert.equal(await page.locator('#sandbox-credit').getAttribute('data-status'),'completed');
 const evidence=JSON.parse(await page.locator('#job-evidence').textContent());
 const transcript=await page.locator('#transcript').textContent();
 const providerEvidence=transcript.split('\n').filter(Boolean).map(x=>JSON.parse(x)).filter(x=>x.type==='provider_attestation');
 assert(providerEvidence.length>0,'No TEE provider evidence in sandbox transcript');
 assert.match(await page.locator('#node-status').textContent(),/Node verified/);
 const downloadPromise=page.waitForEvent('download');await page.locator('#download').click();
 const download=await downloadPromise;await download.saveAs(out+'/patch.diff');
 const patchHash=createHash('sha256').update(await readFile(out+'/patch.diff')).digest('hex');
 assert.equal(patchHash,evidence.statement.outputs.patch);
 await writeFile(out+'/job-evidence.json',JSON.stringify(evidence,null,2)+'\n');await writeFile(out+'/transcript.jsonl',transcript);
 report.sandbox={jobId:evidence.statement.job_id,secondsUsed:evidence.statement.seconds_used,status:await page.locator('#job-status').textContent(),
  patchSha256:patchHash,patchApplied:true,updatedFile:'Hello from the private agent.\n',providerResponses:providerEvidence.length,allowanceAfter:await page.locator('#sandbox-credit').textContent()};
 assert.equal(report.requests.filter(r=>r.method==='POST'&&r.path.endsWith('/sandbox/jobs')).length,1);
 assert(report.requests.every(r=>!r.plaintextMarkerHits));assert.equal(report.transactionsAttempted,0);assert.deepEqual(report.errors,[]);
 report.steps.sandbox='PASS';
 await page.locator('#diff').scrollIntoViewIfNeeded();
 await phase('Verified patch applied · '+evidence.statement.seconds_used+' sandbox seconds · Attestation, receipt and output hashes checked.');await shot('05-verified-patch');
 await page.locator('#updated-files').scrollIntoViewIfNeeded();await page.waitForTimeout(3500);await shot('06-updated-file');
 await page.locator('#sandbox-credit').scrollIntoViewIfNeeded();
 await phase('Complete · Chat credit decreased · Included sandbox job completed · No chain transactions.');await shot('07-credit-and-completed-job');
 report.result='PASS';
}catch(e){report.error=e.message;report.alert=await page.locator('#alert').textContent().catch(()=>null);await shot('failure').catch(()=>{});
}finally{report.finishedAt=new Date().toISOString();await writeFile(out+'/steps.json',JSON.stringify(report,null,2)+'\n');await context.close();await browser.close();}
console.log(JSON.stringify({result:report.result,steps:report.steps,error:report.error}));if(report.result!=='PASS')process.exitCode=1;
