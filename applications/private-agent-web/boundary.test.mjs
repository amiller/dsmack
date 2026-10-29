import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';

const base=process.env.BASE_URL||'http://127.0.0.1:18731/private-agent/';
const evidence=resolve(process.env.EVIDENCE||'local-data/ui-boundaries');
assert(process.env.PUBLIC_NODE_FIXTURE,'Set PUBLIC_NODE_FIXTURE to public historical node/enrollment data only');
const fixture=JSON.parse(await readFile(process.env.PUBLIC_NODE_FIXTURE,'utf8'));
const moduleName=process.env.PLAYWRIGHT_MODULE||'playwright';
const {chromium}=await import(isAbsolute(moduleName)?pathToFileURL(moduleName).href:moduleName);
await mkdir(evidence,{recursive:true});
const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
const report={baseURL:base,startedAt:new Date().toISOString(),browser:browser.version(),
  scope:'Browser UI checks with historical public node/enrollment, mocked discovery/RPC, and synthetic provider protocol responses; no real hardware/model-attestation success claim. Provider refusal tests intercept a synthetic chat POST and refuse before answer acceptance, not before the prompt POST.',cases:[]};
if(new URL(base).hostname==='pod.dstack.soc1024.com'){
  const response=await fetch(new URL('/_api/projects/private-agent',base),{signal:AbortSignal.timeout(10000)});
  assert(response.ok,'Cannot read the live page deployment metadata');
  const project=await response.json();
  report.deployment={name:project.name,runtime:project.runtime,isolation:project.isolation,mode:project.mode,ref:project.ref};
}
const jsonHeaders={'content-type':'application/json'};
const model='deepseek-ai/DeepSeek-V3.1';
const clone=value=>JSON.parse(JSON.stringify(value));
const word=value=>BigInt(value).toString(16).padStart(64,'0');

async function ready(page){
  await page.goto(base,{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>document.documentElement.dataset.ready==='true',null,{timeout:30000});
  await page.waitForFunction(()=>document.querySelector('#service').textContent!=='Connecting to the broker…'||!document.querySelector('#alert').hidden);
}
async function refusal(page,pattern){
  await page.waitForFunction(source=>{
    const alert=document.querySelector('#alert');
    return alert&&!alert.hidden&&new RegExp(source,'i').test(alert.textContent);
  },pattern.source,{timeout:15000});
  return page.locator('#alert').textContent();
}
function monitor(page){
  const calls=[];
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.pathname.includes('/relay-broker/'))calls.push({method:request.method(),path:url.pathname});
  });
  return calls;
}
function noJobData(calls){
  assert(!calls.some(call=>call.method==='POST'&&/\/(sandbox\/jobs|payments\/grant)$/.test(call.path)),
    'A refused node received a job or payment grant POST');
}
async function loadPolicy(page,policy){
  await page.locator('#policy').setInputFiles({name:'historical-public-policy.json',mimeType:'application/json',
    buffer:Buffer.from(JSON.stringify(policy))});
}
async function historicalNode(page,change=()=>{}){
  const response=await page.request.get(new URL('config.json',base).href);
  assert(response.ok(),'Cannot load public page configuration');
  const cfg=await response.json(),policy={...clone(fixture.policy),rpc:cfg.rpc,grantSigner:cfg.grantSigner};
  const registration=clone(fixture.registration);
  change(registration,policy);
  const mockedConfig={...cfg,brokerKey:fixture.policy.brokerKey};
  delete mockedConfig.sandboxPolicy;
  await page.route(new URL('config.json',base).href,route=>route.fulfill({status:200,headers:jsonHeaders,body:JSON.stringify(mockedConfig)}));
  await page.route('**/relay-broker/key',route=>route.fulfill({status:200,headers:jsonHeaders,
    body:JSON.stringify({algorithm:'Ed25519',public_key:fixture.policy.brokerKey})}));
  await page.route('**/relay-broker/nodes',route=>route.fulfill({status:200,headers:jsonHeaders,
    body:JSON.stringify([{relay_peer:registration.relay_peer}])}));
  await page.route('**/relay-broker/sandbox/nodes/**/attestation?*',route=>route.fulfill({status:200,headers:jsonHeaders,
    body:JSON.stringify(registration)}));
  const rpc=[];
  await page.route(cfg.rpc,async route=>{
    const request=route.request().postDataJSON();
    rpc.push({method:request.method,selector:request.params?.[0]?.data?.slice(0,10)});
    let result;
    if(request.method==='eth_chainId')result='0x14a34';
    else if(request.method==='eth_call'){
      const selector=request.params[0].data.slice(0,10);
      if(selector==='0xb4eb10ce')result='0x'+'0'.repeat(24)+'f7bbd6dbb5708d3470940dcc19e2b2c75706ee8e';
      else if(selector==='0x5523509a')result='0x'+word(3);
      else if(selector==='0x65f4df9c')result='0x'+fixture.assertionRpIdHash;
    }
    assert(result,'Unexpected public RPC read in refusal fixture: '+JSON.stringify(rpc.at(-1)));
    await route.fulfill({status:200,headers:jsonHeaders,body:JSON.stringify({jsonrpc:'2.0',id:request.id,result})});
  });
  return {policy,rpc};
}
async function send(page,text){
  const editor=page.locator('message-editor'),input=editor.locator('textarea,[contenteditable="true"]').first();
  await input.fill(text);
  const button=editor.getByRole('button',{name:/send/i});
  if(await button.count())await button.first().click();else await input.press('Enter');
}
async function confirmedFixture(page,priceWei='1'){
  await page.locator('#burner').click();
  await page.waitForFunction(()=>/0x[0-9a-fA-F]{40}/.test(document.querySelector('#wallet').textContent));
  const payer=(await page.locator('#wallet').textContent()).match(/0x[0-9a-fA-F]{40}/)[0];
  await page.evaluate(async({payer,priceWei})=>{
    await new Promise((resolve,reject)=>{
      const open=indexedDB.open('dsmack-private-agent',1);
      open.onerror=()=>reject(open.error);
      open.onsuccess=()=>{
        const db=open.result,tx=db.transaction('wallet','readwrite');
        tx.objectStore('wallet').put([{status:'confirmed',unit:2,amount:'1000',used:'0',paidWei:String(1000n*BigInt(priceWei)),priceWei,
          payer,txHash:'0x'+'33'.repeat(32),purchaseId:'900002',allocation:{status:'active'}}],'purchases');
        tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);
      };
    });
  },{payer,priceWei});
  await ready(page);
}
async function providerFixture(page,kind){
  const cfg=await(await page.request.get(new URL('config.json',base).href)).json();
  await page.route('**/relay-broker/inference/quote',route=>route.fulfill({status:200,headers:jsonHeaders,
    body:JSON.stringify({mode:'broker-proxy',provider:'near',model,chainId:84532,escrow:cfg.escrow,codeHash:cfg.codeHash,
      unit:'tokens',unitId:2,priceWei:kind==='valid'?'17':'1',floorPriceWei:'1',maxTokens:10000000,requestTokenCeiling:100,configured:true})}));
  let intercepted=0;
  const answer=kind==='valid'?'Synthetic streamed protocol answer.':'UNVERIFIED_PROVIDER_ANSWER_MUST_NOT_RENDER';
  let usageReads=0;
  if(kind==='valid')await page.route('**/relay-broker/inference/usage',route=>{
    usageReads++;
    return route.fulfill({status:200,headers:jsonHeaders,body:JSON.stringify({purchaseId:'900002',usedTokens:'7',costNanoUsd:'9876',
      usage:{rows:[{keyId:'synthetic-protocol-key',inferenceId:'synthetic-protocol-inference',totalTokens:7,costNanoUsd:'9876'}],
        inputTokens:3,outputTokens:4,totalTokens:7,costNanoUsd:'9876'}})});
  });
  await page.route('**/relay-broker/inference/chat',async route=>{
    const request=route.request().postDataJSON();
    intercepted++;
    const expected=createHash('sha256').update('dsmack-near-attestation/1:'+request.purchaseId+':'+request.txHash+':'+request.nonce).digest('hex');
    const attestation={mode:'broker-proxy',provider:'near',model,verification:'verified',verifier:'synthetic-browser-refusal-fixture',
      nonce:kind==='nonce'?'00'.repeat(32):expected,verifiedAt:Math.floor(Date.now()/1000)-(kind==='timestamp'?3600:0),
      gateway:{signingAddress:'0x'+'11'.repeat(20),tlsFingerprint:'11'.repeat(32)},models:[{model,signingAddress:'0x'+'22'.repeat(20)}],
      tls:{checkedBy:'broker',browserObservable:false,binding:'spki'},report:{fixture:true}};
    const deltas=kind==='valid'?['Synthetic streamed ','protocol answer.']:[answer];
    const body='event: attestation\ndata: '+JSON.stringify(attestation)+'\n\n'
      +deltas.map(content=>'data: '+JSON.stringify({model,choices:[{delta:{content}}]})+'\n\n').join('')+'data: [DONE]\n\n';
    await route.fulfill({status:200,headers:{'content-type':'text/event-stream'},body});
  });
  return {answer,count:()=>intercepted,usageReads:()=>usageReads};
}
async function run(name,mode,fn){
  if(process.env.CASE_FILTER&&process.env.CASE_FILTER!==name)return;
  const context=await browser.newContext({viewport:{width:1440,height:1100}}),page=await context.newPage();
  const errors=[],result={name,mode,status:'failed'},started=Date.now();
  page.on('pageerror',error=>errors.push(error.message));
  try{Object.assign(result,await fn(page));assert.equal(errors.length,0,errors.join('; '));result.status='passed';}
  catch(error){result.error=error.message;result.pageErrors=errors;}
  try{await page.screenshot({path:resolve(evidence,name+'.png'),fullPage:true});}catch(error){result.screenshotError=error.message;}
  result.elapsedMs=Date.now()-started;report.cases.push(result);await context.close();
  await writeFile(resolve(evidence,'boundary-results.json'),JSON.stringify(report,null,2)+'\n');
  console.log(`${result.status}: ${name}`);
}

try{
  for(const [name,change,pattern] of [
    ['tampered-node-signature',registration=>{registration.attestation=fixture.tamperedSignatureProof;},/Node attestation refused:.*assertion signature/],
    ['swapped-compose-measurement',registration=>{registration.manifest_sha256='00'.repeat(32);},/Node attestation refused:.*registration measurements/],
    ['swapped-image-measurement',registration=>{registration.os_image_hash='00'.repeat(32);},/Node attestation refused:.*registration measurements/],
  ]){
    await run(name,'historical public node and mocked discovery/RPC snapshot',async page=>{
      const calls=monitor(page),{policy,rpc}=await historicalNode(page,change);
      await ready(page);await loadPolicy(page,policy);
      await page.waitForFunction(()=>document.querySelector('#node-status').textContent.includes('Trusted policy loaded'));
      await page.locator('#discover').click();
      const alert=await refusal(page,pattern);noJobData(calls);
      assert(!(await page.locator('#node-status').textContent()).includes('Node verified'));
      return {alert,calls,rpc,claim:'Real UI verification refused the public fixture before any repository/job/grant POST.'};
    });
  }
  await run('wrong-policy-broker-key','historical public policy with wrong pinned broker key',async page=>{
    const calls=monitor(page),{policy}=await historicalNode(page);
    policy.brokerKey='00'.repeat(32);
    await ready(page);await loadPolicy(page,policy);
    const alert=await refusal(page,/Wrong broker key or payment signer in sandbox policy/);
    noJobData(calls);return {alert,calls,claim:'Wrong policy broker key refused by the policy-file UI before discovery or job submission.'};
  });
  for(const kind of ['timestamp','nonce']){
    await run('stale-provider-'+kind,'synthetic confirmed credit and intercepted provider SSE',async page=>{
      const calls=monitor(page),provider=await providerFixture(page,kind);
      await ready(page);await confirmedFixture(page);
      await send(page,'Synthetic SC6 provider evidence refusal; no real inference request.');
      const alert=await refusal(page,/Provider attestation.*stale|Provider attestation.*nonce/);
      assert.equal(provider.count(),1,'Expected exactly one intercepted synthetic chat POST');
      assert.equal(await page.getByText(provider.answer,{exact:false}).count(),0,'Unverified answer was rendered');
      assert.equal(await page.locator('#attestations .evidence-item').count(),0,'Stale report was shown as verified answer evidence');
      noJobData(calls);
      assert(!calls.some(call=>call.method==='POST'&&/\/inference\/mint$/.test(call.path)),'Fixture unexpectedly minted a key');
      return {alert,calls,claim:'Synthetic prompt was sent only to an intercepted browser route. Stale/foreign evidence refused before answer acceptance; this is not pre-send provider attestation verification.'};
    });
  }
  await run('streaming-and-usage-protocol','mocked SSE, attestation labels, confirmed credit, and per-key usage',async page=>{
    const calls=monitor(page),provider=await providerFixture(page,'valid');
    await ready(page);await confirmedFixture(page,'17');
    await send(page,'Synthetic protocol adapter check; no real provider call.');
    await page.getByText(provider.answer,{exact:false}).first().waitFor({state:'visible'});
    await page.waitForFunction(()=>document.querySelector('#usage').textContent.includes('Provider: 7 tokens · 9876 nano-USD · 119 wei charged'));
    await page.waitForFunction(()=>document.querySelector('message-editor').isStreaming===false);
    assert.equal(await page.locator('#attestations .evidence-item').count(),1,'Synthetic broker-labelled evidence was not associated with the answer');
    assert.equal(provider.count(),1);assert.equal(provider.usageReads(),1);
    assert(!calls.some(call=>call.method==='POST'&&/\/inference\/mint$/.test(call.path)),'Preallocated fixture unexpectedly minted a key');
    noJobData(calls);
    return {calls,displayedUsage:await page.locator('#usage').textContent(),
      claim:'Two synthetic completion SSE frames render one answer and one broker-labelled evidence item. Mocked per-key usage reports 7 tokens at 17 wei/token, displaying exactly 119 wei and 9876 nano-USD. This tests the Agent adapter protocol, not real provider or attestation verification.'};
  });
  await run('expired-unminted-token-refund','synthetic pending purchase and injected wallet; real pinned escrow code read',async page=>{
    const {Interface}=await import('ethers');
    const abi=new Interface([
      'function getPurchase(uint256) view returns (tuple(bytes32 node,address payer,bytes32 buyerKey,address operator,uint8 unit,uint128 amount,uint128 price,uint128 floorPrice,uint64 boughtAt,uint64 expires,uint64 sequence,uint128 used,uint64 endedAt,bool closed,bytes32 bindingHash))',
      'function refund(uint256)',
    ]);
    const cfg=await(await page.request.get(new URL('config.json',base).href)).json();
    const payer='0x'+'44'.repeat(20),zero='0x'+'00'.repeat(32),purchaseId='900003',now=Math.floor(Date.now()/1000);
    const encodedPurchase=abi.encodeFunctionResult('getPurchase',[[zero,payer,zero,'0x'+'55'.repeat(20),2,1000,17,1,now-7200,now-3700,0,0,0,false,zero]]);
    await page.addInitScript(({payer,encodedPurchase,getPurchaseSelector})=>{
      window.syntheticRefundRequests=[];
      window.ethereum={
        request:async({method,params})=>{
          if(method==='eth_chainId')return '0x14a34';
          if(method==='eth_accounts'||method==='eth_requestAccounts')return [payer];
          if(method==='eth_call'&&params[0].data.startsWith(getPurchaseSelector))return encodedPurchase;
          if(method==='eth_estimateGas')return '0x186a0';
          if(method==='eth_getTransactionCount')return '0x0';
          if(method==='eth_blockNumber')return '0x1';
          if(method==='eth_sendTransaction'){
            window.syntheticRefundRequests.push(params[0]);
            const error=new Error('SYNTHETIC_REFUND_TRANSACTION_CAPTURED');error.code=4001;throw error;
          }
          throw new Error('Unexpected injected-wallet method: '+method);
        },on(){},removeListener(){},
      };
    },{payer,encodedPurchase,getPurchaseSelector:abi.getFunction('getPurchase').selector});
    await page.route('**/relay-broker/**',route=>route.fulfill({status:503,headers:jsonHeaders,
      body:JSON.stringify({error:'Synthetic unavailable broker; refund must use escrow directly.'})}));
    const calls=monitor(page);
    let realCodeRead=false;
    page.on('request',request=>{
      if(request.url()!==new URL(cfg.rpc).href||request.method()!=='POST')return;
      const body=request.postDataJSON(),rows=Array.isArray(body)?body:[body];
      if(rows.some(row=>row.method==='eth_getCode'&&row.params[0].toLowerCase()===cfg.escrow.toLowerCase()))realCodeRead=true;
    });
    await ready(page);
    await page.evaluate(async({payer,purchaseId})=>{
      await new Promise((resolve,reject)=>{
        const open=indexedDB.open('dsmack-private-agent',1);
        open.onerror=()=>reject(open.error);
        open.onsuccess=()=>{
          const db=open.result,tx=db.transaction('wallet','readwrite');
          tx.objectStore('wallet').put([{status:'pending',unit:2,amount:'1000',used:'0',paidWei:'17000',priceWei:'17',
            payer,txHash:'0x'+'66'.repeat(32),purchaseId}],'purchases');
          tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);
        };
      });
    },{payer,purchaseId});
    await ready(page);await page.locator('#connect').click();
    await page.waitForFunction(payer=>document.querySelector('#wallet').textContent.toLowerCase()===payer.toLowerCase(),payer);
    await page.locator('#unit').selectOption('2');await page.locator('#refund').click();
    await page.waitForFunction(()=>window.syntheticRefundRequests.length===1,null,{timeout:30000});
    const [request]=await page.evaluate(()=>window.syntheticRefundRequests);
    assert.equal(request.to.toLowerCase(),cfg.escrow.toLowerCase());
    assert.equal(request.data,abi.encodeFunctionData('refund',[purchaseId]));
    assert(realCodeRead,'Pinned escrow code was not checked through the real RPC');
    assert(!calls.some(call=>call.method==='POST'&&/\/inference\/close$/.test(call.path)),'Unminted credit called provider close');
    noJobData(calls);
    const alert=await refusal(page,/SYNTHETIC_REFUND_TRANSACTION_CAPTURED|user rejected/);
    return {alert,calls,requestedTransaction:{to:request.to,data:request.data},realPinnedEscrowCodeRead:realCodeRead,
      claim:'Expired pending tokens without an allocation reach the pinned escrow refund(uint256) path despite broker503. Injected wallet captures and refuses eth_sendTransaction, so no transaction or successful refund occurred.'};
  });
}finally{
  report.finishedAt=new Date().toISOString();report.passed=report.cases.every(result=>result.status==='passed');
  await writeFile(resolve(evidence,'boundary-results.json'),JSON.stringify(report,null,2)+'\n');await browser.close();
}
if(!report.passed)process.exitCode=1;
