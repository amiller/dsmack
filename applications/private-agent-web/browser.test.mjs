import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';

const base=process.env.BASE_URL||'http://127.0.0.1:18731/private-agent/';
const evidence=resolve(process.env.EVIDENCE||'local-data/private-agent-browser');
const moduleName=process.env.PLAYWRIGHT_MODULE||'playwright';
const {chromium}=await import(isAbsolute(moduleName)?pathToFileURL(moduleName).href:moduleName);
await mkdir(evidence,{recursive:true});
const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
const report={baseURL:base,browser:browser.version(),startedAt:new Date().toISOString(),
  scope:'Live page smoke plus explicitly labelled browser fixtures and mocked-backend refusal checks. These checks do not claim real SC1 credit finality, SC2 inference, or SC3 sandbox completion.',cases:[]};
const responseHeaders={'content-type':'application/json'};
const quote={mode:'broker-proxy',provider:'near',model:'deepseek-ai/DeepSeek-V3.1',unit:'tokens',unitId:2,
  chainId:84532,priceWei:'1',floorPriceWei:'1',maxTokens:10000000,requestTokenCeiling:100,
  maxNanoUsdPerToken:'100000',configured:true};

async function ready(page){
  await page.goto(base,{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>document.documentElement.dataset.ready==='true',null,{timeout:30000});
  await page.locator('message-editor').waitFor({state:'visible'});
  await page.waitForFunction(()=>document.querySelector('#service').textContent!=='Connecting to the broker…'||!document.querySelector('#alert').hidden);
}
async function message(page,text){
  const editor=page.locator('message-editor');
  const input=editor.locator('textarea,[contenteditable="true"]').first();
  await input.fill(text);
  const send=editor.getByRole('button',{name:/send/i});
  if(await send.count())await send.first().click();
  else await input.press('Enter');
}
async function alertIncludes(page,pattern){
  await page.waitForFunction(source=>{
    const alert=document.querySelector('#alert');
    return alert&&!alert.hidden&&new RegExp(source,'i').test(alert.textContent);
  },pattern.source,{timeout:15000});
}
function monitor(page){
  const calls=[];
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.pathname.includes('/relay-broker/'))calls.push({method:request.method(),path:url.pathname});
  });
  return calls;
}
function noSensitivePosts(calls){
  assert(!calls.some(c=>c.method==='POST'&&/\/(inference\/(chat|mint)|sandbox\/jobs)$/.test(c.path)),
    'A refused action sent sensitive data or allocated a provider key');
}
async function backendQuote(page){
  const response=await page.request.get(new URL('config.json',base).href);
  assert(response.ok(),'Page config is unavailable for the mocked quote');
  const cfg=await response.json();
  await page.route('**/relay-broker/inference/quote',async route=>{
    await route.fulfill({status:200,headers:responseHeaders,
      body:JSON.stringify({...quote,escrow:cfg.escrow,codeHash:cfg.codeHash})});
  });
}
async function run(name,mode,fn){
  const context=await browser.newContext({viewport:{width:1440,height:1100}});
  const page=await context.newPage(),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  const result={name,mode,status:'failed'},started=Date.now();
  try{
    Object.assign(result,await fn(page,context));
    assert.equal(errors.length,0,'Uncaught browser errors: '+errors.join('; '));
    result.status='passed';
  }catch(error){result.error=error.message;result.pageErrors=errors;}
  try{await page.screenshot({path:resolve(evidence,name+'.png'),fullPage:true});}
  catch(error){result.screenshotError=error.message;}
  result.elapsedMs=Date.now()-started;
  report.cases.push(result);
  await context.close();
  await writeFile(resolve(evidence,'browser-results.json'),JSON.stringify(report,null,2)+'\n');
  console.log(`${result.status}: ${name} (${mode})`);
}

try{
  await run('fresh-profile-wallet','live page and live backend',async page=>{
    const responses=[];
    page.on('response',response=>{
      const url=new URL(response.url());
      if(url.pathname.includes('/relay-broker/'))responses.push({path:url.pathname,status:response.status()});
    });
    await ready(page);
    await page.getByRole('button',{name:'Create browser wallet',exact:true}).click();
    await page.waitForFunction(()=>/0x[0-9a-fA-F]{40}/.test(document.querySelector('#wallet').textContent));
    const wallet=(await page.locator('#wallet').textContent()).match(/0x[0-9a-fA-F]{40}/)[0];
    await ready(page);
    assert((await page.locator('#wallet').textContent()).includes(wallet),'Browser wallet did not survive reload');
    return {wallet,responses,service:await page.locator('#service').textContent(),
      claim:'Fresh browser profile, zero installation, local wallet generation and persistence only; no funded purchase was attempted.'};
  });

  await run('unconfirmed-credit-refused','mocked inference quote; no credit fixture',async page=>{
    await backendQuote(page);
    const calls=monitor(page);
    await ready(page);
    await message(page,'SC6 refusal check: do not send this uncredited prompt.');
    await alertIncludes(page,/CREDIT_NOT_CONFIRMED|confirmed credit|finalized confirmation/);
    await page.locator('#run').click();
    await alertIncludes(page,/CREDIT_NOT_CONFIRMED|confirmed credit|finalized confirmation/);
    noSensitivePosts(calls);
    return {calls,claim:'Unconfirmed inference and sandbox actions refused before prompt or job POSTs.'};
  });

  await run('wrong-injected-wallet-chain','browser injected-wallet fixture',async(page,context)=>{
    await context.addInitScript(()=>{
      const account='0x1111111111111111111111111111111111111111';
      window.ethereum={
        request:async({method})=>{
          if(method==='eth_chainId')return '0x1';
          if(method==='eth_accounts'||method==='eth_requestAccounts')return [account];
          throw new Error('Unexpected wallet request: '+method);
        },on(){},removeListener(){},
      };
    });
    await ready(page);
    await page.locator('#connect').click();
    await alertIncludes(page,/Wrong network.*Base Sepolia|Switch.*Base Sepolia/);
    assert((await page.locator('#wallet').textContent()).includes('No wallet'),'Wrong-chain wallet became active');
    return {claim:'Mainnet injected wallet refused; no transaction is requested.'};
  });

  await run('purchase-cards-and-insufficient-credit','IndexedDB purchase fixtures and mocked inference quote',async page=>{
    await backendQuote(page);
    const calls=monitor(page);
    await ready(page);
    await page.locator('#burner').click();
    await page.waitForFunction(()=>/0x[0-9a-fA-F]{40}/.test(document.querySelector('#wallet').textContent));
    const wallet=(await page.locator('#wallet').textContent()).match(/0x[0-9a-fA-F]{40}/)[0];
    const hashes=['0x'+'11'.repeat(32),'0x'+'22'.repeat(32)];
    await page.evaluate(async({wallet,hashes})=>{
      await new Promise((resolve,reject)=>{
        const open=indexedDB.open('dsmack-private-agent',1);
        open.onerror=()=>reject(open.error);
        open.onsuccess=()=>{
          const db=open.result,tx=db.transaction('wallet','readwrite');
          tx.objectStore('wallet').put([
            {status:'pending',unit:1,amount:'60',used:'0',paidWei:'60',priceWei:'1',payer:wallet,txHash:hashes[0]},
            {status:'confirmed',unit:2,amount:'99',used:'0',paidWei:'99',priceWei:'1',payer:wallet,
              txHash:hashes[1],purchaseId:'900001',allocation:{status:'active'}},
          ],'purchases');
          tx.oncomplete=()=>{db.close();resolve();};
          tx.onerror=()=>reject(tx.error);
        };
      });
    },{wallet,hashes});
    await ready(page);
    const cards=await page.locator('#purchases').textContent();
    assert.match(cards,/Pending · 60 seconds/);
    assert.match(cards,/Confirmed · 99 tokens/);
    const links=await page.locator('#purchases a').evaluateAll(nodes=>nodes.map(node=>node.href));
    assert.deepEqual(links,hashes.map(hash=>'https://sepolia.basescan.org/tx/'+hash));
    await message(page,'SC6 insufficient-credit check: this prompt must stay in the browser.');
    await alertIncludes(page,/CREDIT_EXHAUSTED|Confirmed credit cannot cover/);
    noSensitivePosts(calls);
    return {calls,claim:'Synthetic pending and confirmed purchase cards render with Basescan links. A 99-token confirmed fixture cannot cover the mocked 100-token reservation; no mint/chat/job POST occurred.'};
  });

  await run('wrong-broker-key-refused','mocked broker key and inference quote',async page=>{
    await backendQuote(page);
    await page.route('**/relay-broker/key',route=>route.fulfill({status:200,headers:responseHeaders,
      body:JSON.stringify({algorithm:'Ed25519',public_key:'00'.repeat(32)})}));
    const calls=monitor(page);
    await ready(page);
    await page.locator('#buy').click();
    await alertIncludes(page,/Wrong broker key/);
    await message(page,'SC6 wrong broker key: this prompt must remain in the browser.');
    await alertIncludes(page,/Wrong broker key/);
    noSensitivePosts(calls);
    return {calls,claim:'Pinned broker-key mismatch refuses buy/chat before sensitive POSTs.'};
  });
}finally{
  report.finishedAt=new Date().toISOString();
  report.passed=report.cases.every(result=>result.status==='passed');
  await writeFile(resolve(evidence,'browser-results.json'),JSON.stringify(report,null,2)+'\n');
  await browser.close();
}
if(!report.passed)process.exitCode=1;
