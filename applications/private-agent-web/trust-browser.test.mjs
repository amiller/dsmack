import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { JsonRpcProvider, ContractFactory, Wallet, SigningKey, keccak256 } from 'ethers';
import { randomBytes, hkdfSync, createCipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
const evidence = resolve(process.env.EVIDENCE || 'local-data/trust');
await mkdir(evidence,{recursive:true});
const portProbe = createServer();
await new Promise(r => portProbe.listen(0, '127.0.0.1', r));
const anvilPort = portProbe.address().port;
await new Promise(r => portProbe.close(r));
const anvil = spawn(process.env.ANVIL || 'anvil', ['--port',String(anvilPort),'--chain-id','84532','--silent'], {stdio:'ignore'});
const provider = new JsonRpcProvider(`http://127.0.0.1:${anvilPort}`);
function encryptReply(text, clientKey) {
  const ephemeral = Wallet.createRandom(), nonce = randomBytes(12);
  const point = Buffer.from(new SigningKey(ephemeral.privateKey).computeSharedSecret('0x04' + clientKey).slice(2), 'hex');
  const key = Buffer.from(hkdfSync('sha256', point.subarray(1,33), Buffer.alloc(0), Buffer.from('ecdsa_encryption'), 32));
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([Buffer.from(ephemeral.signingKey.publicKey.slice(2),'hex'), nonce,
    cipher.update(text,'utf8'), cipher.final(), cipher.getAuthTag()]).toString('hex');
}
const server = createServer(async (req,res) => {
  try {
    if (req.url.startsWith('/rpc/')) {
      const chunks=[]; for await(const c of req) chunks.push(c);
      const response=await fetch(`http://127.0.0.1:${anvilPort}`,{method:'POST',headers:{'content-type':'application/json'},body:Buffer.concat(chunks)});
      res.setHeader('content-type','application/json'); res.end(await response.text()); return;
    }
    const file = req.url === '/private-agent/' ? 'index.html' : req.url.replace('/private-agent/','').split('?')[0];
    const bytes=await readFile(resolve('dist',file));
    res.setHeader('content-type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/html');
    res.end(bytes);
  } catch(e) {res.writeHead(500);res.end(e.message);}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
process.env.BASE_URL=`http://127.0.0.1:${server.address().port}/private-agent/`;
const base=process.env.BASE_URL;
const { backend,ready,send,publicHeaders }=await import('./test-fixtures/browser-broker.mjs');
const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
const logs=[];
try {
  await new Promise(resolve=>setTimeout(resolve,500));
  // Anvil's public development account, used only on the local chain.
  const signer=await provider.getSigner(0);
  const artifact=JSON.parse(await readFile('../../contracts/out/PageBundleRegistry.sol/PageBundleRegistry.json'));
  const registry=await new ContractFactory(artifact.abi,artifact.bytecode.object,signer).deploy(await signer.getAddress());
  await registry.waitForDeployment();
  const ownCID=(await readFile('dist/index.html','utf8')).match(/name="page-bundle-cid" content="([^"]+)"/)[1];
  await (await registry.publish(ownCID)).wait();
  for(const width of [390,1280]) {
    const context=await browser.newContext({viewport:{width,height:900}}),page=await context.newPage();
    page.on('console',m=>logs.push(m.type()+': '+m.text()));
    page.on('pageerror',e=>logs.push('pageerror: '+e.message));
    const calls=await backend(page,'trust');
    await page.route('**/relay-broker/inference/chat', async route => {
      const body = route.request().postDataJSON(), {model} = await import('./test-fixtures/near.mjs');
      calls.push({path:'/inference/chat',body});
      assert(!JSON.stringify(body).includes('Hello from the independently verified browser'));
      const content=encryptReply('Browser verified model reply.',body.headers['x-client-pub-key']);
      await route.fulfill({headers:publicHeaders,contentType:'text/event-stream',body:
        'data: '+JSON.stringify({model,choices:[{delta:{content},finish_reason:'stop'}]})+'\n\ndata: [DONE]\n\n'});
    });
    const cfg=await (await page.request.get(new URL('config.json',base).href)).json();
    cfg.broker=cfg.broker.replace('/relay-broker-staging','/relay-broker');
    cfg.syncAnchorCodeHash=keccak256('0x6000');
    cfg.pageBundleRegistry={registry:await registry.getAddress(),rpcs:[new URL('/rpc/a',base).href,new URL('/rpc/b',base).href]};
    await page.route('**/config.json',route=>route.fulfill({headers:publicHeaders,body:JSON.stringify(cfg)}));
    await ready(page);
    const dispatched = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/inference/chat'));
    await send(page,'Hello from the independently verified browser');
    await page.waitForFunction(()=>!document.querySelector('#verified').hidden, {timeout:30000});
    await dispatched;
    await page.getByText('Browser verified model reply.', {exact:true}).waitFor();
    assert(calls.some(c=>c.path==='/inference/chat'),'verified encrypted request reaches transport');
    assert.equal(await page.locator('#page-version').isVisible(),false);
    await page.locator('#advanced').evaluate(e=>e.open=true);
    const saved=await page.evaluate(()=>document.querySelector('#attestations pre').textContent);
    const checked=JSON.parse(saved);
    assert.equal(checked.browser.fullQuoteVerifiedBy,'browser');
    assert.equal(checked.models[0].gpuEvidence,'verified');
    await writeFile(resolve(evidence,`verified-${width}.json`),JSON.stringify(checked,null,2));
    await page.screenshot({path:resolve(evidence,`verified-${width}.png`),fullPage:true});
    const changed='bafkrei'+'a'.repeat(52);
    await (await registry.publish(changed)).wait();
    await page.clock.fastForward(60000);
    await page.waitForFunction(()=>document.querySelector('#page-version').textContent.startsWith('This page version changed'));
    assert((await page.locator('#page-version').innerText()).includes(ownCID));
    assert((await page.locator('#page-version').innerText()).includes(changed));
    assert.equal(await page.locator('#new-chat').isEnabled(),true);
    await page.screenshot({path:resolve(evidence,`version-changed-${width}.png`),fullPage:true});
    await (await registry.publish(ownCID)).wait();
    await context.close();
  }
  for (const kind of ['nonce','key','model']) {
    const context=await browser.newContext({viewport:{width:390,height:900}}),page=await context.newPage();
    const calls=await backend(page,kind);
    await ready(page);
    await send(page,'Refuse an unverified encryption key before transport');
    const pattern=kind==='nonce'?'nonce':kind==='key'?'differs from the attested':'names another model';
    await page.waitForFunction(pattern=>[...document.querySelectorAll('#alert, .send-status')].some(e => new RegExp(pattern,'i').test(e.title)),pattern);
    assert(!calls.some(c=>c.path==='/inference/chat'));
    assert.equal(await page.locator('#verified').isVisible(),false);
    await page.screenshot({path:resolve(evidence,`refused-${kind}.png`),fullPage:true});
    await context.close();
  }
  await writeFile(resolve(evidence,'result.json'),JSON.stringify({verified:true,widths:[390,1280],refused:['nonce','key','model'],registry:await registry.getAddress(),ownCID},null,2));
} finally {
  await writeFile(resolve(evidence,'console.log'),logs.join('\n'));
  await browser.close(); await new Promise(resolve=>server.close(resolve)); provider.destroy();anvil.kill('SIGTERM');
}
