// Run against a local anvil on port 18545 after npm run build.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright";
import { ContractFactory, JsonRpcProvider, Wallet, keccak256 } from "ethers";
const provider=new JsonRpcProvider("http://127.0.0.1:18545",84532,{cacheTimeout:-1});
const owner=await provider.getSigner(0);
const deploy=async(path,args=[])=>{
 const a=JSON.parse(await readFile(path));
 const c=await new ContractFactory(a.abi,a.bytecode.object,owner).deploy(...args);
 await c.waitForDeployment();return c;
};
const token=await deploy("../../contracts/out/UsageEscrow.t.sol/MockUSDC.json");
const rail=await deploy("../../contracts/out/UsageEscrow.sol/UsageEscrow.json",[await token.getAddress(),await owner.getAddress()]);
const cfg=JSON.parse(await readFile("dist/config.json"));
delete cfg.pageBundleRegistry;
cfg.escrow=await rail.getAddress();cfg.codeHash=keccak256(await provider.getCode(cfg.escrow));
const claimKey=Wallet.createRandom();
await (await rail.registerBroker(claimKey.address)).wait();
const fleetCfg={...cfg,rpc:"https://base-sepolia-rpc.publicnode.com",broker:"https://pod.dstack.soc1024.com/relay-broker",deploymentBlock:0,classesByPublisher:{}};
const errors=[];
const server=createServer(async(req,res)=>{
 try {
  const path=new URL(req.url,"http://local").pathname;
  if(path==="/rpc") {
   const chunks=[];for await(const chunk of req)chunks.push(chunk);
   const response=await fetch("http://127.0.0.1:18545",{method:"POST",headers:{"content-type":"application/json"},body:Buffer.concat(chunks)});
   res.setHeader("content-type","application/json");res.end(await response.text());return;
  }
  if(path==="/operator-fleet/config.json") {res.setHeader("content-type","application/json");res.end(JSON.stringify(fleetCfg));return;}
  if(path==="/private-agent/config.json") {res.setHeader("content-type","application/json");res.end(JSON.stringify(cfg));return;}
  if(path.startsWith("/relay-broker/")) {
   let body={};if(req.method==="POST") {const chunks=[];for await(const chunk of req)chunks.push(chunk);body=JSON.parse(Buffer.concat(chunks).toString());}
   let value;
   if(path.endsWith("/payments/key"))value={chainId:84532,escrow:cfg.escrow,codeHash:cfg.codeHash,address:cfg.grantSigner};
   else if(path.endsWith("/key"))value={public_key:cfg.brokerKey};
   else if(path.endsWith("/inference/quote"))value={mode:"broker-e2ee",provider:"near",model:"fixture",configured:true,maxOutputTokens:512};
   else if(path.endsWith("/inference/credit")) {
    const deposited=await rail.deposits(body.wallet);
    value={wallet:body.wallet,grantedNanoUsd:String(deposited*1000n),spentNanoUsd:"0",reservedNanoUsd:"0",remainingNanoUsd:String(deposited*1000n),usedTokens:"0"};
   } else if(path.endsWith("/nodes")||path.endsWith("/fleet"))value=[];
   else value={};
   res.setHeader("content-type","application/json");res.end(JSON.stringify(value));return;
  }
  const root=path.startsWith("/operator-fleet/")?"../operator-fleet/dist":"dist";
  const name=path.replace(/^\/(private-agent|operator-fleet)\/?/,"")||"index.html";
  const file=resolve(root,name);assert(file.startsWith(resolve(root)+"/"));
  res.setHeader("content-type",name.endsWith(".js")?"text/javascript":name.endsWith(".css")?"text/css":name.endsWith(".json")?"application/json":"text/html");
  res.end(await readFile(file));
 } catch(error) {errors.push(error.message);res.statusCode=500;res.end("local fixture error");}
});
await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
cfg.broker="https://pod.dstack.soc1024.com/relay-broker";cfg.rpc="https://sepolia.base.org";
const evidence=resolve(process.env.EVIDENCE);await mkdir(evidence,{recursive:true});
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
let page;
try {
 page=await browser.newPage();
 page.setDefaultTimeout(15000);
 page.on("pageerror",error=>console.error("page error:",error.message));
 page.on("console",message=>{if(message.type()==="error")console.error("console:",message.text())});
 await page.route("**/*",async route=>{
  const request=route.request(),url=request.url();
  if(new URL(url).origin===origin)return route.continue();
  const local=[cfg.rpc,fleetCfg.rpc].includes(url.replace(/\/$/, ""))?"/rpc":url.startsWith(cfg.broker)?new URL(url).pathname:undefined;
  if(!local)return route.abort();
  const headers={"access-control-allow-origin":origin,"access-control-allow-methods":"GET, POST, OPTIONS","access-control-allow-headers":"content-type"};
  if(request.method()==="OPTIONS")return route.fulfill({status:204,headers});
  const response=await fetch(origin+local,{method:request.method(),headers:{"content-type":"application/json"},body:request.postData()??undefined});
  return route.fulfill({status:response.status,headers:{...headers,"content-type":"application/json"},body:await response.text()});
 });
 await page.goto(origin+"/private-agent/");
 await page.waitForFunction(()=>document.documentElement.dataset.servicesReady === "true");
 await page.evaluate(() => document.querySelector("#chat").onBeforeSend()).catch(error => {
  if (!/CREDIT_EXHAUSTED/.test(error.message)) throw error;
 });
 await page.waitForFunction(()=>/^0x[0-9a-fA-F]{40}$/.test(document.querySelector("#wallet").textContent));
 const wallet=await page.locator("#wallet").textContent();
 await (await owner.sendTransaction({to:wallet,value:10n**18n})).wait();
 await (await token.mint(wallet,1000000)).wait();
 await page.locator("#advanced > summary").click();
 await page.getByText("Add credit",{exact:true}).click();
 await page.locator("#deposit-amount").fill("1");
 await page.locator("#deposit").click();
 await page.waitForFunction(()=>document.querySelector("#prepaid-status").textContent.startsWith("USDC deposited."));
 assert.equal(await rail.deposits(wallet),1000000n);
 await page.waitForFunction(()=>document.querySelector("#chat-credit").dataset.remainingNanoUsd==="1000000000");
 await page.screenshot({path:evidence+"/prepaid-deposit.png",fullPage:true});
 await page.locator("#refund").click();
 await page.waitForFunction(()=>document.querySelector("#prepaid-status").textContent.startsWith("Account closing."));
 assert((await rail.exitRequestedAt(wallet))>0n);
 await provider.send("evm_increaseTime",[14*86400]);await provider.send("evm_mine",[]);
 await page.locator("#refund").click();
 await page.waitForFunction(()=>document.querySelector("#prepaid-status").textContent.startsWith("Remaining USDC withdrawn."));
 assert.equal(await token.balanceOf(wallet),1000000n);
 await page.screenshot({path:evidence+"/prepaid-withdraw.png",fullPage:true});
 // The operator page reads cumulative Claimed events as incremental USDC payouts.
 const ownerAddress=await owner.getAddress();
 await (await token.mint(ownerAddress,10000)).wait();
 await (await token.approve(cfg.escrow,10000)).wait();
 await (await rail.deposit(10000)).wait();
 const period=Math.floor(Number((await provider.getBlock("latest")).timestamp)/604800)-1;
 const claim={operator:ownerAddress,cumulativeOwed:"10000",period};
 const domain={name:"DsmackPrepaid",version:"1",chainId:84532,verifyingContract:cfg.escrow,salt:"0x"+ownerAddress.slice(2).toLowerCase().padStart(64,"0")};
 const types={Claim:[{name:"operator",type:"address"},{name:"cumulativeOwed",type:"uint256"},{name:"period",type:"uint64"}]};
 await (await rail.claim(ownerAddress,claim,await claimKey.signTypedData(domain,types,claim))).wait();
 await provider.send("anvil_mine",["0x100"]);
 await page.clock.install({time:new Date(Number((await provider.getBlock("latest")).timestamp)*1000)});
 await page.goto(origin+"/operator-fleet/?operator="+ownerAddress);
 await page.waitForFunction(()=>document.documentElement.dataset.loaded==="true");
 assert.equal(await page.locator("#earned-all").textContent(),"0.01");
 assert.equal(await page.locator("#error").isVisible(),false);
 await page.screenshot({path:evidence+"/operator-usdc.png",fullPage:true});
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({wallet,depositUsdcUnits:"1000000",refundedUsdcUnits:"1000000",flow:"create wallet -> deposit and refresh automatically -> request exit -> withdraw"}));
} catch(error) {
 console.error(await page.locator("body").innerText());
 await page.screenshot({path:evidence+"/prepaid-failure.png",fullPage:true});
 throw error;
} finally {await browser.close();await new Promise(resolve=>server.close(resolve));provider.destroy();}
