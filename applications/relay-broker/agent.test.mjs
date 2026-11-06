import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "npm:ethers@6.17.0";
import { Receipt, receiptDomain } from "../payments/schema.mjs";
import { Payments } from "./payments.mjs";
import { Inference, creditGrantPrefix } from "./inference.mjs";
import { AgentSessions } from "./agent.mjs";
import { canonical, signingKey } from "./grants.mjs";
const hex = (v) => [...new Uint8Array(v)].map(v => v.toString(16).padStart(2,"0")).join("");
const peer = "12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
async function fixture({ starter = "250000000", lifetime = 1800, initialized = true, inferenceCfg = {}, agentCfg = {}, hostBrowse } = {}) {
 let now=2000000000;
 const wallet=Wallet.createRandom(), other=Wallet.createRandom();
 const key=await signingKey("12".repeat(32));
 const receiptKey=Wallet.createRandom();
 const escrow="0x1000000000000000000000000000000000000001";
 const payments=new Payments({cfg:{escrow},key:Wallet.createRandom(),chain:{snapshot:async()=>({call:async()=>0n})},state:{},save:async()=>{},now:()=>now});
 const inference=new Inference({payments,cfg:{model:"fixture/model",starterCreditNanoUsd:starter,...inferenceCfg},provider:{apiKey:"fixture"},now:()=>now});
 const node={kind:"compute",relay_peer:peer,admit_until:now+lifetime,
  payments:{receiptSigner:receiptKey.address,operator:other.address},
  attestation:{nodeBinding:{binding:{receiptSigner:receiptKey.address}}}};
 const broker={payments,inference,key,cfg:{agent:agentCfg},live:()=>[node],now:()=>now};
 let fleetSlots;
 const readFleet=async()=>[{publisher:"mac-one",online:true,received_at:now,updated_at:now,config:{max_guests:1,...(hostBrowse?{browse:hostBrowse}:{})},
  slots:fleetSlots??broker.live().map((n,slot_id)=>({slot_id,state:"ready",relay_peer:n.relay_peer}))}];
 const sessions=new AgentSessions(broker,readFleet);
 async function signed(action,extra={},who=wallet) {
  const body={action,wallet:who.address,nonce:crypto.randomUUID().replaceAll("-",""),issuedAt:now,...extra};
  return {...body,sig:await who.signMessage(canonical(body))};
 }
 if(initialized)await inference.credit(await signed("credit"));
 async function open(who=wallet,browse) {return sessions.open(await signed("agent-open",{conversationId:"conversation",client_peer:peer,node_peer:peer,...(browse?{browse}:{})},who));}
 const sequences=new Map();
 async function receipt(sessionId,guestSeconds,final=false,wrongKey=false) {
  const sequence=(sequences.get(sessionId)??0)+1;sequences.set(sessionId,sequence);
  const body={purchaseId:BigInt("0x"+sessionId).toString(),sequence,unit:1,used:String(guestSeconds),
   endedAt:Math.min(now,payments.state.agentSessions[sessionId].grant.expires_at),finalReceipt:final};
  return {receipt:body,signature:await (wrongKey?Wallet.createRandom():receiptKey).signTypedData(receiptDomain(escrow),{Receipt},body)};
 }
 return {sessions,inference,payments,signed,open,receipt,other,wallet,broker,node,readFleet,
  setSlots:value=>{fleetSlots=value;},advance:(s)=>now+=s};
}

test("guest seconds reserve and settle the same credit; untrusted reports cannot charge it",async()=>{
 const f=await fixture(),session=await f.open();
 assert.equal(session.credit.reservedNanoUsd,"900000");
 assert.equal(session.credit.remainingNanoUsd,"249100000");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,5,false,true)),e=>e.code==="GUEST_SIGNATURE");
 await f.sessions.receipt(await f.receipt(session.sessionId,5));
 let status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.guestSeconds,5);
 assert.equal(status.credit.spentNanoUsd,"900000");
 assert.equal(status.credit.reservedNanoUsd,"75000");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,4)),e=>e.code==="GUEST_USAGE");
 await assert.rejects(f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId},f.other),true),e=>e.code==="CREDIT_NOT_CONFIRMED");
 await f.inference.credit(await f.signed("credit",{},f.other));
 await assert.rejects(f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId},f.other),true),e=>e.code==="SESSION_OWNER");
 const ended=await f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId}),true);
 assert.equal(ended.endRequested,true);
 assert.equal((await f.sessions.receipt(await f.receipt(session.sessionId,7))).stop,true);
 const final=await f.receipt(session.sessionId,8,true);
 await f.sessions.receipt(final); await f.sessions.receipt(final);
 status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.active,false);
 assert.equal(status.credit.spentNanoUsd,"900000");
 assert.equal(status.credit.reservedNanoUsd,"0");
});

test("concurrent claims hold one guest and expired unused grants release without invented usage",async()=>{
 const f=await fixture();
 const spare={...f.node,relay_peer:peer+"-spare"};
 f.broker.live=()=>[f.node,spare];
 const requests=await Promise.all([f.node,spare].map(node=>f.signed("agent-open",{
  conversationId:node.relay_peer,client_peer:peer,node_peer:node.relay_peer})));
 const results=await Promise.allSettled(requests.map(request=>f.sessions.open(request)));
 assert.equal(results.filter(r=>r.status==="fulfilled").length,1);
 const first=results.find(r=>r.status==="fulfilled").value;
 const refusal=results.find(r=>r.status==="rejected").reason;
 assert.equal(refusal.code,"SESSION_ACTIVE");
 assert(refusal.message.includes(first.sessionId));
 f.advance(1801);
 const status=await f.sessions.status(await f.signed("agent-status",{sessionId:first.sessionId}));
 assert.equal(status.active,false);
 assert.equal(status.credit.reservedNanoUsd,"0");
 assert.equal(status.credit.spentNanoUsd,"0");
});

test("a session on a guest that is no longer live does not hold the wallet slot",async()=>{
 const f=await fixture();
 const gone={...f.node,relay_peer:peer+"-gone"};
 f.broker.live=()=>[gone,f.node];
 f.setSlots([{slot_id:1,state:"ready",relay_peer:gone.relay_peer},{slot_id:0,state:"ready",relay_peer:f.node.relay_peer}]);
 await f.sessions.open(await f.signed("agent-open",{conversationId:"old",client_peer:peer,node_peer:gone.relay_peer}));
 f.broker.live=()=>[f.node];
 const next=await f.sessions.open(await f.signed("agent-open",{conversationId:"new",client_peer:peer,node_peer:f.node.relay_peer}));
 assert(next.sessionId);
});

test("ending a session frees the wallet slot before its guest finishes",async()=>{
 const f=await fixture();
 const other={...f.node,relay_peer:peer+"-other"};
 f.broker.live=()=>[other,f.node];
 f.setSlots([{slot_id:1,state:"ready",relay_peer:other.relay_peer},{slot_id:0,state:"ready",relay_peer:f.node.relay_peer}]);
 const first=await f.sessions.open(await f.signed("agent-open",{conversationId:"old",client_peer:peer,node_peer:other.relay_peer}));
 await f.sessions.receipt(await f.receipt(first.sessionId,1));
 await f.sessions.status(await f.signed("agent-end",{sessionId:first.sessionId}),true);
 const next=await f.sessions.open(await f.signed("agent-open",{conversationId:"new",client_peer:peer,node_peer:f.node.relay_peer}));
 assert(next.sessionId);
});

test("configured wallet slot limit persists across session handlers and ending a stay frees one slot",async()=>{
 const f=await fixture({agentCfg:{maxActiveSessionsPerWallet:2}});
 const nodes=Array.from({length:3},(_,i)=>({...f.node,relay_peer:peer+"-slot-"+i}));
 f.broker.live=()=>nodes;
 const claim=async index=>f.signed("agent-open",{conversationId:"conversation-"+index,
  client_peer:peer,node_peer:nodes[index].relay_peer});
 const first=await f.sessions.open(await claim(0));
 const second=await f.sessions.open(await claim(1));
 const reloaded=new AgentSessions(f.broker,f.readFleet);
 await assert.rejects(reloaded.open(await claim(2)),error=>{
  assert.equal(error.code,"SESSION_ACTIVE");
  assert(error.message.includes(first.sessionId));assert(error.message.includes(second.sessionId));
  return true;
 });
 await f.sessions.status(await f.signed("agent-end",{sessionId:first.sessionId}),true);
 const replacement=await reloaded.open(await claim(2));
 assert.equal(replacement.active,true);
 assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).reservedNanoUsd,"1800000");
});

test("HTTP broker enforces daily starter credit and wallet slots across ledger reload",async()=>{
 const {handleRequest}=await import("./server.ts");
 const f=await fixture({initialized:false,inferenceCfg:{dailyStarterBudgetNanoUsd:"500000000"}});
 const dir=await Deno.makeTempDir(),path=dir+"/payments.json";
 f.payments.save=next=>Deno.writeTextFile(path,JSON.stringify(next));
 const spare={...f.node,relay_peer:peer+"-spare"};
 f.broker.live=()=>[f.node,spare];
 const [mac]=await f.readFleet();
 await Deno.writeTextFile(dir+"/fleet.json",JSON.stringify({heartbeats:{[mac.publisher]:mac},
  links:{[mac.publisher]:{link:{operator:f.wallet.address,kid:"fixture"}}}}));
 const server=Deno.serve({hostname:"127.0.0.1",port:0,onListen(){}},
  request=>handleRequest(request,f.broker,{dataDir:dir,env:{}}));
 const post=async(path,body)=>{
  const response=await fetch(`http://127.0.0.1:${server.addr.port}${path}`,{
   method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  return {status:response.status,body:await response.json()};
 };
 const credit=async who=>post("/inference/credit",await f.signed("credit",{},who));
 const open=async(who,node,conversationId)=>post("/agent/open",await f.signed("agent-open",{
  conversationId,client_peer:peer,node_peer:node.relay_peer},who));
 try {
  assert.equal((await credit(f.wallet)).body.grantedNanoUsd,"250000000");
  assert.equal((await credit(f.other)).body.grantedNanoUsd,"250000000");
  const first=await open(f.wallet,f.node,"first");assert.equal(first.status,200);
  const persisted=JSON.parse(await Deno.readTextFile(path));
  const payments=new Payments({cfg:{},key:{},chain:{},state:persisted,save:f.payments.save,now:f.broker.now});
  f.broker.payments=payments;
  f.broker.inference=new Inference({payments,cfg:f.inference.cfg,provider:{apiKey:"fixture"},now:f.broker.now});
  const exhausted=await credit(Wallet.createRandom());
  assert.equal(exhausted.status,402);assert.equal(exhausted.body.error.code,"STARTER_BUDGET_EXHAUSTED");
  assert.match(exhausted.body.error.message,/free credit for today is used up/);
  assert.equal((await credit(f.wallet)).status,200);
  const blocked=await open(f.wallet,spare,"second");
  assert.equal(blocked.status,409);assert.equal(blocked.body.error.code,"SESSION_ACTIVE");
  assert(blocked.body.error.message.includes(first.body.sessionId));
  assert.equal((await open(f.other,spare,"other-wallet")).status,200);
  const ended=await post("/agent/end",await f.signed("agent-end",{sessionId:first.body.sessionId}));
  assert.equal(ended.status,200);assert.equal(ended.body.active,false);
  assert.equal((await open(f.wallet,f.node,"resumed")).status,200);
  f.advance(86400-2000000000%86400);
  assert.equal((await credit(Wallet.createRandom())).status,200);
  assert.equal(JSON.parse(await Deno.readTextFile(path)).inferenceStarterGrants.grantedNanoUsd,"250000000");
 } finally {await server.shutdown();await Deno.remove(dir,{recursive:true});}
});

test("ending before transport admission releases credit and revokes the unused grant",async()=>{
 const f=await fixture(),session=await f.open();
 const ended=await f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId}),true);
 assert.equal(ended.active,false);
 assert.equal(ended.credit.reservedNanoUsd,"0");
 assert.equal(ended.credit.spentNanoUsd,"0");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,0)),e=>e.code==="SESSION_CLOSED");
 assert.notEqual((await f.open()).sessionId,session.sessionId);
});

test("expired started session releases ownership and preserves unresolved credit until signed final recovery",async()=>{
 const f=await fixture(),session=await f.open();
 await f.sessions.receipt(await f.receipt(session.sessionId,5));
 f.advance(1801);
 let status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.usageUnresolved,true);
 assert.equal(status.credit.reservedNanoUsd,"75000");
 await f.sessions.receipt(await f.receipt(session.sessionId,6,true));
 status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.usageUnresolved,false);
 assert.equal(status.credit.reservedNanoUsd,"0");
 assert.equal(status.credit.spentNanoUsd,"900000");
});

test("four payout guests advertise distinct availability and a fifth claim is busy",async()=>{
 const f=await fixture();
 const nodes=Array.from({length:4},(_,i)=>({...f.node,relay_peer:peer+"-slot-"+i,telemetry:{busy:false}}));
 f.broker.live=()=>nodes;
 const wallets=[f.wallet,Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom(),f.other];
 for(const wallet of wallets.slice(1))await f.inference.credit(await f.signed("credit",{},wallet));
 const held=[];
 for(const [i,wallet] of wallets.slice(0,4).entries()){
  const node=nodes.find(n=>f.sessions.available(n));
  assert(node,"slot "+i+" should be available");
  const session=await f.sessions.open(await f.signed("agent-open",{conversationId:"conversation-"+i,client_peer:peer,node_peer:node.relay_peer},wallet));
  held.push(session.node.relay_peer);
  assert.equal(f.sessions.available(node),false);
 }
 assert.equal(new Set(held).size,4);
 assert.equal(nodes.filter(n=>f.sessions.available(n)).length,0);
 await assert.rejects(f.sessions.open(await f.signed("agent-open",{conversationId:"fifth",client_peer:peer,node_peer:nodes[0].relay_peer},wallets[4])),e=>e.code==="GUEST_BUSY");
 f.advance(1801);
 assert.equal(f.sessions.available(nodes[0]),true);
 nodes[0].telemetry.busy=true;
 assert.equal(f.sessions.available(nodes[0]),false,"guest status remains authoritative after a lease expires");
});


test("a held predecessor keeps its logical slot when a ready replacement appears",async()=>{
 const f=await fixture(),first=await f.open();
 assert.deepEqual(f.payments.state.agentSessions[first.sessionId].placement,{publisher:"mac-one",slot_id:0});
 const replacement={...f.node,relay_peer:peer+"-replacement",admit_until:f.node.admit_until+100};
 f.broker.live=()=>[f.node,replacement];
 f.setSlots([{slot_id:0,state:"ready",relay_peer:f.node.relay_peer},
  {slot_id:0,state:"ready",relay_peer:replacement.relay_peer}]);
 await f.inference.credit(await f.signed("credit",{},f.other));
 async function replacementClaim(){return await f.signed("agent-open",{conversationId:"replacement",client_peer:peer,
  node_peer:replacement.relay_peer},f.other);}
 await assert.rejects(f.sessions.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 // The persisted slot also blocks a replacement after the old guest is absent
 // from the new heartbeat and live node index.
 f.broker.live=()=>[replacement];
 f.setSlots([{slot_id:0,state:"ready",relay_peer:replacement.relay_peer}]);
 await assert.rejects(f.sessions.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 const reloaded=new AgentSessions(f.broker,f.readFleet);
 await assert.rejects(reloaded.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 await f.sessions.status(await f.signed("agent-end",{sessionId:first.sessionId}),true);
 const resumed=await reloaded.open(await replacementClaim());
 assert.deepEqual(resumed.placement,{publisher:"mac-one",slot_id:0});
});

test("four different logical slots admit concurrently and a fifth direct claim cannot take a spare",async()=>{
 const f=await fixture();
 const nodes=Array.from({length:4},(_,i)=>({...f.node,relay_peer:peer+"-logical-"+i}));
 f.broker.live=()=>nodes;
 const wallets=[f.wallet,Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom(),f.other];
 for(const wallet of wallets.slice(1))await f.inference.credit(await f.signed("credit",{},wallet));
 const requests=await Promise.all(wallets.slice(0,4).map((wallet,i)=>f.signed("agent-open",{
  conversationId:"logical-"+i,client_peer:peer,node_peer:nodes[i].relay_peer},wallet)));
 const held=await Promise.all(requests.map(request=>f.sessions.open(request)));
 assert.equal(new Set(held.map(session=>session.placement.slot_id)).size,4);
 const spare={...f.node,relay_peer:peer+"-spare",admit_until:f.node.admit_until+100};
 f.broker.live=()=>nodes.concat(spare);
 f.setSlots(nodes.map((node,slot_id)=>({slot_id,state:"ready",relay_peer:node.relay_peer}))
  .concat({slot_id:0,state:"ready",relay_peer:spare.relay_peer}));
 await assert.rejects(f.sessions.open(await f.signed("agent-open",{conversationId:"fifth-spare",client_peer:peer,
  node_peer:spare.relay_peer},wallets[4])),e=>e.code==="GUEST_BUSY");
 assert.equal(Object.values(f.payments.state.agentSessions).filter(session=>!session.final).length,4);
});


test("unused setup grants release after 90 seconds while wall expiry leaves room for an admitted call",async()=>{
 const f=await fixture({lifetime:3300});f.node.payments={...f.node.payments,runExpires:f.broker.now()+3600};
 const session=await f.open();
 assert.equal(session.handoverAt,f.node.admit_until);
 assert.equal(session.grant.expires_at,f.broker.now()+3480);
 assert.equal(session.setupUntil,f.broker.now()+90);
 f.advance(91);
 assert.equal(f.sessions.available(f.node),true);
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,0)),e=>e.code==="SESSION_CLOSED");
 const status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.active,false);assert.equal(status.closedReason,"unused-grant-expired");
 assert.equal(status.credit.spentNanoUsd,"0");assert.equal(status.credit.reservedNanoUsd,"0");
});


test("a fresh browser cannot resume an expired conversation until its admitted guest saves and sends final",async()=>{
 const {handleRequest}=await import("./server.ts");
 const f=await fixture(),first=await f.open();
 await f.sessions.receipt(await f.receipt(first.sessionId,5));
 f.advance(1801);
 const replacement={...f.node,relay_peer:peer+"-handover",admit_until:f.broker.now()+1800};
 f.broker.live=()=>[replacement];
 const dir=await Deno.makeTempDir();
 const post=async conversationId=>handleRequest(new Request("https://broker.example/agent/open",{method:"POST",
  headers:{"content-type":"application/json"},body:JSON.stringify(await f.signed("agent-open",{
   conversationId,client_peer:peer,node_peer:replacement.relay_peer}))}),f.broker,{dataDir:dir,env:{}});
 try {
  const [mac]=await f.readFleet();
  await Deno.writeTextFile(dir+"/fleet.json",JSON.stringify({heartbeats:{[mac.publisher]:mac},
   links:{[mac.publisher]:{link:{operator:f.wallet.address,kid:"fixture"}}}}));
  const blocked=await post("conversation"),error=(await blocked.json()).error;
  assert.equal(blocked.status,409);assert.equal(error.code,"SESSION_SAVING");
  assert.equal(error.retryAfterSeconds,5);assert.equal(blocked.headers.get("retry-after"),"5");
  assert.equal(Object.keys(f.payments.state.agentSessions).length,1,"waiting cannot reserve a successor grant");
  // A lost receipt from another conversation must not prevent all future work.
  const other=await post("different-conversation");assert.equal(other.status,200);
  const otherStay=await other.json();
  await f.sessions.status(await f.signed("agent-end",{sessionId:otherStay.sessionId}),true);
  await f.sessions.receipt(await f.receipt(first.sessionId,6,true,false,"drain"));
  const resumed=await post("conversation");assert.equal(resumed.status,200);
  const next=await resumed.json();assert.notEqual(next.sessionId,first.sessionId);
  assert.equal(next.conversationId,"conversation");
  assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).spentNanoUsd,"900000");
 } finally {await Deno.remove(dir,{recursive:true});}
});


test("S1 bills a 60 second minimum once and only active seconds beyond it",async()=>{
 const f=await fixture({starter:"1500000"}),session=await f.open(),wallet=f.wallet.address.toLowerCase();
 assert.equal(session.rateNanoUsdPerSecond,"15000");assert.equal(session.activeBudgetSeconds,60);
 await f.sessions.receipt(await f.receipt(session.sessionId,0));
 assert.equal(f.inference.summary(wallet).spentNanoUsd,"900000");
 for(const used of [20,40,60,80,100]) {
  f.advance(20);
  await f.sessions.receipt(await f.receipt(session.sessionId,used));
 }
 const final=await f.receipt(session.sessionId,100,true);
 await f.sessions.receipt(final);await f.sessions.receipt(final);
 assert.equal(f.inference.summary(wallet).spentNanoUsd,"1500000");
 assert.equal(f.inference.summary(wallet).reservedNanoUsd,"0");
 await assert.rejects(f.open(),e=>e.code==="CREDIT_EXHAUSTED");
});

test("less than the minimum cannot start and pending inference credit stays reserved",async()=>{
 const poor=await fixture({starter:"899999"});
 await assert.rejects(poor.open(),e=>e.code==="CREDIT_EXHAUSTED");
 const f=await fixture({starter:"1500000"}),session=await f.open(),wallet=f.wallet.address.toLowerCase();
 f.payments.state.inferenceCredit[wallet].pending="model";
 f.payments.state.inferenceRequests={model:{status:"sent",reservedNanoUsd:"600000"}};
 const started=await f.sessions.receipt(await f.receipt(session.sessionId,0));
 assert.equal(started.activeBudgetSeconds,60);
 await f.sessions.receipt(await f.receipt(session.sessionId,60,true));
 assert.equal(f.inference.summary(wallet).spentNanoUsd,"900000");
 assert.equal(f.inference.summary(wallet).reservedNanoUsd,"600000");
});


test("directory distinguishes all slots busy from no online Macs, even without live guest registrations", async () => {
 const {handleRequest}=await import("./server.ts");
 const f=await fixture(),dir=await Deno.makeTempDir();
 const get=()=>handleRequest(new Request("https://broker.example/nodes"),f.broker,{dataDir:dir,env:{}});
 try {
  f.broker.live=()=>[];
  const empty=await get();
  assert.equal(empty.status,503); assert.equal((await empty.json()).error.code,"FLEET_EMPTY");
  const mac={publisher:"mac-one",received_at:f.broker.now(),updated_at:f.broker.now(),slots:[{slot_id:0,state:"busy"}]};
  await Deno.writeTextFile(dir+"/fleet.json",JSON.stringify({heartbeats:{[mac.publisher]:mac},
   links:{[mac.publisher]:{link:{operator:f.wallet.address,kid:"fixture"}}}}));
  const busy=await get(),error=(await busy.json()).error;
  assert.equal(busy.status,503); assert.equal(error.code,"FLEET_BUSY");
  assert.equal(error.retryAfterSeconds,15); assert.equal(busy.headers.get("retry-after"),"15");
  f.advance(60);
  assert.equal((await (await get()).json()).error.code,"FLEET_EMPTY");
 } finally { await Deno.remove(dir,{recursive:true}); }
});

test("browse terms: the stay names its sites within the host's signed policy, priced by the host's surcharge, looked up by token",async()=>{
 const plain=await fixture(),none=await plain.open();
 assert.deepEqual({...none.browse,token:undefined},{mode:"none",hosts:[],nanoUsdPerSecond:"0",token:undefined});
 assert.match(none.browse.token,/^[0-9a-f]{32}$/);
 assert.equal(none.rateNanoUsdPerSecond,"15000");
 assert.deepEqual(plain.sessions.browsePolicy(none.browse.token,"mac-one"),{mode:"none",hosts:[],expires_at:none.grant.expires_at});
 const hostBrowse={default:"named",max:"open",price:{open_nano_usd_per_second:"5000",named_host_nano_usd_per_second:"100"}};
 const named=await (await fixture({hostBrowse})).open(undefined,{mode:"named",hosts:["shop.example","maps.example"]});
 assert.deepEqual([named.browse.mode,named.browse.hosts,named.rateNanoUsdPerSecond],["named",["shop.example","maps.example"],"15200"]);
 const wide=await fixture({hostBrowse}),open=await wide.open(undefined,{mode:"open",hosts:[]});
 assert.equal(open.rateNanoUsdPerSecond,"20000");
 assert.deepEqual(wide.sessions.browsePolicy(open.browse.token,"mac-one").mode,"open");
 await wide.sessions.status(await wide.signed("agent-end",{sessionId:open.sessionId}),true);
 assert.throws(()=>wide.sessions.browsePolicy(open.browse.token,"mac-one"),/no active stay on this Mac/);
 assert.throws(()=>wide.sessions.browsePolicy("nothex","mac-one"),/browse token and publisher required/);
 const capped=await fixture({hostBrowse:{default:"none",max:"named"}});
 await assert.rejects(capped.open(undefined,{mode:"open",hosts:[]}),/browse up to named/);
 await assert.rejects(capped.open(undefined,{mode:"named",hosts:["Not A Host"]}),/browse must be/);
 await assert.rejects(capped.open(undefined,{mode:"none",hosts:["shop.example"]}),/hosts only for named/);
});

test("a browse token works only on the stay's own Mac and stops when the stay ends, even with grant time left",async()=>{
 const f=await fixture({hostBrowse:{default:"none",max:"open"}}),s=await f.open(undefined,{mode:"open",hosts:[]});
 const mac=s.placement.publisher;
 assert.equal(f.sessions.browsePolicy(s.browse.token,mac).mode,"open");
 assert.throws(()=>f.sessions.browsePolicy(s.browse.token,"0x"+"b2".repeat(20)),/no active stay on this Mac/);
 f.advance(60);
 await f.sessions.receipt(await f.receipt(s.sessionId,60,true));
 assert.ok(s.grant.expires_at>f.broker.now());
 assert.throws(()=>f.sessions.browsePolicy(s.browse.token,mac),/no active stay on this Mac/);
});
