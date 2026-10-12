import {decodeAbiParameters,decodeFunctionData,encodeAbiParameters,keccak256,parseTransaction,recoverTransactionAddress,type Address,type Hex,type TransactionSerialized} from 'npm:viem@2.38.0';
export type SponsorRequest={id:Hex,to:Address,data:Hex,nonce:number,gas:bigint,gasPrice:bigint};
export interface SponsorPolicy {reserve(request:SponsorRequest):Promise<void>;reconcile(raw:Hex):Promise<void>;allowMail?(to:string,body:unknown,stage?:'enqueue'|'deliver'):Promise<void>;status?():Promise<Record<string,unknown>>;}
export type QualificationBudget={version:1,approved:boolean,reference:string,validUntil:string,owner:Address,registry:Address,adapter:Address,category:Hex,seedKeyId:Hex,peerKeyId:Hex,seedMember:Hex,peerMember:Hex,seedName:string,peerName:string,priceCap:string,totalCap:string};
export type Reservation={id:Hex,to:Address,dataHash:Hex,nonce:number,gas:string,gasPrice:string,fee:string,kind:string,member:Hex,account?:Address,keyId?:Hex,sessionKeyHash?:Hex,joinTx?:Hex,mailbox?:string,envelopeDigest?:Hex};
export type Ledger={scope:Hex,reservations:Reservation[],bindings?:Record<string,string>};
export type BudgetDependencies={now?:()=>number,feeEnvelope:(gas:bigint,bytes:number)=>Promise<bigint>,preSignCheck:(requiredFee?:bigint)=>Promise<void>,verifyHello?:(body:unknown)=>Promise<{joinTx:Hex,sessionKeyHash:Hex,member:Hex}>};
const OWNER='0xe45C80da8A992447E9Da6d2d82Fe4b6Fa2d48C61',REGISTRY='0xd4B33C83576a6049d29c6B849ec73491e52781a0',ADAPTER='0x46b425674d361a5E2A0ec5F486A6c1FA5aE012BB',CATEGORY='0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6';
const ZERO=('0x'+'00'.repeat(32)) as Hex;
const same=(a:string,b:string)=>a.toLowerCase()===b.toLowerCase();
const need=(ok:unknown,message:string)=>{if(!ok)throw Error(message);};
export function member(category:Hex,kid:Hex):Hex{return keccak256(encodeAbiParameters([{type:'bytes32'},{type:'bytes32'}],[category,kid]));}
// One instance behind Relay.txQueue; deployment must retain a single container writer.
export class DurableSponsorLedger {
 private cached?:Ledger;private halted=false;
 constructor(private file:string,private scope:Hex,private totalCap:bigint,private maxReservations:number,private validate:(r:Reservation,all:Reservation[])=>void,private validateLedger?:(ledger:Ledger)=>void){}
 async load():Promise<Ledger>{
  need(!this.halted,'sponsorship journal halted; manual reconciliation required');if(this.cached)return this.cached;
  let candidate:Ledger;try{candidate=JSON.parse(await Deno.readTextFile(this.file));}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;candidate={scope:this.scope,reservations:[]};}
  need(candidate.scope===this.scope&&Array.isArray(candidate.reservations)&&candidate.reservations.length<=this.maxReservations,'different sponsorship ledger; manual reconciliation required');
  for(const r of candidate.reservations){need(/^0x[0-9a-f]{64}$/.test(r.id)&&/^0x[0-9a-f]{64}$/.test(r.dataHash)&&Number.isSafeInteger(r.nonce)&&r.nonce>=0&&/^\d+$/.test(r.gas)&&/^\d+$/.test(r.gasPrice)&&/^\d+$/.test(r.fee)&&BigInt(r.gas)>0n&&BigInt(r.gasPrice)>0n&&BigInt(r.fee)>=BigInt(r.gas)*BigInt(r.gasPrice),'invalid durable reservation');this.validate(r,candidate.reservations);}
  need(new Set(candidate.reservations.map(r=>r.nonce)).size===candidate.reservations.length&&new Set(candidate.reservations.map(r=>r.id)).size===candidate.reservations.length,'duplicate reservation');
  need(candidate.reservations.reduce((n,r)=>n+BigInt(r.fee),0n)<=this.totalCap,'ledger exceeds budget');this.validateLedger?.(candidate);this.cached=candidate;return candidate;
 }
 async commit(ledger:Ledger){
  need(!this.halted,'sponsorship journal halted; manual reconciliation required');
  try{
   const temp=this.file+'.tmp';const f=await Deno.open(temp,{createNew:true,write:true,mode:0o600});
   try{const b=new TextEncoder().encode(JSON.stringify(ledger));let n=0;while(n<b.length)n+=await f.write(b.subarray(n));await f.sync();}finally{f.close();}
   await Deno.rename(temp,this.file);const slash=this.file.lastIndexOf('/');const directory=await Deno.open(slash>=0?this.file.slice(0,slash)||'/':'.',{read:true});try{await directory.sync();}finally{directory.close();}
   this.cached=ledger;
  }catch{this.halted=true;this.cached=undefined;throw Error('sponsorship persistence failed; manual reconciliation required');}
 }
}
export class QualificationSponsorPolicy implements SponsorPolicy {
 private readonly journal:DurableSponsorLedger;private readonly scope:Hex;private readonly now:()=>number;
 constructor(private config:QualificationBudget,private file:string,private abi:{demo:any,adapter:any},private deps:BudgetDependencies){
  need(config.version===1&&config.approved===true&&/^native84532-qualification:/.test(config.reference),'qualification sponsorship not approved');
  need(same(config.owner,OWNER)&&same(config.registry,REGISTRY)&&same(config.adapter,ADAPTER)&&same(config.category,CATEGORY),'wrong sponsorship domain');
  for(const key of [config.seedKeyId,config.peerKeyId,config.seedMember,config.peerMember])need(/^0x[0-9a-f]{64}$/.test(key),'unbound selected identity');
  need(config.seedKeyId!==config.peerKeyId&&member(config.category,config.seedKeyId)===config.seedMember&&member(config.category,config.peerKeyId)===config.peerMember,'identity derivation differs');
  need(/^\d+$/.test(config.priceCap)&&BigInt(config.priceCap)>0n&&BigInt(config.priceCap)<=12000000n&&/^\d+$/.test(config.totalCap)&&BigInt(config.totalCap)>0n&&BigInt(config.totalCap)<=211000000000000n,'budget limits invalid');
  need(/^[a-zA-Z0-9_-]{1,80}$/.test(config.seedName)&&/^[a-zA-Z0-9_-]{1,80}$/.test(config.peerName)&&config.seedName!==config.peerName,'selected mailbox names invalid');
  need(Number.isFinite(Date.parse(config.validUntil)),'invalid qualification deadline');
  this.scope=keccak256(new TextEncoder().encode(JSON.stringify(config)));this.now=deps.now||Date.now;
  this.journal=new DurableSponsorLedger(file,this.scope,BigInt(config.totalCap),8,(r,all)=>{const limits:Record<string,[number,bigint,Hex]>={'peer-enroll':[1,14000000n,config.peerMember],'seed-bootstrap':[1,500000n,config.seedMember],'peer-join':[2,500000n,config.peerMember],'seed-receipt':[2,500000n,config.seedMember],'peer-receipt':[2,500000n,config.peerMember]};const l=limits[r.kind];need(l&&r.member===l[2]&&BigInt(r.gas)<=l[1]&&BigInt(r.gasPrice)<=BigInt(config.priceCap)&&all.filter(x=>x.kind===r.kind).length<=l[0],'durable action limits differ');if(r.kind==='seed-bootstrap')need(/^0x[0-9a-f]{64}$/.test(r.sessionKeyHash||''),'bootstrap session absent');if(r.kind==='seed-receipt'||r.kind==='peer-receipt')need(/^0x[0-9a-f]{64}$/.test(r.joinTx||'')&&/^0x[0-9a-f]{64}$/.test(r.envelopeDigest||''),'receipt binding absent');},ledger=>this.validateBindings(ledger));
 }
 private validateBindings(ledger:Ledger){
  need(ledger.bindings===undefined||typeof ledger.bindings==='object'&&ledger.bindings!==null&&Object.keys(ledger.bindings).length<=2,'invalid mail bindings');
  for(const [key,text] of Object.entries(ledger.bindings||{})){need(/^hello:[01]$/.test(key)&&typeof text==='string'&&text.length<500,'invalid HELLO binding');const h=JSON.parse(text);need(Object.keys(h).sort().join(',')==='joinTx,member,sessionKeyHash'&&/^0x[0-9a-f]{64}$/.test(h.joinTx)&&/^0x[0-9a-f]{64}$/.test(h.sessionKeyHash)&&h.member===this.config.peerMember,'unbound HELLO');}
 }
 async allowMail(to:string,unknownBody:unknown,stage:'enqueue'|'deliver'='enqueue'){
  need(this.now()<Date.parse(this.config.validUntil),'qualification mail expired');const body=unknownBody as Record<string,string>;
  need(body&&typeof body==='object','invalid mail');const seed='nft:'+this.config.seedName,peer='nft:'+this.config.peerName;
  if(body.type==='HELLO'){
   need(to===seed&&body.from===this.config.peerName&&body.member===this.config.peerMember&&this.deps.verifyHello,'only selected peer HELLO');
   const verified=await this.deps.verifyHello!(body);need(verified.member===this.config.peerMember&&verified.joinTx===body.joinTx&&/^0x[0-9a-f]{130}$/.test(body.sessionPublic)&&keccak256(body.sessionPublic as Hex)===verified.sessionKeyHash,'HELLO session differs');
   const ledger=await this.journal.load(),bindings=ledger.bindings||{},values=Object.values(bindings).map(t=>JSON.parse(t));const prior=values.find(h=>h.joinTx===verified.joinTx);if(prior){need(stage==='deliver'&&prior.member===verified.member&&prior.sessionKeyHash===verified.sessionKeyHash,'duplicate HELLO session');return;}need(values.length<2,'exhausted HELLO sessions');
   await this.journal.commit({...ledger,bindings:{...bindings,['hello:'+values.length]:JSON.stringify(verified)}});return;
  }
  if(body.type==='PARCEL'){
   need(to===peer&&body.from===this.config.seedName&&/^0x[0-9a-f]{508}$/.test(body.parcel),'only selected seed parcel');const ledger=await this.journal.load();
   const digest=keccak256(body.parcel as Hex),receipt=ledger.reservations.find(r=>r.kind==='seed-receipt'&&r.envelopeDigest===digest);need(receipt,'unreserved seed parcel');
   const recipient=('0x'+body.parcel.slice(2+130*2,2+162*2)) as Hex,session=('0x'+body.parcel.slice(2+65*2,2+130*2)) as Hex,scope=('0x'+body.parcel.slice(2+162*2,2+194*2)) as Hex;
   const hello=Object.values(ledger.bindings||{}).map(t=>JSON.parse(t)).find(h=>h.joinTx===receipt!.joinTx);need(hello&&recipient===this.config.peerMember&&keccak256(session)===hello.sessionKeyHash&&scope===ZERO,'parcel recipient/session differs');return;
  }
  need((body.type==='PROOF'&&to===seed&&body.from===this.config.peerName)||(body.type==='ERROR'&&((to===peer&&body.from===this.config.seedName)||(to===seed&&body.from===this.config.peerName))),'unapproved qualification mail');
 }
 private classify(to:Address,data:Hex):{kind:string,member:Hex,cap:bigint,max:number}{
  if(same(to,this.config.adapter)){
   const decoded=decodeFunctionData({abi:this.abi.adapter,data});need(decoded.functionName==='enroll','only selected enrollment');
   const auth=(decoded.args as [Hex,Hex,Hex])[1];const b=Uint8Array.from(auth.slice(2).match(/../g)||[],x=>parseInt(x,16));
   need(b.length>=164&&b.length<=1024&&(b[32]&0x40)!==0&&(b[32]&0x80)!==0&&(b[32]&0x3e)===0&&b.slice(33,37).every(x=>x===0)&&b[53]===0&&b[54]===32,'invalid credential layout');
   const kid=('0x'+Array.from(b.slice(55,87),x=>x.toString(16).padStart(2,'0')).join('')) as Hex;
   need(kid===this.config.peerKeyId,'only selected peer enrollment; seed must resume valid identity');
   return {kind:'peer-enroll',member:this.config.peerMember,cap:14000000n,max:1};
  }
  need(same(to,this.config.registry),'unapproved sponsorship target');
  const decoded=decodeFunctionData({abi:this.abi.demo,data});need(decoded.functionName==='execute','only native execute');
  const [r,proof]=decoded.args as any;need(same(r.category,this.config.category)&&same(r.owner,this.config.owner)&&same(r.memberSigner,this.config.owner)&&r.scope===ZERO,'unapproved request domain');
  const [kid]=decodeAbiParameters([{type:'bytes32'},{type:'bytes'},{type:'uint256'},{type:'uint256'}],proof);
  const who=member(this.config.category,kid);need(who===this.config.seedMember||who===this.config.peerMember,'unselected native identity');
  if(Number(r.action)===2){need(who===this.config.seedMember,'only selected seed bootstrap');return {kind:'seed-bootstrap',member:who,cap:500000n,max:1};}
  if(Number(r.action)===0){need(who===this.config.peerMember,'only selected peer join');return {kind:'peer-join',member:who,cap:500000n,max:2};}
  need(Number(r.action)===3,'claim/admin/account/handoff sponsorship excluded');
  return {kind:who===this.config.seedMember?'seed-receipt':'peer-receipt',member:who,cap:500000n,max:2};
 }
 async reserve(q:SponsorRequest){
  need(this.now()<Date.parse(this.config.validUntil),'qualification sponsorship expired');
  need(q.id===keccak256((q.to.toLowerCase()+q.data.slice(2)) as Hex),'calldata reservation identity differs');
  const action=this.classify(q.to,q.data);need(Number.isSafeInteger(q.nonce)&&q.nonce>=0&&q.gas>0n&&q.gas<=action.cap&&q.gasPrice>0n&&q.gasPrice<=BigInt(this.config.priceCap),'sponsorship execution cap exceeded');
  const ledger=await this.journal.load(),existing=ledger.reservations.find(r=>r.id===q.id);
  const decodedRequest=action.kind.endsWith('-receipt')?(decodeFunctionData({abi:this.abi.demo,data:q.data}).args as any)[0]:undefined;
  let receiptBinding:Partial<Reservation>=action.kind==='seed-bootstrap'?{sessionKeyHash:(decodeFunctionData({abi:this.abi.demo,data:q.data}).args as any)[0].sessionKeyHash}:{};if(decodedRequest){const envelopeDigest=decodedRequest.envelopeDigest as Hex;if(action.kind==='seed-receipt'){const bootstrap=ledger.reservations.find(r=>r.kind==='seed-bootstrap');need(bootstrap&&bootstrap.sessionKeyHash===decodedRequest.sessionKeyHash,'seed receipt bootstrap session differs');const hellos=Object.values(ledger.bindings||{}).map(t=>JSON.parse(t));const h=existing?hellos.find(h=>h.joinTx===existing.joinTx):hellos.find(h=>!ledger.reservations.some(r=>r.kind==='seed-receipt'&&r.joinTx===h.joinTx));need(h,'seed receipt requires approved peer HELLO');receiptBinding={joinTx:h.joinTx,envelopeDigest};}else{const sender=ledger.reservations.find(r=>r.kind==='seed-receipt'&&r.envelopeDigest===envelopeDigest);need(sender,'peer receipt requires paired selected seed receipt');const hello=Object.values(ledger.bindings||{}).map(t=>JSON.parse(t)).find(h=>h.joinTx===sender!.joinTx);need(hello&&hello.sessionKeyHash===decodedRequest.sessionKeyHash,'peer receipt HELLO session differs');receiptBinding={joinTx:sender!.joinTx,envelopeDigest,sessionKeyHash:decodedRequest.sessionKeyHash};}}
  const overhead=await this.deps.feeEnvelope(q.gas,(q.data.length-2)/2+256);need(overhead>=0n,'invalid fee envelope');const fee=q.gas*q.gasPrice+overhead;
  if(existing){need(same(existing.to,q.to)&&existing.dataHash===keccak256(q.data)&&existing.nonce===q.nonce&&existing.kind===action.kind&&existing.member===action.member&&q.gas<=BigInt(existing.gas)&&q.gasPrice<=BigInt(existing.gasPrice)&&fee<=BigInt(existing.fee)&&(!decodedRequest||(existing.joinTx===receiptBinding.joinTx&&existing.envelopeDigest===receiptBinding.envelopeDigest)),'retry differs from durable reservation');}
  else {
   need(!ledger.reservations.some(r=>r.nonce===q.nonce),'nonce already reserved');
   need(ledger.reservations.filter(r=>r.kind===action.kind).length<action.max,'qualification action count exhausted');
   need(ledger.reservations.reduce((n,r)=>n+BigInt(r.fee),0n)+fee<=BigInt(this.config.totalCap),'qualification aggregate fee exhausted');
   const updated={...ledger,reservations:[...ledger.reservations,{id:q.id,to:q.to,dataHash:keccak256(q.data),nonce:q.nonce,gas:String(q.gas),gasPrice:String(q.gasPrice),fee:String(fee),kind:action.kind,member:action.member,...receiptBinding}]};
   await this.journal.commit(updated);
  }
  await this.deps.preSignCheck(fee);need(this.now()<Date.parse(this.config.validUntil),'qualification expired before signing');
 }
 async status(){const l=await this.journal.load();const maxima:Record<string,number>={'peer-enroll':1,'seed-bootstrap':1,'peer-join':2,'seed-receipt':2,'peer-receipt':2};const remaining=Object.fromEntries(Object.entries(maxima).map(([kind,max])=>[kind,max-l.reservations.filter(r=>r.kind===kind).length]));return {mode:'qualification',expiresAt:this.config.validUntil,expired:this.now()>=Date.parse(this.config.validUntil),additionalPublicEnrollmentCapacity:0,remainingActions:remaining,reservedFeeWei:String(l.reservations.reduce((n,r)=>n+BigInt(r.fee),0n)),ceilingWei:this.config.totalCap};}
 async reconcile(raw:Hex){
  const tx=parseTransaction(raw);need(tx.type==='legacy'&&tx.chainId===84532&&tx.to&&tx.data&&tx.nonce!==undefined&&tx.gas&&tx.gasPrice&&(tx.value??0n)===0n,'unapproved pending transaction');
  need(same(await recoverTransactionAddress({serializedTransaction:raw as TransactionSerialized}),this.config.owner),'pending signer differs');
  const id=keccak256((tx.to!.toLowerCase()+tx.data!.slice(2)) as Hex),ledger=await this.journal.load();need(ledger.reservations.some(r=>r.id===id),'unreserved pending transaction; manual reconciliation required');
  // Never create or refund a reservation through replay. Expiry blocks further broadcasts.
  await this.reserve({id,to:tx.to!,data:tx.data!,nonce:tx.nonce!,gas:tx.gas!,gasPrice:tx.gasPrice!});
 }
}
