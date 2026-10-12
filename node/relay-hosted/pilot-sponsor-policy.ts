import {decodeAbiParameters,decodeFunctionData,encodeAbiParameters,hexToBytes,toHex,keccak256,parseTransaction,recoverTransactionAddress,type Address,type Hex,type TransactionSerialized} from 'npm:viem@2.38.0';
import {DurableSponsorLedger,member,type SponsorPolicy,type SponsorRequest,type Reservation,type Ledger,type BudgetDependencies} from './sponsor-policy.ts';

// One public slot, not a friend invitation or proof of a distinct human/device.
// Relay must successfully estimate the exact calldata BEFORE reserve, retain its
// normal route/class authentication, and serialize reserve/allowMail on txQueue.
export type PilotBudget={version:1,approved:boolean,reference:string,validUntil:string,owner:Address,registry:Address,adapter:Address,category:Hex,factory:Address,badges:Address,codeHash:Hex,rpIdHash:Hex,seedKeyId:Hex,seedMember:Hex,seedMailbox:string,seedSessionKeyHash:Hex,priceCap:string,totalCap:string};
export type PilotDependencies=BudgetDependencies&{
 // Verify a successful canonical Join receipt, exact category/member/session,
 // fresh block and current admission; body is public HELLO metadata only.
 verifyHello:(body:unknown)=>Promise<{joinTx:Hex,sessionKeyHash:Hex,member:Hex}>;
 accountAddress:(x:bigint,y:bigint)=>Promise<Address>;
 accountEligibleForFirstClaim:(account:Address)=>Promise<boolean>;
};
const ZERO=('0x'+'00'.repeat(32)) as Hex;
const DOMAIN={owner:'0xe45c80da8a992447e9da6d2d82fe4b6fa2d48c61',registry:'0xd4b33c83576a6049d29c6b849ec73491e52781a0',adapter:'0x46b425674d361a5e2a0ec5f486a6c1fa5ae012bb',category:'0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6',factory:'0x18b5c72c48622661aeeadb596443c5e0e99f5188',badges:'0x6ac5fb83f5bf615842b5a9a6c50b8011fab50c3b',codeHash:'0xc1f295c567431331d9a899fd969d201ffad281ecf05c02f3a26d00719c91e9d8',rpIdHash:'0x90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6'};
function need(v:unknown,m:string):asserts v {if(!v)throw Error(m);}
const same=(a:string,b:string)=>a.toLowerCase()===b.toLowerCase();
const h32=(v:unknown):v is Hex=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v);
const addr=(v:unknown):v is Address=>typeof v==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v)&&!/^0x0{40}$/.test(v);
const LIMITS:Record<string,[number,bigint]>={'pilot-enroll':[1,14000000n],'pilot-join':[1,500000n],'seed-receipt':[1,500000n],'pilot-receipt':[3,500000n],'pilot-factory':[1,1500000n],'pilot-claim':[1,500000n]};
function enrollment(auth:Hex,config:PilotBudget):Hex {
 const b=hexToBytes(auth);need(b.length>=164&&b.length<=1024&&(b[32]&0xc0)===0xc0&&(b[32]&0x3e)===0&&b.slice(33,37).every(x=>x===0)&&b[53]===0&&b[54]===32,'invalid enrollment layout');
 need(toHex(b.slice(0,32))===config.rpIdHash,'wrong enrollment app');
 // Match the contract's canonical 77-byte COSE profile before the extensions.
 need(toHex(b.slice(87,97))==='0xa5010203262001215820'&&toHex(b.slice(129,132))==='0x225820','invalid enrollment COSE');
 let p=164;const head=(major:number)=>{need(p<b.length,'truncated extension');const v=b[p++];need(v>>5===major,'extension type');let n=v&31;need(n<26,'extension length');if(n===24){need(p<b.length,'truncated extension');n=b[p++];need(n>=24,'noncanonical extension');}else if(n===25){need(p+2<=b.length,'truncated extension');n=b[p++]*256+b[p++];need(n>255,'noncanonical extension');}return n;};
 const item=(major:number)=>{const n=head(major);need(p+n<=b.length,'extension bounds');const v=b.slice(p,p+n);p+=n;return v;};
 const count=head(5);need(count===3||count===4,'extension count');const seen=new Set<string>();let code='',type='',category='';
 for(let i=0;i<count;i++){const key=new TextDecoder('utf-8',{fatal:true}).decode(item(3));need(!seen.has(key),'duplicate extension');seen.add(key);const value=toHex(item(key==='apple_bundle_version_01'?3:2));if(key==='apple_cd_hash_hash_01')code=value;else if(key==='apple_cd_hash_type_01')type=value;else if(key==='apple_validation_category_01')category=value;else need(key==='apple_bundle_version_01','unknown extension');}
 need(p===b.length&&code===config.codeHash&&type==='0x02'&&category==='0x06000000','not selected C Developer ID enrollment');
 return toHex(b.slice(55,87));
}
export class PublicPilotSponsorPolicy implements SponsorPolicy {
 private journal:DurableSponsorLedger;private scope:Hex;private now:()=>number;
 constructor(private config:PilotBudget,file:string,private abi:{demo:any,adapter:any,factory:any,badges:any},private deps:PilotDependencies){
  need(config.version===1&&config.approved===true&&/^native84532-public-pilot:/.test(config.reference),'public pilot not approved');
  for(const [key,value] of Object.entries(DOMAIN))need(same((config as any)[key],value),'wrong pilot domain/build');
  need(h32(config.seedKeyId)&&config.seedKeyId!==ZERO&&member(config.category,config.seedKeyId)===config.seedMember&&config.seedMailbox==='nft:release-nft-seed','invalid seed binding');
  need(/^\d+$/.test(config.priceCap)&&BigInt(config.priceCap)>0n&&BigInt(config.priceCap)<=12000000n&&/^\d+$/.test(config.totalCap)&&BigInt(config.totalCap)>0n&&BigInt(config.totalCap)<=240000000000000n,'invalid pilot ceiling');
  need(h32(config.seedSessionKeyHash)&&config.seedSessionKeyHash!==ZERO,'invalid seed session');
  need(Number.isFinite(Date.parse(config.validUntil)),'invalid pilot expiry');this.now=deps.now||Date.now;this.scope=keccak256(new TextEncoder().encode(JSON.stringify(config)));
  this.journal=new DurableSponsorLedger(file,this.scope,BigInt(config.totalCap),8,(r,all)=>this.validateReservation(r,all),(l)=>this.validateBindings(l));
 }
 private validateReservation(r:Reservation,all:Reservation[]){
  const limit=LIMITS[r.kind];need(limit&&BigInt(r.gas)<=limit[1]&&BigInt(r.gasPrice)<=BigInt(this.config.priceCap)&&all.filter(x=>x.kind===r.kind).length<=limit[0],'pilot durable action cap');
  const first=all.find(x=>x.kind==='pilot-enroll');need(first&&h32(first.keyId)&&first.keyId!==this.config.seedKeyId&&member(this.config.category,first.keyId)===first.member,'unbound pilot reservation');
  need(r.member===(r.kind==='seed-receipt'?this.config.seedMember:first.member),'different reserved participant');
  const target=r.kind==='pilot-enroll'?this.config.adapter:r.kind==='pilot-factory'?this.config.factory:r.kind==='pilot-claim'?this.config.badges:this.config.registry;need(same(r.to,target),'different reserved target');
  if(r.kind==='pilot-join')need(h32(r.sessionKeyHash)&&r.sessionKeyHash!==ZERO,'invalid joined session');
  if(r.kind==='pilot-receipt')need(h32(r.envelopeDigest)&&r.envelopeDigest!==ZERO&&h32(r.sessionKeyHash)&&all.some(x=>x.kind==='pilot-join'&&x.sessionKeyHash===r.sessionKeyHash),'unbound durable peer receipt');
  if(r.kind==='seed-receipt')need(h32(r.joinTx)&&h32(r.envelopeDigest)&&r.envelopeDigest!==ZERO,'unbound seed receipt');
  if(r.kind==='pilot-factory'||r.kind==='pilot-claim'){need(addr(r.account),'invalid pilot account');const accounts=all.filter(x=>x.account).map(x=>x.account!.toLowerCase());need(new Set(accounts).size===1,'different pilot account');}
 }
 private validateBindings(l:Ledger){
  const b=l.bindings||{};need(Object.keys(b).every(k=>['helloJoinTx','helloSession','helloFrom','helloHash'].includes(k)),'unknown pilot binding');
  if(Object.keys(b).length){need(Object.keys(b).length===4&&h32(b.helloJoinTx)&&h32(b.helloSession)&&h32(b.helloHash)&&/^nft:[a-zA-Z0-9_-]{1,80}$/.test(b.helloFrom)&&b.helloFrom!==this.config.seedMailbox,'invalid durable HELLO');need(l.reservations.some(r=>r.kind==='pilot-join'&&r.sessionKeyHash===b.helloSession),'HELLO without reserved Join');}
  const firstPeer=l.reservations.find(r=>r.kind==='pilot-receipt');if(firstPeer)need(l.reservations.some(r=>r.kind==='seed-receipt'&&r.envelopeDigest===firstPeer.envelopeDigest),'durable first receipt differs');
  for(const r of l.reservations.filter(r=>r.kind==='seed-receipt'))need(r.joinTx===b.helloJoinTx,'seed receipt HELLO mismatch');
 }
 private active(){need(this.now()<Date.parse(this.config.validUntil),'public pilot expired');}
 private domain(r:any){need(same(r.category,this.config.category)&&same(r.owner,this.config.owner)&&same(r.memberSigner,this.config.owner)&&r.scope===ZERO,'pilot request domain');}
 private async action(q:SponsorRequest,l:Ledger):Promise<Partial<Reservation>&{kind:string,member:Hex}>{
  const first=l.reservations.find(r=>r.kind==='pilot-enroll');
  if(same(q.to,this.config.adapter)){const d=decodeFunctionData({abi:this.abi.adapter,data:q.data});need(d.functionName==='enroll','only pilot enrollment');const keyId=enrollment((d.args as [Hex,Hex,Hex])[1],this.config);need(keyId!==this.config.seedKeyId&&(!first||first.keyId===keyId),'public pilot slot already reserved');return {kind:'pilot-enroll',member:member(this.config.category,keyId),keyId};}
  need(first,'public pilot needs its reserved enrollment');
  if(same(q.to,this.config.registry)){
   const d=decodeFunctionData({abi:this.abi.demo,data:q.data});need(d.functionName==='execute','only native execute');const [r,proof]=d.args as any;this.domain(r);const [kid]=decodeAbiParameters([{type:'bytes32'},{type:'bytes'},{type:'uint256'},{type:'uint256'}],proof);const who=member(this.config.category,kid);
   if(Number(r.action)===0){need(who===first.member&&r.keyX===0n&&r.keyY===0n&&r.envelopeDigest===ZERO&&r.sessionKeyHash!==ZERO,'only bound pilot Join');return {kind:'pilot-join',member:who,sessionKeyHash:r.sessionKeyHash};}
   need(Number(r.action)===3&&r.envelopeDigest!==ZERO,'only pilot key receipts');
   if(who===this.config.seedMember){need(r.sessionKeyHash===this.config.seedSessionKeyHash,'seed session differs');need(l.bindings?.helloJoinTx,'seed receipt requires canonical bound HELLO');return {kind:'seed-receipt',member:who,joinTx:l.bindings!.helloJoinTx as Hex,envelopeDigest:r.envelopeDigest};}
   need(who===first.member&&l.reservations.some(x=>x.kind==='pilot-join'&&x.sessionKeyHash===r.sessionKeyHash),'unbound pilot receipt');const prior=l.reservations.filter(x=>x.kind==='pilot-receipt');if(!prior.length||prior[0].id===q.id)need(l.reservations.some(x=>x.kind==='seed-receipt'&&x.envelopeDigest===r.envelopeDigest),'first peer receipt must acknowledge seed parcel');
   // The next two authenticated Receipt digests are opaque until create/claim
   // arrives. They are bounded, irreversible allowance, not intent authorization.
   return {kind:'pilot-receipt',member:who,envelopeDigest:r.envelopeDigest,sessionKeyHash:r.sessionKeyHash};
  }
  if(same(q.to,this.config.factory)){
   const d=decodeFunctionData({abi:this.abi.factory,data:q.data});need(d.functionName==='createForMember','only bound factory creation');const [x,y,kid,r]=d.args as any;this.domain(r);need(l.reservations.some(x=>x.kind==='pilot-join'&&x.sessionKeyHash===r.sessionKeyHash),'factory session differs');need(kid===first.keyId&&Number(r.action)===3,'factory identity/action');const digest=keccak256(encodeAbiParameters([{type:'bytes32'},{type:'uint256'},{type:'address'},{type:'bytes32'},{type:'uint256'},{type:'uint256'}],[keccak256(new TextEncoder().encode('ATTEST_PERSONAL_CREATE_V1')),84532n,this.config.factory,kid,x,y]));need(r.envelopeDigest===digest&&l.reservations.some(z=>z.kind==='pilot-receipt'&&z.envelopeDigest===digest),'factory lacks reserved creation receipt');const account=await this.deps.accountAddress(x,y);return {kind:'pilot-factory',member:first.member,account};
  }
  need(same(q.to,this.config.badges),'unapproved pilot target');const d=decodeFunctionData({abi:this.abi.badges,data:q.data});need(d.functionName==='claim','only Level1 claim');const [claim,r]=d.args as any;this.domain(r);need(l.reservations.some(x=>x.kind==='pilot-join'&&x.sessionKeyHash===r.sessionKeyHash),'claim session differs');need(claim.keyId===first.keyId&&Number(claim.level)===1&&claim.parent===0n&&Number(r.action)===3,'only bound Level1 claim');const account=claim.recipient as Address;if(!l.reservations.some(x=>x.id===q.id))need(await this.deps.accountEligibleForFirstClaim(account),'account already has badge or is not personal factory account');const bound=l.reservations.find(x=>x.account)?.account;need(!bound||same(bound,account),'different pilot account');const digest=keccak256(encodeAbiParameters([{type:'string'},{type:'uint256'},{type:'address'},{type:'tuple',components:[{name:'recipient',type:'address'},{name:'keyId',type:'bytes32'},{name:'level',type:'uint8'},{name:'parent',type:'uint256'},{name:'deadline',type:'uint64'}]}],['ATTEST_RESEARCH_BADGE_V1',84532n,this.config.badges,claim]));need(r.envelopeDigest===digest&&l.reservations.some(x=>x.kind==='pilot-receipt'&&x.envelopeDigest===digest),'claim lacks reserved consent receipt');return {kind:'pilot-claim',member:first.member,account};
 }
 async reserve(q:SponsorRequest){
  this.active();need(q.id===keccak256((q.to.toLowerCase()+q.data.slice(2)) as Hex),'pilot calldata identity');const l=await this.journal.load(),a=await this.action(q,l),limit=LIMITS[a.kind];need(Number.isSafeInteger(q.nonce)&&q.nonce>=0&&q.gas>0n&&q.gas<=limit[1]&&q.gasPrice>0n&&q.gasPrice<=BigInt(this.config.priceCap),'pilot execution ceiling');
  const overhead=await this.deps.feeEnvelope(q.gas,(q.data.length-2)/2+256);need(overhead>=0n,'pilot fee envelope');const fee=q.gas*q.gasPrice+overhead;
  const old=l.reservations.find(r=>r.id===q.id);
  if(old){need(old.nonce===q.nonce&&same(old.to,q.to)&&old.dataHash===keccak256(q.data)&&old.kind===a.kind&&old.member===a.member&&q.gas<=BigInt(old.gas)&&q.gasPrice<=BigInt(old.gasPrice),'pilot retry changed');need(fee<=BigInt(old.fee),'pilot retry fee grew');}
  else{need(!l.reservations.some(r=>r.nonce===q.nonce)&&l.reservations.filter(r=>r.kind===a.kind).length<limit[0],'pilot count or nonce exhausted');need(l.reservations.reduce((n,r)=>n+BigInt(r.fee),0n)+fee<=BigInt(this.config.totalCap),'pilot aggregate fee exhausted');const row={...a,id:q.id,to:q.to,dataHash:keccak256(q.data),nonce:q.nonce,gas:String(q.gas),gasPrice:String(q.gasPrice),fee:String(fee)} as Reservation;const next={...l,reservations:[...l.reservations,row]};for(const r of next.reservations)this.validateReservation(r,next.reservations);this.validateBindings(next);await this.journal.commit(next);}
  // Reservation survives every failed check, signature failure and uncertain send.
  await this.deps.preSignCheck(fee);this.active();
 }
 async allowMail(to:string,body:unknown){
  this.active();need(body&&typeof body==='object'&&!Array.isArray(body),'invalid pilot mail');const b=body as Record<string,unknown>;need(typeof b.from==='string'&&/^[a-zA-Z0-9_-]{1,80}$/.test(b.from),'invalid pilot sender');const from='nft:'+b.from,l=await this.journal.load(),first=l.reservations.find(r=>r.kind==='pilot-enroll');need(first,'public pilot slot not reserved');
  if(b.type==='HELLO'){
   need(to===this.config.seedMailbox&&from!==to&&b.member===first.member&&h32(b.joinTx)&&typeof b.sessionPublic==='string'&&/^0x04[0-9a-f]{128}$/.test(b.sessionPublic)&&h32(b.nonce),'unbound public HELLO');const session=keccak256(b.sessionPublic as Hex);need(l.reservations.some(r=>r.kind==='pilot-join'&&r.sessionKeyHash===session),'HELLO session differs');const verified=await this.deps.verifyHello(b);need(verified.member===first.member&&verified.joinTx===b.joinTx&&verified.sessionKeyHash===session,'canonical HELLO differs');const bindings={helloJoinTx:b.joinTx as string,helloSession:session,helloFrom:from,helloHash:keccak256(new TextEncoder().encode(JSON.stringify([from,b.member,b.joinTx,b.sessionPublic,b.nonce])))};
   if(l.bindings){need(JSON.stringify(l.bindings)===JSON.stringify(bindings),'public pilot HELLO already bound');return;}
   const next={...l,bindings};this.validateBindings(next);await this.journal.commit(next);return;
  }
  need(l.bindings,'pilot mail lacks HELLO');
  if(b.type==='PARCEL'){
   need(from===this.config.seedMailbox&&to===l.bindings!.helloFrom&&typeof b.parcel==='string'&&/^0x[0-9a-f]{508}$/.test(b.parcel),'unbound pilot parcel');const bytes=hexToBytes(b.parcel as Hex);need(keccak256(toHex(bytes.slice(0,65)))===this.config.seedSessionKeyHash&&toHex(bytes.slice(130,162))===first.member&&keccak256(toHex(bytes.slice(65,130)))===l.bindings!.helloSession&&toHex(bytes.slice(162,194))===ZERO,'parcel recipient differs');need(l.reservations.some(r=>r.kind==='seed-receipt'&&r.joinTx===l.bindings!.helloJoinTx&&r.envelopeDigest===keccak256(b.parcel as Hex)),'parcel lacks reserved seed receipt');return;
  }
  need((b.type==='PROOF'&&from===l.bindings!.helloFrom&&to===this.config.seedMailbox)||(b.type==='ERROR'&&from===this.config.seedMailbox&&to===l.bindings!.helloFrom),'unapproved pilot mailbox message');
 }
 async status():Promise<Record<string,unknown>> {
  const l=await this.journal.load(),expired=this.now()>=Date.parse(this.config.validUntil);
  const remaining=Object.fromEntries(Object.entries(LIMITS).map(([kind,[count]])=>[kind,Math.max(0,count-l.reservations.filter(r=>r.kind===kind).length)]));
  const reserved=l.reservations.reduce((n,r)=>n+BigInt(r.fee),0n),ceiling=BigInt(this.config.totalCap);
  const exhausted=reserved>=ceiling||Object.values(remaining).every(n=>n===0);
  // Capacity is an upper bound; actual fresh fees/chain admission can refuse it.
  return {mode:'public-pilot',expiresAt:this.config.validUntil,expired,exhausted,additionalPublicEnrollmentCapacity:expired||exhausted?0:remaining['pilot-enroll'],remainingActions:remaining,reservedFeeWei:String(reserved),ceilingWei:String(ceiling)};
 }
 async reconcile(raw:Hex){const tx=parseTransaction(raw);need(tx.type==='legacy'&&tx.chainId===84532&&tx.to&&tx.data&&tx.nonce!==undefined&&tx.gas&&tx.gasPrice&&(tx.value??0n)===0n,'unapproved pilot pending transaction');need(same(await recoverTransactionAddress({serializedTransaction:raw as TransactionSerialized}),this.config.owner),'pilot pending signer');const id=keccak256((tx.to!.toLowerCase()+tx.data!.slice(2)) as Hex);need((await this.journal.load()).reservations.some(r=>r.id===id),'unreserved pilot pending transaction');await this.reserve({id,to:tx.to!,data:tx.data!,nonce:tx.nonce!,gas:tx.gas!,gasPrice:tx.gasPrice!});}
}
