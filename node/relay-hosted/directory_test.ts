// Synthetic adapter/RPC fixtures test policy, not actual native acceptance.
import {encode} from "npm:cbor-x@1.6.0";
import {encodeAbiParameters,encodeFunctionData,encodeEventTopics,keccak256,toHex,hexToBytes,type Hex} from "npm:viem@2.38.0";
import {directoryView} from '../../packaging/coupon/status/directory.mjs';
import {NativeDirectory,recordContext,leavePayload,validateCheckIn,decimal,type CheckIn} from './directory.ts';
const abi=JSON.parse(await Deno.readTextFile(new URL('./abi.json',import.meta.url))),badges=JSON.parse(await Deno.readTextFile(new URL('./badge-abi.json',import.meta.url)));
const h=(n:string,size=32)=>('0x'+n.repeat(size)) as Hex;
const network={chainId:84532,DemoV1:'0xd4b33c83576a6049d29c6b849ec73491e52781a0' as Hex,macCategory:h('22'),macAdapter:h('33',20),macCDRegistry:h('44',20),ResearchBadges:h('55',20),PersonalBadgeAccountFactory:h('66',20)};
const measuredNetwork={...network,measuredCategory:h('23'),measuredAdapter:h('34',20),measurementRegistry:h('45',20)};
type Mode='v1'|'v2'|'measured';
const check=(ok:unknown,message='check failed')=>{if(!ok)throw new Error(message);};
async function rejects(fn:()=>unknown){let rejected=false;try{await fn();}catch{rejected=true;}check(rejected,'invalid request accepted');}
const buffer=(v:Uint8Array)=>new Uint8Array(v).buffer;
const base64=(v:Uint8Array)=>btoa(String.fromCharCode(...v));
async function fixture(account=false,mode:Mode='v1'){
 const net=mode==='measured'?measuredNetwork:network,category=mode==='measured'?measuredNetwork.measuredCategory:network.macCategory,adapter=mode==='measured'?measuredNetwork.measuredAdapter:network.macAdapter;
 let now=1800000000;const policy:any={measurement:h('99'),epoch:1n,generation:0n,fail:false,paused:false,badAdapter:false,admitted:true,receiptStatus:'success',canonical:true,receiptReorg:false,receiptAge:10,contextMismatch:false};
 const session=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const sessionPublic=toHex(new Uint8Array(await crypto.subtle.exportKey('raw',session.publicKey)));
 const control=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);const point=new Uint8Array(await crypto.subtle.exportKey('raw',control.publicKey));
 const kid=new Uint8Array(32).fill(7),member=keccak256(new Uint8Array([...hexToBytes(category),...kid]));
 const input:CheckIn={member,keyId:base64(kid),sessionPublic,issuedAt:now,expiresAt:now+90,selfReported:'0.1.0-rc.4',buildNumber:'7',scope:h('00'),keyEpoch:'1',receiptTransaction:h('77'),account:account?h('88',20):null,accountGeneration:'0',accountSignature:null,assertion:'',...(mode==='v1'?{}:{measurement:h('99'),label:'mini mesh-1'})};
 async function assertion(count:number){const auth=new Uint8Array([...new Uint8Array(37),...encode({apple_cd_hash_hash_01:hexToBytes(h('99'))})]);new DataView(auth.buffer).setUint32(33,count,false);input.assertion=base64(encode({authenticatorData:auth,signature:new Uint8Array([48,6,2,1,1,2,1,1])}));}await assertion(1);
 const request={action:3,category,owner:network.DemoV1,memberSigner:network.DemoV1,sessionKeyHash:keccak256(sessionPublic),nonce:0n,validUntil:BigInt(now+55),scope:input.scope,keyX:1n,keyY:2n,envelopeDigest:h('ab')},eventContext=h('ac');
 const event=(name:string,args:any,data:Hex)=>({address:network.DemoV1,topics:encodeEventTopics({abi:abi.demo,eventName:name,args}),data});
 const logs=[event('Checked',{member,category,owner:network.DemoV1},encodeAbiParameters([{type:'bytes32'},{type:'bytes32'}],[eventContext,request.sessionKeyHash])),event('KeyReceipt',{scope:input.scope,member},encodeAbiParameters([{type:'bytes32'},{type:'bytes32'}],[request.envelopeDigest,eventContext]))];
 const client={
  async getBlock({blockNumber}:any={}){if(policy.fail)throw Error('private RPC error');return {number:blockNumber??100n,hash:policy.receiptReorg&&blockNumber===90n?h('bd'):(policy.canonical||blockNumber===undefined?h('bc'):h('bd')),timestamp:BigInt(blockNumber===90n?now-policy.receiptAge:now)};},
  async getBytecode(){return '0x1234';},
  async readContract({functionName}:any){if(policy.fail)throw Error('private RPC error');switch(functionName){case 'paused':return policy.paused;case 'categories':return [policy.badAdapter?h('aa',20):adapter,keccak256('0x1234'),h('01'),h('02'),true,true];case 'members':return [network.DemoV1,network.macCategory,BigInt(now),false];case 'registry':return network.DemoV1;case 'cds':return mode==='measured'?measuredNetwork.measurementRegistry:network.macCDRegistry;case 'measurementOf':return policy.measurement;case 'keyEpochs':return policy.epoch;case 'sharedKeys':return [1n,2n,member,true];case 'contextHash':return policy.contextMismatch?h('ad'):eventContext;case 'isAccount':return true;case 'generation':return policy.generation;case 'keyX':return BigInt(toHex(point.slice(1,33)));case 'keyY':return BigInt(toHex(point.slice(33)));case 'participantOf':return 3n;case 'ownerOf':return input.account;default:throw Error('unexpected read '+functionName);}},
  async call({account,to,blockNumber}:any){check(account===network.DemoV1&&to===adapter&&blockNumber===100n,'verification route not pinned');if(!policy.admitted)throw Error('admission rejection');return {data:encodeAbiParameters([{type:'bytes32'}],[toHex(kid)])};},
  async getTransactionReceipt(){return {status:policy.receiptStatus,blockNumber:90n,blockHash:h('bc'),logs};},
  async getTransaction(){return {to:network.DemoV1,input:encodeFunctionData({abi:abi.demo,functionName:'execute',args:[request,'0x','0x','0x']})};}
 };
 const directory=new NativeDirectory(client,net,abi,badges,true,()=>now);
 async function consent(){if(!input.account)return;const word=(n:bigint|number)=>hexToBytes(toHex(BigInt(n),{size:32})),addr=(a:Hex)=>hexToBytes(('0x'+'00'.repeat(12)+a.slice(2)) as Hex);const payload=new Uint8Array([...hexToBytes(keccak256(new TextEncoder().encode('DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1'))),...word(network.chainId),...addr(network.DemoV1),...hexToBytes(member),...hexToBytes(keccak256(sessionPublic)),...addr(input.account),...word(policy.generation),...hexToBytes(recordContext(net,input))]);input.accountSignature=toHex(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},control.privateKey,buffer(payload))));}await consent();
 return {directory,input,assertion,consent,session,client,policy,now:()=>now,advance(n:number){now+=n;},refresh(){input.issuedAt=now;input.expiresAt=now+90;}};
}
Deno.test('limits reject overflow, noncanonical decimal, version and unknown fields',async()=>{
 const f=await fixture();validateCheckIn(f.input,f.input.issuedAt);
 for(const [field,value] of [['keyEpoch','18446744073709551616'],['keyEpoch','01'],['buildNumber','2147483648'],['buildNumber','-1'],['selfReported','1+evil'],['expiresAt',f.input.issuedAt+91],['account',network.DemoV1],['unexpected',true]] as [string,unknown][])await rejects(()=>validateCheckIn({...f.input,[field]:value},f.input.issuedAt));await rejects(()=>decimal((1n<<256n).toString(),(1n<<256n)-1n));
});
Deno.test('verified receipt and check-in clocks never refresh on GET',async()=>{
 const f=await fixture();await f.directory.checkIn(f.input);const feed=await f.directory.listing();check(directoryView(feed,f.input.issuedAt).status==='available','backend/frontend schema mismatch');const original=(feed as any).nodes[0];check(original.sync.status==='receipt-verified-current-epoch');f.advance(111);const next=(await f.directory.listing() as any).nodes[0];check(next.checkIn.status==='stale'&&next.sync.status==='stale');for(const field of ['receiptBlockTime','receiptCheckedAt'])check(next.sync[field]===original.sync[field]);check(next.checkIn.lastVerifiedAt===original.checkIn.lastVerifiedAt);f.advance(189);check((await f.directory.listing() as any).nodes.length===0);
});
Deno.test('directory counter rejects replay and accepts gap without on-chain writes',async()=>{const f=await fixture();await f.directory.checkIn(f.input);f.advance(6);f.refresh();await rejects(()=>f.directory.checkIn(f.input));await f.assertion(3);await f.directory.checkIn(f.input);});
for(const mode of ['paused','badAdapter','admitted','epoch'])Deno.test('fail closed admission '+mode,async()=>{const f=await fixture();f.policy[mode]=mode==='admitted'?false:mode==='epoch'?2n:true;await rejects(()=>f.directory.checkIn(f.input));check((await f.directory.listing() as any).nodes.length===0);});
for(const mode of ['receiptStatus','contextMismatch'])Deno.test('receipt linkage rejection '+mode,async()=>{const f=await fixture();f.policy[mode]=mode==='receiptStatus'?'reverted':true;await f.directory.checkIn(f.input);check((await f.directory.listing() as any).nodes[0].sync.status==='unverified');});
Deno.test('rotation downgrades historical receipt',async()=>{const f=await fixture();await f.directory.checkIn(f.input);f.policy.epoch=2n;const n=(await f.directory.listing() as any).nodes[0];check(n.sync.status==='stale'&&n.sync.keyEpoch==='1');});
Deno.test('account consent binds exact record and current controller generation',async()=>{
 const f=await fixture(true);await f.directory.checkIn(f.input);check((await f.directory.listing() as any).nodes[0].account.address===f.input.account);f.policy.generation=1n;f.advance(6);check((await f.directory.listing() as any).nodes[0].account.status==='unavailable');const wrong=await fixture(true);wrong.input.accountSignature=h('01',64);await rejects(()=>wrong.directory.checkIn(wrong.input));const changed=await fixture(true);changed.input.selfReported='9.0';await rejects(()=>changed.directory.checkIn(changed.input));
});
Deno.test('leave requires matching session and latest context',async()=>{
 const f=await fixture(),accepted:any=await f.directory.checkIn(f.input),at=f.input.issuedAt;const payload=leavePayload(network,f.input.member,f.input.sessionPublic,accepted.context,at);const signature=toHex(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},f.session.privateKey,buffer(payload))));await rejects(()=>f.directory.leave({member:f.input.member,context:h('fe'),at,signature}));await rejects(()=>f.directory.leave({member:f.input.member,context:accepted.context,at,signature:h('01',64)}));await f.directory.leave({member:f.input.member,context:accepted.context,at,signature});check((await f.directory.listing() as any).nodes.length===0);await rejects(()=>f.directory.leave({member:f.input.member,context:accepted.context,at,signature}));
});
Deno.test('disabled, empty and unavailable are distinct',async()=>{
 const f=await fixture(),disabled=new NativeDirectory(f.client,network,abi,badges,false);check((await disabled.listing()).status==='not-configured');await rejects(()=>disabled.checkIn(f.input));check((await f.directory.listing()).status==='available');f.policy.fail=true;f.advance(6);const bad=await f.directory.listing();check(bad.status==='unavailable'&&bad.error?.code==='RPC_UNAVAILABLE');
});

Deno.test('GET coalesces concurrent RPC verification and has bounded five-second cache',async()=>{
 const f=await fixture(true);await f.directory.checkIn(f.input);let reads=0;
 const original=f.client.readContract;f.client.readContract=async(args:any)=>{reads++;await new Promise(resolve=>setTimeout(resolve,5));return original(args);};
 await Promise.all(Array.from({length:32},()=>f.directory.listing()));check(reads===2,'concurrent GET amplified RPC reads');
 const generated=(await f.directory.listing()).generatedAt;check(reads===2);f.advance(6);check((await f.directory.listing()).generatedAt!==generated);check(reads===4);
});
Deno.test('receipt reorg demotes evidence after cache expiry without refreshing clocks',async()=>{
 const f=await fixture();await f.directory.checkIn(f.input);check((await f.directory.listing() as any).nodes[0].sync.status==='receipt-verified-current-epoch');
 f.policy.receiptReorg=true;f.advance(6);const n=(await f.directory.listing() as any).nodes[0];check(n.sync.status==='unverified'&&n.sync.receiptBlockTime===null&&n.sync.receiptTransaction===null);
});

// Same vector as node/tests/MeasuredEnrollTests.swift (NativeDirectoryEncoding.context).
Deno.test('v2 record context binds measurement and label; shared Swift vector',async()=>{
 const kid=new Uint8Array(32).fill(7),member=keccak256(new Uint8Array([...hexToBytes(network.macCategory),...kid]));
 const b:CheckIn={member,keyId:base64(kid),sessionPublic:('0x04'+'11'.repeat(64)) as Hex,issuedAt:1800000000,expiresAt:1800000090,selfReported:'0.3.0',buildNumber:'12',scope:h('00'),keyEpoch:'2',receiptTransaction:h('77'),account:null,accountGeneration:'0',accountSignature:null,assertion:'',measurement:h('99'),label:'mini-mesh'};
 check(recordContext(network,b)==='0xf67b2597d4f39b6c878f6398e041a8134ac7a3a5ab1ecff073fa25dac96ab447',recordContext(network,b));
 check(recordContext(network,{...b,label:'other'})!==recordContext(network,b)&&recordContext(network,{...b,measurement:h('98')})!==recordContext(network,b),'v2 fields unbound');
 const {measurement:_m,label:_l,...v1}=b;check(recordContext(network,v1)!==recordContext(network,b),'v1 and v2 domains collide');
 for(const [field,value] of [['label','<b>'],['label','x'.repeat(33)],['measurement','0x99'],['label',undefined]] as [string,unknown][])await rejects(()=>validateCheckIn({...b,[field]:value},b.issuedAt));
 await rejects(()=>validateCheckIn({...v1,label:'x'},b.issuedAt));
});
Deno.test('legacy category lists a v2 label with no measurement claim',async()=>{
 const f=await fixture(false,'v2');await f.directory.checkIn(f.input);const n=(await f.directory.listing() as any).nodes[0];
 check(n.label==='mini mesh-1'&&n.version.measurement===null&&directoryView(await f.directory.listing(),f.now()).status==='available');
});
Deno.test('measured category lists M only when the registry maps the attested CDHash to it',async()=>{
 const f=await fixture(false,'measured');f.policy.measurement=h('98');await rejects(()=>f.directory.checkIn(f.input));
 const v1=await fixture(false,'measured');delete v1.input.measurement;delete v1.input.label;await rejects(()=>v1.directory.checkIn(v1.input));
 const g=await fixture(false,'measured');await g.directory.checkIn(g.input);check((await g.directory.listing() as any).nodes[0].version.measurement===h('99'));
});
// Node-level fixture: the node heartbeats every 30 s (Node.attemptDirectoryCheckIn) and then stops.
Deno.test('directory lists a heartbeating measured node, marks it stale after the 90 s TTL and drops it at retention',async()=>{
 const f=await fixture(false,'measured');
 for(let beat=1;beat<=4;beat++){
  f.refresh();await f.assertion(beat);const accepted:any=await f.directory.checkIn(f.input);check(accepted.accepted&&accepted.context===recordContext(measuredNetwork,f.input));
  const feed:any=await f.directory.listing(),view=directoryView(feed,f.now());
  check(feed.nodes.length===1&&feed.nodes[0].checkIn.status==='fresh'&&feed.nodes[0].member===f.input.member&&feed.nodes[0].label==='mini mesh-1'&&feed.nodes[0].version.measurement===h('99')&&feed.nodes[0].version.selfReported==='0.1.0-rc.4','heartbeat not listed');
  check(view.nodes.length===1&&view.nodes[0].fresh,'dashboard does not show the node');
  f.advance(30);
 }
 f.advance(55);check((await f.directory.listing() as any).nodes[0].checkIn.status==='fresh','expired before TTL');
 f.advance(5);const stale:any=await f.directory.listing();check(stale.nodes[0].checkIn.status==='stale'&&!directoryView(stale,f.now()).nodes[0].fresh,'fresh after TTL');
 f.advance(210);check((await f.directory.listing() as any).nodes.length===0,'retained after 300 s');
});
