import {decode} from "npm:cbor-x@1.6.0/decode-no-eval";
import {encodeAbiParameters, encodeFunctionData, decodeFunctionData, decodeEventLog, keccak256, toHex, hexToBytes, parseAbi, type Hex} from "npm:viem@2.38.0";

const ZERO=('0x'+'00'.repeat(32)) as Hex;
const ZERO_ADDRESS='0x'+'00'.repeat(20);
const TTL=90, RETENTION=300, RECEIPT_TTL=120, LIMIT=64;
const measurementAbi=parseAbi(['function measurementOf(bytes32) view returns (bytes32)']);
const encoder=new TextEncoder();
const iso=(seconds:number)=>new Date(seconds*1000).toISOString();
function require(ok:unknown):asserts ok {if(!ok)throw new Error('DIRECTORY_INVALID');}
export function decimal(value:unknown,max:bigint):string {
    require(typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value)&&BigInt(value)<=max);return value;
}
function hex(value:unknown,bytes:number):Hex {require(typeof value==='string'&&new RegExp('^0x[0-9a-f]{'+bytes*2+'}$').test(value));return value as Hex;}
function word(value:bigint|number|string):Uint8Array {return hexToBytes(toHex(BigInt(value),{size:32}));}
function address(value:string):Uint8Array {return hexToBytes(('0x'+'00'.repeat(12)+value.slice(2)) as Hex);}
function join(...parts:Uint8Array[]):Uint8Array {const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;}
const domain=(name:string)=>hexToBytes(keccak256(encoder.encode(name)));
const buffer=(bytes:Uint8Array)=>new Uint8Array(bytes).buffer;
const digest=async(bytes:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',buffer(bytes)));
function binary(value:unknown,max:number):Uint8Array {require(typeof value==='string'&&value.length<=max);return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
function signature(der:Uint8Array):[bigint,bigint] {
    require(der.length>=8&&der[0]===48&&der[1]===der.length-2);let at=2;
    function scalar(){require(der[at++]===2);const n=der[at++];require(n>0&&n<=33&&at+n<=der.length);const bytes=der.slice(at,at+n);at+=n;require(bytes[0]<128&&(bytes[0]!==0||n===1||bytes[1]>=128));return BigInt(toHex(bytes));}
    const r=scalar(),s=scalar();require(at===der.length);return [r,s];
}
// V2 adds the code measurement M and a public label, both bound by the assertion.
export type CheckIn={member:Hex,keyId:string,sessionPublic:Hex,issuedAt:number,expiresAt:number,selfReported:string,buildNumber:string,scope:Hex,keyEpoch:string,receiptTransaction:Hex|null,account:Hex|null,accountGeneration:string,accountSignature:Hex|null,assertion:string,measurement?:Hex,label?:string};
type Network={chainId:number,DemoV1:Hex,macCategory:Hex,macAdapter:Hex,macCDRegistry:Hex,measuredCategory?:Hex,measuredAdapter?:Hex,measurementRegistry?:Hex,ResearchBadges?:Hex,PersonalBadgeAccountFactory?:Hex};
const V1=['member','keyId','sessionPublic','issuedAt','expiresAt','selfReported','buildNumber','scope','keyEpoch','receiptTransaction','account','accountGeneration','accountSignature','assertion'];
/** The category whose member derivation matches, with its adapter and code registry. */
export function admission(network:Network,b:CheckIn) {
    const kid=binary(b.keyId,64);
    const policies=[{category:network.macCategory,adapter:network.macAdapter,cds:network.macCDRegistry,measured:false}];
    if(network.measuredCategory)policies.push({category:network.measuredCategory,adapter:network.measuredAdapter!,cds:network.measurementRegistry!,measured:true});
    const p=policies.find(p=>keccak256(join(hexToBytes(p.category),kid))===b.member);require(p);
    return {category:p.category.toLowerCase() as Hex,adapter:p.adapter.toLowerCase() as Hex,cds:p.cds.toLowerCase() as Hex,measured:p.measured};
}
type Entry={record:any,sessionPublic:Hex,context:Hex,epoch:bigint,receiptBlock:{number:bigint,hash:Hex}|null};
export function validateCheckIn(input:unknown,now:number):CheckIn {
    require(input&&typeof input==='object'&&!Array.isArray(input));const b=input as CheckIn;
    const v2='measurement' in b;
    require(Object.keys(b).sort().join(',')===(v2?[...V1,'measurement','label']:V1).sort().join(','));
    if(v2){hex(b.measurement,32);require(typeof b.label==='string'&&/^[A-Za-z0-9 ._-]{0,32}$/.test(b.label));}
    hex(b.member,32);hex(b.sessionPublic,65);require(b.sessionPublic.startsWith('0x04'));
    require(Number.isSafeInteger(b.issuedAt)&&b.issuedAt>=now-30&&b.issuedAt<=now+5&&b.expiresAt===b.issuedAt+TTL);
    require(typeof b.selfReported==='string'&&/^[0-9][A-Za-z0-9._-]{0,63}$/.test(b.selfReported));decimal(b.buildNumber,2147483647n);
    hex(b.scope,32);require(b.scope===ZERO);decimal(b.keyEpoch,18446744073709551615n);decimal(b.accountGeneration,18446744073709551615n);
    if(b.receiptTransaction!==null)hex(b.receiptTransaction,32);
    if(b.account===null)require(b.accountSignature===null&&b.accountGeneration==='0');else {hex(b.account,20);hex(b.accountSignature,64);}
    require(binary(b.keyId,64).length===32);binary(b.assertion,14000);return b;
}
export function recordContext(network:Network,b:CheckIn):Hex {
    const v2=b.measurement===undefined?[]:[hexToBytes(b.measurement),hexToBytes(keccak256(encoder.encode(b.label!)))];
    return keccak256(join(domain(v2.length?'DSMACK_NATIVE_DIRECTORY_CHECK_IN_V2':'DSMACK_NATIVE_DIRECTORY_CHECK_IN_V1'),word(network.chainId),address(network.DemoV1),hexToBytes(admission(network,b).category),hexToBytes(b.member),hexToBytes(keccak256(b.sessionPublic)),word(b.issuedAt),word(b.expiresAt),hexToBytes(keccak256(encoder.encode(b.selfReported))),word(b.buildNumber),hexToBytes(b.scope),word(b.keyEpoch),hexToBytes(b.receiptTransaction??ZERO),address(b.account??ZERO_ADDRESS),word(b.accountGeneration),...v2));
}
export async function accountConsent(network:Network,b:CheckIn,context:Hex):Promise<Uint8Array> {
    return await digest(join(domain('DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1'),word(network.chainId),address(network.DemoV1),hexToBytes(b.member),hexToBytes(keccak256(b.sessionPublic)),address(b.account!),word(b.accountGeneration),hexToBytes(context)));
}
export function leavePayload(network:Network,member:Hex,session:Hex,context:Hex,at:number):Uint8Array {
    return join(domain('DSMACK_NATIVE_DIRECTORY_LEAVE_V1'),word(network.chainId),address(network.DemoV1),hexToBytes(member),hexToBytes(keccak256(session)),hexToBytes(context),word(at));
}
async function verifyP256(point:Hex,signature:Hex,payload:Uint8Array):Promise<boolean> {
    const key=await crypto.subtle.importKey('raw',buffer(hexToBytes(point)),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,buffer(hexToBytes(signature)),buffer(payload));
}
/** No sponsor or send method exists here. All verification uses pinned read-only RPC. */
export class NativeDirectory {
    private entries=new Map<string,Entry>();
    private counters=new Map<string,{count:number,at:number}>();
    private queue:Promise<unknown>=Promise.resolve();
    private pending=0;
    private revision=0;
    private listingInFlight?:Promise<any>;
    private listingCache?:{at:number,value:any};
    constructor(private client:any,private network:Network,private abi:any,private badgeAbi:any,private enabled=false,private clock=()=>Math.floor(Date.now()/1000)){}
    private read(functionName:string,args:unknown[],blockNumber:bigint,target=this.network.DemoV1,abi=this.abi.demo){return this.client.readContract({address:target,abi,functionName,args,blockNumber});}
    private prune(now:number){for(const [id,e] of this.entries)if(now-Date.parse(e.record.checkIn.lastVerifiedAt)/1000>=RETENTION)this.entries.delete(id);for(const [id,c] of this.counters)if(now-c.at>=RETENTION)this.counters.delete(id);}
    private async head(){const head=await this.client.getBlock();const now=this.clock();require(Number(head.timestamp)<=now+5&&now-Number(head.timestamp)<45);return head;}
    private async canonical(head:any){const again=await this.client.getBlock({blockNumber:head.number});require(again.hash===head.hash);}
    async listing(){
        const now=this.clock();
        if(this.listingCache&&now-this.listingCache.at<5)return structuredClone(this.listingCache.value);
        if(!this.listingInFlight){
            const revision=this.revision;
            this.listingInFlight=this.observeListing().then(value=>{if(revision===this.revision)this.listingCache={at:this.clock(),value};return value;}).finally(()=>{this.listingInFlight=undefined;});
        }
        return structuredClone(await this.listingInFlight);
    }
    private async observeListing(){
        const now=this.clock();this.prune(now);
        const common={schema:1,type:'dsmack-native-directory',generatedAt:iso(now),network:{chainId:this.network.chainId,registry:this.network.DemoV1.toLowerCase()},coverage:'explicit-opt-in',freshness:{heartbeatTtlSeconds:TTL,staleRetentionSeconds:RETENTION,receiptFreshnessSeconds:RECEIPT_TTL}};
        if(!this.enabled)return {...common,status:'not-configured',error:{code:'DIRECTORY_DISABLED'},nodes:[]};
        try {
            const head=await this.head();const epoch=await this.read('keyEpochs',[ZERO],head.number);
            const blocks=new Map<bigint,Promise<any>>();
            const nodes=await Promise.all([...this.entries.values()].map(async entry=> {
                const record=structuredClone(entry.record);
                record.checkIn.status=now<Date.parse(record.checkIn.expiresAt)/1000?'fresh':'stale';
                if(entry.receiptBlock){
                    let block=blocks.get(entry.receiptBlock.number);
                    if(!block){block=this.client.getBlock({blockNumber:entry.receiptBlock.number});blocks.set(entry.receiptBlock.number,block!);}
                    if((await block).hash!==entry.receiptBlock.hash)record.sync={scope:record.sync.scope,keyEpoch:record.sync.keyEpoch,groupPublicFingerprint:null,status:'unverified',receiptTransaction:null,receiptCheckedAt:null,receiptBlockTime:null};
                }
                if(record.sync.receiptBlockTime && (now-Date.parse(record.sync.receiptBlockTime)/1000>RECEIPT_TTL||epoch!==entry.epoch))record.sync.status='stale';
                // Account control is rechecked; a later handoff must not leave a verified old owner binding.
                if(record.account.status==='verified') {
                    const generation=await this.read('generation',[],head.number,record.account.address,this.badgeAbi.account);
                    if(generation!==entry.record.accountGeneration)record.account={status:'unavailable',address:null,participantToken:null};
                }
                delete record.accountGeneration;return record;
            }));
            await this.canonical(head);return {...common,status:'available',error:null,nodes};
        } catch {return {...common,status:'unavailable',error:{code:'RPC_UNAVAILABLE'},nodes:[]};}
    }
    checkIn(input:unknown):Promise<unknown>{require(this.pending<16);this.pending++;const operation=this.queue.then(()=>this.accept(input)).catch(()=>{throw new Error('DIRECTORY_INVALID');}).finally(()=>this.pending--);this.queue=operation.catch(()=>{});return operation;}
    private async accept(input:unknown){
        require(this.enabled);const now=this.clock();this.prune(now);const b=validateCheckIn(input,now);
        const kid=toHex(binary(b.keyId,64)),policy=admission(this.network,b);
        const previous=this.entries.get(b.member);require(!previous||now-Date.parse(previous.record.checkIn.lastVerifiedAt)/1000>=5);
        require(previous||this.entries.size<LIMIT);require(this.counters.has(kid)||this.counters.size<256);
        const context=recordContext(this.network,b);const head=await this.head();
        require(await this.read('keyEpochs',[b.scope],head.number)===BigInt(b.keyEpoch));
        require(await this.read('paused',[],head.number)===false);
        const category=await this.read('categories',[policy.category],head.number);
        require(category[0].toLowerCase()===policy.adapter&&category[5]===true);
        const code=await this.client.getBytecode({address:policy.adapter,blockNumber:head.number});require(code&&keccak256(code)===category[1]);
        const revoked=await this.read('members',[b.member],head.number);require(revoked[3]===false);
        require((await this.read('registry',[],head.number,policy.adapter,this.abi.adapter)).toLowerCase()===this.network.DemoV1.toLowerCase());
        require((await this.read('cds',[],head.number,policy.adapter,this.abi.adapter)).toLowerCase()===policy.cds);
        const assertion=decode(binary(b.assertion,14000));require(assertion&&assertion.authenticatorData instanceof Uint8Array&&assertion.signature instanceof Uint8Array);
        const auth=assertion.authenticatorData;require(auth.length>=38);const count=new DataView(auth.buffer,auth.byteOffset,auth.byteLength).getUint32(33,false);require(count>(this.counters.get(kid)?.count??0));
        const [r,s]=signature(assertion.signature);
        const proof=encodeAbiParameters([{type:'bytes32'},{type:'bytes'},{type:'uint256'},{type:'uint256'}],[kid,toHex(auth),r,s]);
        const verified=await this.client.call({account:this.network.DemoV1,to:policy.adapter,data:encodeFunctionData({abi:this.abi.adapter,functionName:'verify',args:[context,proof]}),blockNumber:head.number});
        require(verified.data?.toLowerCase()===encodeAbiParameters([{type:'bytes32'}],[kid]));
        // The deployed canonical parser has already rejected duplicate/unknown/malformed extensions.
        const extensions=decode(auth.slice(37));const cdhash=toHex(extensions.apple_cd_hash_hash_01);hex(cdhash,32);
        // The claimed M is listed only when the measured registry maps the attested CDHash to it.
        if(policy.measured)require(b.measurement!==undefined&&await this.read('measurementOf',[cdhash],head.number,policy.cds,measurementAbi)===b.measurement);
        await crypto.subtle.importKey('raw',buffer(hexToBytes(b.sessionPublic)),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
        let account:any={status:'unavailable',address:null,participantToken:null};
        if(b.account!==null) {
            require(this.network.PersonalBadgeAccountFactory&&this.network.ResearchBadges);
            require(await this.read('isAccount',[b.account],head.number,this.network.PersonalBadgeAccountFactory,this.badgeAbi.factory)===true);
            const generation=await this.read('generation',[],head.number,b.account,this.badgeAbi.account);require(generation===BigInt(b.accountGeneration));
            const x=await this.read('keyX',[],head.number,b.account,this.badgeAbi.account),y=await this.read('keyY',[],head.number,b.account,this.badgeAbi.account);
            // WebCrypto hashes payload once; native signs SHA256(payload) as a RawDigest.
            const consentPayload=join(domain('DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1'),word(this.network.chainId),address(this.network.DemoV1),hexToBytes(b.member),hexToBytes(keccak256(b.sessionPublic)),address(b.account),word(b.accountGeneration),hexToBytes(context));
            require(await verifyP256(toHex(join(new Uint8Array([4]),word(x),word(y))),b.accountSignature!,consentPayload));
            const token=await this.read('participantOf',[b.account],head.number,this.network.ResearchBadges,this.badgeAbi.badges);decimal(token.toString(),(1n<<256n)-1n);
            if(token>0n)require((await this.read('ownerOf',[token],head.number,this.network.ResearchBadges,this.badgeAbi.badges)).toLowerCase()===b.account);
            account={status:'verified',address:b.account,participantToken:token>0n?token.toString():null};
        }
        const receiptState=await this.receipt(b,policy.category,head,now);const sync=receiptState.record;
        await this.canonical(head);
        const verifiedAt=this.clock();require(verifiedAt>=now&&verifiedAt-Number(head.timestamp)<45&&verifiedAt<=b.expiresAt);
        if(sync.receiptBlockTime){sync.receiptCheckedAt=iso(verifiedAt);if(verifiedAt-Date.parse(sync.receiptBlockTime)/1000>RECEIPT_TTL)sync.status='stale';}
        const record={id:keccak256(join(word(this.network.chainId),address(this.network.DemoV1),hexToBytes(b.member))),member:b.member,account,accountGeneration:BigInt(b.accountGeneration),label:b.label??null,version:{selfReported:b.selfReported,buildNumber:b.buildNumber,admittedCodeHash:cdhash,measurement:policy.measured?b.measurement!:null},checkIn:{lastVerifiedAt:iso(verifiedAt),expiresAt:iso(verifiedAt+TTL),status:'fresh'},sync};
        this.counters.set(kid,{count,at:verifiedAt});this.entries.set(b.member,{record,sessionPublic:b.sessionPublic,context,epoch:BigInt(b.keyEpoch),receiptBlock:receiptState.block});
        this.revision++;this.listingCache=undefined;
        return {accepted:true,context,expiresAt:record.checkIn.expiresAt,account:account.address,admittedCodeHash:cdhash,syncStatus:sync.status};
    }
    private async receipt(b:CheckIn,category:Hex,head:any,now:number){
        const result:any={scope:b.scope,keyEpoch:b.keyEpoch,groupPublicFingerprint:null,status:'unverified',receiptTransaction:null,receiptCheckedAt:null,receiptBlockTime:null};
        let canonicalBlock:{number:bigint,hash:Hex}|null=null;
        if(!b.receiptTransaction)return {record:result,block:canonicalBlock};
        try {
            const receipt=await this.client.getTransactionReceipt({hash:b.receiptTransaction});require(receipt.status==='success'&&receipt.blockNumber<=head.number);
            const block=await this.client.getBlock({blockNumber:receipt.blockNumber});require(block.hash===receipt.blockHash&&Number(block.timestamp)<=now+5);
            const tx=await this.client.getTransaction({hash:b.receiptTransaction});require(tx.to?.toLowerCase()===this.network.DemoV1.toLowerCase());
            const decoded=decodeFunctionData({abi:this.abi.demo,data:tx.input});require(decoded.functionName==='execute');const request=(decoded.args as any)[0];
            require(request.action===3&&request.category===category&&request.scope===b.scope&&request.sessionKeyHash===keccak256(b.sessionPublic));
            const epoch=await this.read('keyEpochs',[b.scope],head.number);require(epoch===BigInt(b.keyEpoch));
            const key=await this.read('sharedKeys',[b.scope],head.number);require(key[3]===true&&key[0]===request.keyX&&key[1]===request.keyY);
            const expected=await this.read('contextHash',[request],head.number);
            const logs=receipt.logs.filter((log:any)=>log.address.toLowerCase()===this.network.DemoV1.toLowerCase()).map((log:any)=>{try{return decodeEventLog({abi:this.abi.demo,data:log.data,topics:log.topics});}catch{return null;}});
            const checked=logs.filter((log:any)=>log?.eventName==='Checked'),receipts=logs.filter((log:any)=>log?.eventName==='KeyReceipt');require(checked.length===1&&receipts.length===1);
            const c:any=checked[0]!.args,k:any=receipts[0]!.args;
            require(c.member===b.member&&c.category===category&&c.context===expected&&c.sessionKeyHash===keccak256(b.sessionPublic));
            require(k.member===b.member&&k.scope===b.scope&&k.context===expected&&k.envelopeDigest===request.envelopeDigest);
            result.groupPublicFingerprint='sha256:'+toHex(await digest(join(new Uint8Array([4]),word(key[0]),word(key[1])))).slice(2);
            result.status=now-Number(block.timestamp)<=RECEIPT_TTL?'receipt-verified-current-epoch':'stale';result.receiptTransaction=b.receiptTransaction;result.receiptCheckedAt=iso(now);result.receiptBlockTime=iso(Number(block.timestamp));canonicalBlock={number:receipt.blockNumber,hash:receipt.blockHash};
        } catch { /* A claimed receipt is not promoted when any linkage or RPC check fails. */ }
        return {record:result,block:canonicalBlock};
    }
    leave(input:any):Promise<unknown>{require(this.pending<16);this.pending++;const operation=this.queue.then(async()=>{
        require(this.enabled);const now=this.clock();this.prune(now);require(input&&Object.keys(input).sort().join(',')==='at,context,member,signature');hex(input.member,32);hex(input.context,32);hex(input.signature,64);require(Number.isSafeInteger(input.at)&&input.at>=now-30&&input.at<=now+5);
        const entry=this.entries.get(input.member);require(entry&&entry.context===input.context);
        require(await verifyP256(entry.sessionPublic,input.signature,leavePayload(this.network,input.member,entry.sessionPublic,input.context,input.at)));
        this.entries.delete(input.member);this.revision++;this.listingCache=undefined;return {left:true};
    }).catch(()=>{throw new Error('DIRECTORY_INVALID');}).finally(()=>this.pending--);this.queue=operation.catch(()=>{});return operation;}
}
