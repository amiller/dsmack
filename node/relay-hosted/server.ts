import {NativeDirectory} from "./directory.ts";
import {createPublicClient, http, encodeFunctionData, encodeAbiParameters, keccak256, sha256, toHex, parseAbi, parseTransaction, type Hex, type Address} from "npm:viem@2.38.0";
import {privateKeyToAccount} from "npm:viem@2.38.0/accounts";
import {decode} from "npm:cbor-x@1.6.0/decode-no-eval";

import type {SponsorPolicy} from "./sponsor-policy.ts";
type Context={env:Record<string,string>,dataDir:string,sponsorPolicy?:SponsorPolicy};
type Entry={raw:Hex,hash:Hex,complete:boolean,success?:boolean};
type Mail={at:number,message:Record<string,unknown>};
type State={transactions:Record<string,Entry>,boxes:Record<string,Mail[]>,directories?:{root?:any,nft?:any}};
const abi=JSON.parse(await Deno.readTextFile(new URL('./abi.json',import.meta.url)));
const badgeAbi=JSON.parse(await Deno.readTextFile(new URL('./badge-abi.json',import.meta.url)));
const deployment=JSON.parse(await Deno.readTextFile(new URL('./network.json',import.meta.url)));
let nftDeployment:typeof deployment|undefined;
try {nftDeployment=JSON.parse(await Deno.readTextFile(new URL('./network-nft.json',import.meta.url)));}
catch(e) {if(!(e instanceof Deno.errors.NotFound))throw e;}
// An optional iPhone route shares the NFT network and mailboxes, but has its
// own code registry, attestation profile, and badge/account policy. Legacy field
// aliases below keep transaction construction identical across the routes.
let iosDeployment:typeof deployment|undefined;
try {
    const ios=JSON.parse(await Deno.readTextFile(new URL('./network-ios.json',import.meta.url)));
    iosDeployment={...ios,macCategory:hex(ios.iosCategory,32),macAdapter:hex(ios.iosAdapter,20),macCDRegistry:hex(ios.iosCDRegistry,20)};
} catch(e) {if(!(e instanceof Deno.errors.NotFound))throw e;}
export const measuredAbi=parseAbi(['function measure(bytes cd,bytes page0,bytes ent,uint256 L,uint256 S) pure returns (bytes32)','function isAdmitted(bytes32 m,uint256 blockNumber) view returns (bool)','function measurementOf(bytes32 cdhash) view returns (bytes32)','function register(bytes cd,bytes page0,bytes ent,uint256 L,uint256 S) returns (bytes32)']);
const measuredKeys=['measuredCategory','measuredAdapter','measurementRegistry'];
const response=(body:unknown,status=200)=>Response.json(body,{status});
function need(ok:unknown,message:string):asserts ok {if(!ok)throw new Error(message);}
const relayGasCap=16000000n;
export class SponsorOutOfFunds extends Error {
    override name='SponsorOutOfFunds';
    constructor(readonly needWei:bigint,readonly haveWei:bigint){super('sponsor_out_of_funds');}
    body(){return {error:'sponsor_out_of_funds',needWei:String(this.needWei),haveWei:String(this.haveWei)};}
}
function binary(value:unknown):Uint8Array {need(typeof value==='string' && value.length<64000,'invalid base64');return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
function hex(value:unknown,size?:number):Hex {need(typeof value==='string' && /^0x(?:[0-9a-fA-F]{2})*$/.test(value) && (size===undefined || value.length===2+size*2),'invalid hex');return value as Hex;}
function integer(value:unknown):bigint {need(typeof value==='string'||(typeof value==='number'&&Number.isSafeInteger(value)),'invalid number');const n=BigInt(value);need(n>=0n,'negative number');return n;}
function signature(der:Uint8Array):[bigint,bigint] {
    need(der.length>=8 && der[0]===0x30 && der[1]===der.length-2,'invalid assertion signature');
    let offset=2;
    const scalar=()=>{need(der[offset++]===2,'invalid signature integer');const size=der[offset++];need(size>0&&size<=33&&offset+size<=der.length,'signature extent');const b=der.slice(offset,offset+size);offset+=size;need(b[0]<128 && (b[0]!==0||size===1||b[1]>=128),'noncanonical signature');return BigInt(toHex(b));};
    const r=scalar(),s=scalar();need(offset===der.length,'signature trailing bytes');return [r,s];
}
export class Relay {
    private state:State={transactions:{},boxes:{}};
    private writeQueue:Promise<unknown>=Promise.resolve();
    private txQueue:Promise<unknown>=Promise.resolve();
    private account;
    private client;
    private directory:string;
    private initialized:Promise<void>;
    private readonly sponsorWritesPaused:boolean;
    private readonly sponsorPolicy?:SponsorPolicy;
    private nativeDirectory?:NativeDirectory;
    private rootNativeDirectory?:NativeDirectory;
    constructor(context:Context) {
        this.sponsorWritesPaused=context.env.SPONSOR_WRITES_PAUSED==='true';
        this.sponsorPolicy=context.sponsorPolicy;
        this.account=privateKeyToAccount(hex(context.env.PRIVATE_KEY,32));
        this.client=createPublicClient({transport:http(context.env.RPC_URL || 'https://sepolia.base.org',{timeout:30000,retryCount:1})});
        if(deployment.ResearchBadges&&deployment.PersonalBadgeAccountFactory)this.rootNativeDirectory=new NativeDirectory(this.client,deployment,abi,badgeAbi,context.env.NATIVE_DIRECTORY_ENABLED==='true');
        if(nftDeployment)this.nativeDirectory=new NativeDirectory(this.client,nftDeployment,abi,badgeAbi,context.env.NATIVE_DIRECTORY_ENABLED==='true');
        this.directory=context.dataDir;
        this.initialized=this.load();
    }
    private async load() {
        need([31337,84532].includes(deployment.chainId),'test networks only');
        need(await this.client.getChainId()===deployment.chainId,'wrong chain');
        need(this.account.address.toLowerCase()===deployment.admin.toLowerCase(),'wrong sponsor');
        if(nftDeployment)need(nftDeployment.chainId===deployment.chainId && nftDeployment.admin.toLowerCase()===deployment.admin.toLowerCase(),'NFT route must share chain and sponsor');
        if(iosDeployment) {
            need(nftDeployment,'iPhone route requires NFT network');
            need(iosDeployment.chainId===nftDeployment.chainId
                && iosDeployment.admin.toLowerCase()===nftDeployment.admin.toLowerCase()
                && iosDeployment.DemoV1.toLowerCase()===nftDeployment.DemoV1.toLowerCase(),
                'iPhone route must share NFT chain, sponsor and registry');
            for(const field of ['macCategory','macAdapter','macCDRegistry'])
                need(iosDeployment[field].toLowerCase()!==nftDeployment[field].toLowerCase(),'iPhone route requires a separate admission policy');
        }
        // A measured admission policy (MeasurementRegistry + AppleAttestMeasuredV1) runs beside the legacy category.
        for(const network of [deployment,nftDeployment].filter(Boolean)) {
            const present=measuredKeys.filter(k=>network[k]!==undefined);
            need(present.length===0||present.length===3,'measured admission needs '+measuredKeys.join(', '));
            if(present.length)need(network.measuredCategory.toLowerCase()!==network.macCategory.toLowerCase()&&network.measuredAdapter.toLowerCase()!==network.macAdapter.toLowerCase(),'measured admission requires a separate category and adapter');
        }
        await Deno.mkdir(this.directory,{recursive:true});
        try {this.state=JSON.parse(await Deno.readTextFile(this.directory+'/state.json'));}
        catch(e) {if(!(e instanceof Deno.errors.NotFound))throw e;}
        // State files written before the directory was persisted have no directories key.
        if(this.state.directories?.root)this.rootNativeDirectory!.restore(this.state.directories.root);
        if(this.state.directories?.nft)this.nativeDirectory!.restore(this.state.directories.nft);
    }
    private saveDirectories() {this.state.directories={root:this.rootNativeDirectory?.snapshot(),nft:this.nativeDirectory?.snapshot()};return this.save();}
    private save() {
        const content=JSON.stringify(this.state);
        const operation=this.writeQueue.then(async()=>{
            const path=this.directory+'/state.tmp';
            const f=await Deno.open(path,{write:true,create:true,truncate:true,mode:0o600});
            try {const bytes=new TextEncoder().encode(content);let n=0;while(n<bytes.length)n+=await f.write(bytes.subarray(n));await f.sync();}finally{f.close();}
            await Deno.rename(path,this.directory+'/state.json');
        });
        this.writeQueue=operation.catch(()=>{});return operation;
    }
    private async settle(entry:Entry):Promise<Hex> {
        if(!entry.complete)await this.sponsorPolicy?.reconcile(entry.raw);
        if(entry.complete){need(entry.success===true,"transaction reverted");return entry.hash;}
        let receipt;
        try {receipt=await this.client.getTransactionReceipt({hash:entry.hash});}catch { /* May not have been sent yet. */ }
        if(!receipt) {
            try {await this.client.sendRawTransaction({serializedTransaction:entry.raw});}catch(e) {
                const details=e as {shortMessage?:string,details?:string};
                const message=String(details.details||details.shortMessage||'submission failed');
                const transaction=parseTransaction(entry.raw);
                console.error('Transaction submission result',JSON.stringify({hash:entry.hash,gas:transaction.gas?.toString(),message:message.slice(0,400)}));
                // Repair only this explicit sequencer rejection, retaining destination,
                // calldata and nonce. A replacement cannot execute twice at one nonce.
                if(deployment.chainId===84532 && message.toLowerCase().includes('gas limit too high') && transaction.type==='legacy' && transaction.gas!>16000000n) {
                    const estimate=await this.client.estimateGas({account:this.account,to:transaction.to!,data:transaction.data});
                    need(estimate<=16000000n,'enrollment exceeds relay gas cap');
                    await this.sponsorPolicy?.reserve({id:keccak256((transaction.to!.toLowerCase()+transaction.data!.slice(2)) as Hex),to:transaction.to!,data:transaction.data!,nonce:transaction.nonce!,gas:estimate+estimate/10n>16000000n?16000000n:estimate+estimate/10n,gasPrice:transaction.gasPrice!});
                    entry.raw=await this.account.signTransaction({type:'legacy',chainId:deployment.chainId,to:transaction.to!,data:transaction.data,nonce:transaction.nonce!,gas:estimate+estimate/10n>16000000n?16000000n:estimate+estimate/10n,gasPrice:transaction.gasPrice!});
                    entry.hash=keccak256(entry.raw);await this.save();
                    return await this.settle(entry);
                }
                // Already known/mined is resolved by the receipt below.
            }
            receipt=await this.client.waitForTransactionReceipt({hash:entry.hash,timeout:90000,pollingInterval:1000});
        }
        // Persist the terminal state even on revert, so it cannot block later requests.
        if(deployment.chainId===84532)await new Promise(resolve=>setTimeout(resolve,4000));
        entry.complete=true;entry.success=receipt.status==='success';await this.save();
        need(receipt.status==='success','transaction reverted');return entry.hash;
    }
    private transact(to:Address,data:Hex):Promise<Hex> {
        const operation=this.txQueue.then(async()=>{
            need(!this.sponsorWritesPaused,'sponsor maintenance; retry shortly');
            const id=keccak256((to.toLowerCase()+data.slice(2)) as Hex);
            if(this.state.transactions[id])return await this.settle(this.state.transactions[id]);
            for(const entry of Object.values(this.state.transactions))if(!entry.complete)await this.settle(entry);
            need(Object.keys(this.state.transactions).length<10000,'relay transaction journal full');
            const gas=await this.client.estimateGas({account:this.account,to,data});
            const nonce=await this.client.getTransactionCount({address:this.account.address,blockTag:'pending'});
            const gasPrice=await this.gasPrice();
            need(deployment.chainId!==84532 || gas<=relayGasCap,'enrollment exceeds relay gas cap');
            const limit=deployment.chainId===84532 && gas+gas/10n>relayGasCap?relayGasCap:gas+gas/10n;
            const haveWei=await this.client.getBalance({address:this.account.address});
            if(haveWei<limit*gasPrice)throw new SponsorOutOfFunds(limit*gasPrice,haveWei);
            await this.sponsorPolicy?.reserve({id,to,data,nonce,gas:limit,gasPrice});
            const raw=await this.account.signTransaction({chainId:deployment.chainId,to,data,nonce,gas:limit,gasPrice,type:'legacy'});
            const entry={raw,hash:keccak256(raw),complete:false};this.state.transactions[id]=entry;
            // The exact signed transaction is durable BEFORE submission; retries reuse it.
            await this.save();return await this.settle(entry);
        });
        this.txQueue=operation.catch(()=>{});return operation;
    }
    private async gasPrice() {
        const observed=await this.client.getGasPrice();
        return this.sponsorPolicy?.gasPrice?this.sponsorPolicy.gasPrice(observed):observed*2n;
    }
    private measured(network:typeof deployment,category:unknown):boolean {
        const c=hex(category,32).toLowerCase();
        if(c===network.measuredCategory?.toLowerCase())return true;
        need(c===network.macCategory.toLowerCase(),'unknown category');return false;
    }
    /** MeasurementRegistry.register before enroll, once per CDHash; refuses a measurement outside its window. */
    private async registerMeasurement(network:typeof deployment,body:any,authData:Uint8Array) {
        need(['cd','page0','ent','L','S'].every(k=>body[k]!==undefined),'enrollment requires the code measurement {cd,page0,ent,L,S}');
        const cd=toHex(binary(body.cd)),page0=toHex(binary(body.page0)),ent=toHex(binary(body.ent)),L=integer(body.L),S=integer(body.S);
        need(page0.length===2+16384*2,'measurement page0');
        // Extensions follow the 164-byte attested-credential prefix the adapter requires (AppleAuthData.check).
        need(authData.length>164,'attestation authData');const attested=decode(authData.subarray(164))?.apple_cd_hash_hash_01;
        need(attested instanceof Uint8Array&&toHex(attested)===sha256(cd),'code measurement is not of the attested CDHash');
        const address=network.measurementRegistry as Address;
        let m:Hex;try {m=await this.client.readContract({address,abi:measuredAbi,functionName:'measure',args:[cd,page0,ent,L,S]});}catch {throw new Error('invalid code measurement');}
        need(await this.client.readContract({address,abi:measuredAbi,functionName:'isAdmitted',args:[m,await this.client.getBlockNumber()]}),'build not admitted');
        if(await this.client.readContract({address,abi:measuredAbi,functionName:'measurementOf',args:[sha256(cd)]})!==m)
            await this.transact(network.measurementRegistry,encodeFunctionData({abi:measuredAbi,functionName:'register',args:[cd,page0,ent,L,S]}));
    }
    private networkRequest(r:any,network:typeof deployment) {
        need(r&&[0,2,3].includes(r.action),'unsupported action');
        this.measured(network,r.category);
        need(r.owner?.toLowerCase()===this.account.address.toLowerCase()&&r.memberSigner?.toLowerCase()===this.account.address.toLowerCase(),'wrong owner');
        return {action:r.action,category:hex(r.category,32),owner:this.account.address,memberSigner:this.account.address,sessionKeyHash:hex(r.sessionKeyHash,32),nonce:integer(r.nonce),validUntil:integer(r.validUntil),scope:hex(r.scope,32),keyX:integer(r.keyX),keyY:integer(r.keyY),envelopeDigest:hex(r.envelopeDigest,32)};
    }
    async handle(request:Request) {
        await this.initialized;
        const incoming=new URL(request.url).pathname.replace(/\/$/,'');
        const ios=incoming==='/ios'||incoming.startsWith('/ios/');
        const nft=incoming==='/nft'||incoming.startsWith('/nft/');
        if(ios&&!iosDeployment)return response({error:'iPhone route not configured'},404);
        if(nft&&!nftDeployment)return response({error:'NFT route not configured'},404);
        const selected=ios?iosDeployment:nft?nftDeployment:deployment;
        const path=(ios||nft)?incoming.slice(4):incoming;
        const mailboxPrefix=(ios||nft)?'nft:':'';
        const nativeDirectory=nft?this.nativeDirectory:ios?undefined:this.rootNativeDirectory;
        if(path==='/directory'&&request.method==='GET'){if(!nativeDirectory)return response({error:'directory route not configured'},404);const result=response(await nativeDirectory.listing());result.headers.set('Access-Control-Allow-Origin','*');result.headers.set('Cache-Control','no-store');return result;}
        if(request.method==='GET' && ['/info','/_warmup'].includes(path))return response({owner:this.account.address,chainId:selected.chainId,registry:selected.DemoV1,protocolVersion:2});
        if(request.method==='GET' && path==='/status'){const status=response({generatedAt:new Date().toISOString(),chainId:selected.chainId,registry:selected.DemoV1,protocolVersion:2,sponsorWritesPaused:this.sponsorWritesPaused,sponsorBudget:await this.sponsorPolicy?.status?.(),sponsor:{address:this.account.address,balanceWei:String(await this.client.getBalance({address:this.account.address})),enrollCostWei:String(relayGasCap*await this.gasPrice())},pending:Object.values(this.state.transactions).filter(e=>!e.complete).map(e=>({hash:e.hash,gas:parseTransaction(e.raw).gas?.toString()})),completed:Object.values(this.state.transactions).filter(e=>e.complete).length});status.headers.set('Cache-Control','no-store');status.headers.set('Access-Control-Allow-Origin','*');return status;}
        if(request.method==='GET' && path.startsWith('/recv/')) {
            const name=path.slice(6);need(/^[a-zA-Z0-9_-]{1,80}$/.test(name),'invalid mailbox');
            const dequeue=async()=>{
                const queue=(this.state.boxes[mailboxPrefix+name]||[]).filter(x=>Date.now()-x.at<120000);
                let entry=queue.shift();const hadEntry=!!entry;
                while(entry&&this.sponsorPolicy?.allowMail){try{await this.sponsorPolicy.allowMail(mailboxPrefix+name,entry.message,'deliver');break;}catch{entry=queue.shift();}}
                if(queue.length)this.state.boxes[mailboxPrefix+name]=queue;else delete this.state.boxes[mailboxPrefix+name];
                if(hadEntry)await this.save();return response({message:entry?.message||null});
            };
            if(this.sponsorPolicy){const operation=this.txQueue.then(dequeue);this.txQueue=operation.catch(()=>{});return await operation;}
            return await dequeue();
        }
        need(request.method==='POST','unknown route');
        const reader=request.body?.getReader();need(reader,'missing request body');let raw='';let size=0;const decoder=new TextDecoder();
        while(true){const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.length;if(size>65536){await reader.cancel();throw new Error('request too large');}raw+=decoder.decode(chunk.value,{stream:true});}raw+=decoder.decode();
        const body=JSON.parse(raw);
        if(path==='/directory/check-in'){need(nativeDirectory&&size<=16384,'DIRECTORY_INVALID');const result=await nativeDirectory.checkIn(body);await this.saveDirectories();return response(result);}
        if(path==='/directory/leave'){need(nativeDirectory&&size<=4096,'DIRECTORY_INVALID');const result=await nativeDirectory.leave(body);await this.saveDirectories();return response(result);}
        if(path.startsWith('/send/')) {
            const name=path.slice(6);need(/^[a-zA-Z0-9_-]{1,80}$/.test(name),'invalid mailbox');
            need(size<=8192 && typeof body.from==='string' && /^[a-zA-Z0-9_-]{1,80}$/.test(body.from),'invalid message');
            need(['HELLO','PARCEL','PROOF','ERROR','HEARTBEAT'].includes(body.type),'unsupported message type');
            const enqueue=async()=>{
                await this.sponsorPolicy?.allowMail?.(mailboxPrefix+name,body,'enqueue');
                for(const [key,items] of Object.entries(this.state.boxes)){const live=items.filter(x=>Date.now()-x.at<120000);if(live.length)this.state.boxes[key]=live;else delete this.state.boxes[key];}
                need(this.state.boxes[mailboxPrefix+name]||Object.keys(this.state.boxes).length<500,'mailbox limit');
                const queue=this.state.boxes[mailboxPrefix+name]||[];need(queue.length<32,'mailbox full');queue.push({at:Date.now(),message:body});this.state.boxes[mailboxPrefix+name]=queue;await this.save();return response({queued:queue.length});
            };
            if(this.sponsorPolicy){const operation=this.txQueue.then(enqueue);this.txQueue=operation.catch(()=>{});return await operation;}
            return await enqueue();
        }
        if(path==='/enroll') {
            const measured=this.measured(selected,body.category);
            const evidence=decode(binary(body.attestation));
            const data=encodeFunctionData({abi:abi.adapter,functionName:'enroll',args:[toHex(evidence.attStmt.x5c[0]),toHex(evidence.authData),hex(body.clientData,32)]});
            if(measured)await this.registerMeasurement(selected,body,evidence.authData);
            return response({tx:await this.transact(measured?selected.measuredAdapter:selected.macAdapter,data)});
        }
        if(path==='/register-build') {
            need(selected.ResearchBadges&&selected.PersonalBadgeAccountFactory,'NFT builder registration not enabled');
            const cd=hex(body.cd),page0=hex(body.page0,16384),ent=hex(body.ent);
            need(cd.length<=32770&&ent.length<=8194,'build registration size');
            const data=encodeFunctionData({abi:badgeAbi.registry,functionName:'registerBuild',args:[cd,page0,ent]});
            return response({tx:await this.transact(selected.macCDRegistry,data)});
        }
        if(['/personal-account','/badge-claim','/account-handoff'].includes(path)) {
            need(selected.ResearchBadges&&selected.PersonalBadgeAccountFactory,'NFT claims not enabled');
            if(path==='/personal-account') {
                const data=encodeFunctionData({abi:badgeAbi.factory,functionName:'createForMember',args:[integer(body.x),integer(body.y),hex(body.keyId,32),this.networkRequest(body.request,selected)]});
                return response({tx:await this.transact(selected.PersonalBadgeAccountFactory,data)});
            }
            if(path==='/account-handoff') {
                const target=hex(body.account,20);
                need(await this.client.readContract({address:selected.PersonalBadgeAccountFactory,abi:badgeAbi.factory,functionName:'isAccount',args:[target]}),'unknown personal account');
                need((await this.client.readContract({address:selected.ResearchBadges,abi:badgeAbi.badges,functionName:'participantOf',args:[target]}) as bigint)>0n,'account has no participant NFT');
                const data=encodeFunctionData({abi:badgeAbi.account,functionName:'handoff',args:[integer(body.x),integer(body.y),integer(body.deadline),hex(body.oldSignature,64),hex(body.newSignature,64)]});
                return response({tx:await this.transact(target,data)});
            }
            const c=body.claim;need(c&&[1,2].includes(c.level),'invalid badge level');
            const claim={recipient:hex(c.recipient,20),keyId:hex(c.keyId,32),level:c.level,parent:integer(c.parent),deadline:integer(c.deadline)};
            const data=encodeFunctionData({abi:badgeAbi.badges,functionName:'claim',args:[claim,this.networkRequest(body.request,selected),hex(body.recipientSignature)]});
            return response({tx:await this.transact(selected.ResearchBadges,data)});
        }
        if(path==='/execute') {
            const value=this.networkRequest(body.request,selected);
            const context=await this.client.readContract({address:selected.DemoV1,abi:abi.demo,functionName:'contextHash',args:[value]}) as Hex;
            need(context.toLowerCase()===hex(body.context,32).toLowerCase(),'request context mismatch');
            const assertion=decode(binary(body.assertion));const [x,y]=signature(assertion.signature);
            const kid=binary(body.keyId);need(kid.length===32,'invalid key ID');
            const proof=encodeAbiParameters([{type:'bytes32'},{type:'bytes'},{type:'uint256'},{type:'uint256'}],[toHex(kid),toHex(assertion.authenticatorData),x,y]);
            const memberSignature=await this.account.signMessage({message:{raw:context}});
            const data=encodeFunctionData({abi:abi.demo,functionName:'execute',args:[value,proof,memberSignature,hex(body.groupSignature)]});
            return response({tx:await this.transact(selected.DemoV1,data)});
        }
        return response({error:'unknown route'},404);
    }
}
let relay:Relay|undefined;
export default async function handler(request:Request,context:Context) {
    try {relay ??= new Relay(context);return await relay.handle(request);}
    catch(e) {
        if(e instanceof SponsorOutOfFunds){console.error('Relay sponsor out of funds:',JSON.stringify(e.body()));return response(e.body(),503);}
        console.error('Relay request failed:',e instanceof Error?e.name:'unknown');return response({error:e instanceof Error && e.name==='Error'?e.message:'relay transaction unavailable; retry'},503);}
}
if(import.meta.main) {
    const context={env:Deno.env.toObject(),dataDir:Deno.env.get('RELAY_DATA')||'./relay-data'};
    Deno.serve({hostname:'127.0.0.1',port:Number(Deno.env.get('PORT')||18577)},r=>handler(r,context));
}
