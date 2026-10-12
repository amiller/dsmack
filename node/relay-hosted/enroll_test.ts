// Relay enrollment against a fake JSON-RPC: the measured category registers M before enroll.
import {privateKeyToAccount} from "npm:viem@2.38.0/accounts";
import {decodeFunctionData,encodeFunctionResult,hexToBytes,keccak256,parseTransaction,sha256,toHex,type Hex} from "npm:viem@2.38.0";
import {encode} from "npm:cbor-x@1.6.0";
const key='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const abi=JSON.parse(await Deno.readTextFile(new URL('./abi.json',import.meta.url)));
const check=(ok:unknown,message:string)=>{if(!ok)throw new Error(message);};
const h=(n:string,size=32)=>('0x'+n.repeat(size)) as Hex;
const M=h('9a'),measured={measuredCategory:h('23'),measuredAdapter:h('34',20),measurementRegistry:h('45',20)};
const b64=(v:Uint8Array)=>btoa(String.fromCharCode(...v));
const blobs={cd:b64(new Uint8Array(400).fill(1)),page0:b64(new Uint8Array(16384)),ent:b64(new Uint8Array(90).fill(2)),L:1000,S:1200};
const attest=(cd:string)=>b64(encode({attStmt:{x5c:[new Uint8Array([1,2,3])]},authData:new Uint8Array([...new Uint8Array(164),...encode({apple_cd_hash_hash_01:hexToBytes(sha256(Uint8Array.from(atob(cd),c=>c.charCodeAt(0))))})])}));
const attestation=attest(blobs.cd);

async function relay(mode:'legacy'|'measured',chain:{admitted:boolean,registered:boolean}) {
    const {measuredAbi}=await import('./server.ts');
    const sent:{to:string,fn:string}[]=[],calls:string[]=[],mined=new Set<string>();
    const rpc=Deno.serve({hostname:'127.0.0.1',port:0,onListen:()=>{}},async request=>{
        const {id,method,params}=await request.json();
        const result=(r:unknown)=>Response.json({jsonrpc:'2.0',id,result:r});
        if(method==='eth_chainId')return result('0x7a69');
        if(method==='eth_blockNumber')return result('0x64');
        if(method==='eth_call'){
            const {functionName,args}=decodeFunctionData({abi:measuredAbi,data:params[0].data});calls.push(functionName);
            check(params[0].to.toLowerCase()===measured.measurementRegistry,'read outside the measurement registry');
            const value=functionName==='measure'?M:functionName==='isAdmitted'?(chain.admitted&&args[0]===M&&args[1]===100n):chain.registered?M:h('00');
            return result(encodeFunctionResult({abi:measuredAbi,functionName,result:value as never}));
        }
        if(method==='eth_estimateGas')return result('0x5208');
        if(method==='eth_getBlockByNumber')return result({number:'0x64',hash:h('bc'),parentHash:h('bb'),timestamp:'0x1',baseFeePerGas:'0x1',gasLimit:'0x1c9c380',gasUsed:'0x0',transactions:[]});
        if(method==='eth_getTransactionCount')return result(toHex(sent.length));
        if(['eth_gasPrice','eth_maxPriorityFeePerGas'].includes(method))return result('0x1');
        if(method==='eth_sendRawTransaction'){
            const tx=parseTransaction(params[0]);
            const fn=tx.to===measured.measurementRegistry?decodeFunctionData({abi:measuredAbi,data:tx.data!}).functionName:decodeFunctionData({abi:abi.adapter,data:tx.data!}).functionName;
            sent.push({to:tx.to!,fn});mined.add(keccak256(params[0]));return result(keccak256(params[0]));
        }
        if(method==='eth_getTransactionReceipt'){
            if(!mined.has(params[0]))return result(null);
            return result({transactionHash:params[0],status:'0x1',blockNumber:'0x64',blockHash:h('bc'),transactionIndex:'0x0',from:privateKeyToAccount(key).address,to:null,cumulativeGasUsed:'0x5208',gasUsed:'0x5208',effectiveGasPrice:'0x1',logs:[],logsBloom:'0x'+'00'.repeat(256),type:'0x0',contractAddress:null});
        }
        throw new Error('unexpected RPC '+method);
    });
    const directory=await Deno.makeTempDir();
    for(const name of ['server.ts','directory.ts','abi.json','badge-abi.json'])await Deno.copyFile(new URL(name,import.meta.url),directory+'/'+name);
    const network=JSON.parse(await Deno.readTextFile(new URL('network.json',import.meta.url)));
    network.chainId=31337;network.admin=privateKeyToAccount(key).address;
    await Deno.writeTextFile(directory+'/network.json',JSON.stringify(mode==='measured'?{...network,...measured}:network));
    const {default:handler}=await import('file://'+directory+'/server.ts');
    const context={env:{PRIVATE_KEY:key,RPC_URL:'http://127.0.0.1:'+rpc.addr.port},dataDir:directory+'/data'};
    const enroll=async(body:Record<string,unknown>)=>await (await handler(new Request('http://relay/enroll',{method:'POST',body:JSON.stringify({attestation,clientData:h('cd'),...body})}),context)).json();
    return {network,sent,calls,enroll,async close(){await rpc.shutdown();await Deno.remove(directory,{recursive:true});}};
}

Deno.test('measured category: register M before enroll, through the measured adapter',async()=>{
    const r=await relay('measured',{admitted:true,registered:false});
    try {
        const body=await r.enroll({category:measured.measuredCategory,...blobs});
        check(body.tx,'enroll failed: '+JSON.stringify(body));
        check(JSON.stringify(r.sent)===JSON.stringify([{to:measured.measurementRegistry,fn:'register'},{to:measured.measuredAdapter,fn:'enroll'}]),'order '+JSON.stringify(r.sent));
        check(r.calls.join()==='measure,isAdmitted,measurementOf','reads '+r.calls.join());
    } finally {await r.close();}
});
Deno.test('measured category: an already registered CDHash enrolls without a second register',async()=>{
    const r=await relay('measured',{admitted:true,registered:true});
    try {
        check((await r.enroll({category:measured.measuredCategory,...blobs})).tx,'enroll failed');
        check(r.sent.length===1&&r.sent[0].fn==='enroll','re-registered '+JSON.stringify(r.sent));
    } finally {await r.close();}
});
Deno.test('measured category: refuses "build not admitted" and missing measurement, sends nothing',async()=>{
    const r=await relay('measured',{admitted:false,registered:false});
    try {
        check((await r.enroll({category:measured.measuredCategory,...blobs})).error==='build not admitted','admitted a closed window');
        check((await r.enroll({category:measured.measuredCategory})).error==='enrollment requires the code measurement {cd,page0,ent,L,S}','enrolled without M');
        check((await r.enroll({category:measured.measuredCategory,...blobs,page0:blobs.ent})).error==='measurement page0','short page0 accepted');
        check((await r.enroll({category:measured.measuredCategory,...blobs,attestation:attest(blobs.ent)})).error==='code measurement is not of the attested CDHash','registered a CodeDirectory the attestation does not name');
        check(r.sent.length===0,'sent '+JSON.stringify(r.sent));
    } finally {await r.close();}
});
Deno.test('legacy category beside measured, and legacy-only network: enroll unchanged, no registry reads',async()=>{
    for(const mode of ['measured','legacy'] as const){
        const r=await relay(mode,{admitted:false,registered:false});
        try {
            check((await r.enroll({category:r.network.macCategory,...blobs})).tx,'legacy enroll failed');
            check(r.sent.length===1&&r.sent[0].to.toLowerCase()===r.network.macAdapter.toLowerCase()&&r.calls.length===0,mode+' '+JSON.stringify(r.sent));
            if(mode==='legacy')check((await r.enroll({category:measured.measuredCategory,...blobs})).error==='unknown category','measured category without configuration');
        } finally {await r.close();}
    }
});
Deno.test('measured configuration must be complete and separate',async()=>{
    for(const bad of [(_:any)=>({measuredAdapter:measured.measuredAdapter}),(n:any)=>({...measured,measuredCategory:n.macCategory})]){
        const directory=await Deno.makeTempDir();
        try {
            for(const name of ['server.ts','directory.ts','abi.json','badge-abi.json'])await Deno.copyFile(new URL(name,import.meta.url),directory+'/'+name);
            const network=JSON.parse(await Deno.readTextFile(new URL('network.json',import.meta.url)));network.chainId=31337;network.admin=privateKeyToAccount(key).address;
            await Deno.writeTextFile(directory+'/network.json',JSON.stringify({...network,...bad(network)}));
            const rpc=Deno.serve({hostname:'127.0.0.1',port:0,onListen:()=>{}},async request=>Response.json({jsonrpc:'2.0',id:(await request.json()).id,result:'0x7a69'}));
            const {default:handler}=await import('file://'+directory+'/server.ts');
            const body=await (await handler(new Request('http://relay/info'),{env:{PRIVATE_KEY:key,RPC_URL:'http://127.0.0.1:'+rpc.addr.port},dataDir:directory+'/data'})).json();
            await rpc.shutdown();
            check(/^measured admission/.test(body.error),'accepted bad config: '+JSON.stringify(body));
        } finally {await Deno.remove(directory,{recursive:true});}
    }
});
