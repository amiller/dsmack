import {privateKeyToAccount} from "npm:viem@2.38.0/accounts";
import {toHex,type Hex} from "npm:viem@2.38.0";

Deno.test('iPhone and Mac share NFT mailboxes with separate admission; legacy stays isolated',async()=>{
    // Public Anvil fixture key, never a deployed sponsor credential.
    const key='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    const directory=await Deno.makeTempDir();
    const rpc=Deno.serve({hostname:'127.0.0.1',port:0,onListen:()=>{}},async request=>{
        const value=await request.json();
        const results:Record<string,string>={eth_chainId:'0x7a69',eth_getBalance:'0x64',eth_gasPrice:'0x1'};
        if(!results[value.method])throw new Error('Unexpected RPC call: '+value.method);
        return Response.json({jsonrpc:'2.0',id:value.id,result:results[value.method]});
    });
    const check=(condition:unknown,message:string)=>{if(!condition)throw new Error(message);};
    try {
        for(const name of ['server.ts','directory.ts','abi.json','badge-abi.json'])
            await Deno.copyFile(new URL(name,import.meta.url),directory+'/'+name);
        const fixture=JSON.parse(await Deno.readTextFile(new URL('network.json',import.meta.url)));
        fixture.chainId=31337;fixture.admin=privateKeyToAccount(key).address;
        delete fixture.ResearchBadges;delete fixture.PersonalBadgeAccountFactory;
        const nft={...fixture,DemoV1:'0x1111111111111111111111111111111111111111',macCategory:'0x'+'22'.repeat(32),ResearchBadges:'0x3333333333333333333333333333333333333333',PersonalBadgeAccountFactory:'0x4444444444444444444444444444444444444444'};
        const ios={...nft,iosCategory:'0x'+'66'.repeat(32),iosAdapter:'0x'+'77'.repeat(20),iosCDRegistry:'0x'+'88'.repeat(20)};
        await Deno.writeTextFile(directory+'/network-ios.json',JSON.stringify(ios));
        await Deno.writeTextFile(directory+'/network.json',JSON.stringify(fixture));
        await Deno.writeTextFile(directory+'/network-nft.json',JSON.stringify(nft));
        const dataDir=directory+'/data';await Deno.mkdir(dataDir);
        await Deno.writeTextFile(dataDir+'/state.json',JSON.stringify({transactions:{retained:{raw:'0x',hash:'0x'+'55'.repeat(32),complete:true,success:true}},boxes:{}}));
        const {default:handler}=await import('file://'+directory+'/server.ts');
        const context={env:{PRIVATE_KEY:key,RPC_URL:'http://127.0.0.1:'+rpc.addr.port},dataDir};
        const call=async(path:string,body?:unknown)=>{
            const result=await handler(new Request('http://relay'+path,body===undefined?{}:{method:'POST',body:JSON.stringify(body)}),context);
            return {status:result.status,body:await result.json()};
        };
        check((await call('/info')).body.registry===fixture.DemoV1,'legacy network changed');
        check((await call('/nft/info')).body.registry===nft.DemoV1,'NFT network missing');
        check((await call('/ios/info')).body.registry===nft.DemoV1,'iPhone registry diverged');
        check((await call('/ios/status')).body.completed===1,'iPhone sponsor journal not shared');
        check((await call('/status')).body.completed===1,'existing journal lost');
        check((await call('/nft/status')).body.sponsor.balanceWei==='100','sponsor balance missing from status');
        check((await call('/nft/status')).body.completed===1,'sponsor journal not shared');
        await call('/send/same-name',{from:'old',type:'HELLO'});
        await call('/nft/send/same-name',{from:'new',type:'HELLO'});
        check((await call('/recv/same-name')).body.message.from==='old','legacy mailbox crossed networks');
        check((await call('/nft/recv/same-name')).body.message.from==='new','NFT mailbox crossed networks');
        await call('/nft/send/seed-b',{from:'seed-a',type:'HEARTBEAT',keyEpoch:1,holds:true});
        check((await call('/nft/recv/seed-b')).body.message.holds===true,'seed heartbeat not relayed');
        check((await call('/nft/send/seed-b',{from:'seed-a',type:'GOSSIP'})).body.error==='unsupported message type','unknown mail type accepted');
        check((await call('/nft/enroll',{category:fixture.macCategory})).body.error==='unknown category','NFT route accepted legacy category');
        check((await call('/enroll',{category:nft.macCategory})).body.error==='unknown category','legacy route accepted NFT category');
        await call('/ios/send/release-nft-seed',{from:'iphone',type:'HELLO'});
        check((await call('/nft/recv/release-nft-seed')).body.message.from==='iphone','Mac seed cannot receive iPhone hello');
        await call('/nft/send/iphone',{from:'release-nft-seed',type:'PARCEL'});
        check((await call('/ios/recv/iphone')).body.message.from==='release-nft-seed','iPhone cannot receive Mac parcel');
        check((await call('/recv/iphone')).body.message===null,'legacy route saw NFT parcel');
        check((await call('/ios/enroll',{category:nft.macCategory})).body.error==='unknown category','iPhone route accepted Mac category');
        check((await call('/nft/enroll',{category:ios.iosCategory})).body.error==='unknown category','Mac route accepted iPhone category');
        check((await call('/badge-claim',{})).body.error==='NFT claims not enabled','legacy NFT route enabled');
    } finally {
        await rpc.shutdown();
        await Deno.remove(directory,{recursive:true});
    }
});

for(const mode of ['absent','wrong-registry','wrong-sponsor','reused-category','maintenance']) {
    Deno.test('iPhone route configuration guard: '+mode,async()=>{
        const key='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
        const directory=await Deno.makeTempDir();
        const rpc=Deno.serve({hostname:'127.0.0.1',port:0,onListen:()=>{}},async request=>{
            const value=await request.json();
            const results:Record<string,string>={eth_chainId:'0x7a69',eth_getBalance:'0x64',eth_gasPrice:'0x1'};
            if(!results[value.method])throw new Error('Unexpected RPC call: '+value.method);
            return Response.json({jsonrpc:'2.0',id:value.id,result:results[value.method]});
        });
        try {
            for(const name of ['server.ts','directory.ts','abi.json','badge-abi.json'])
                await Deno.copyFile(new URL(name,import.meta.url),directory+'/'+name);
            const base=JSON.parse(await Deno.readTextFile(new URL('network.json',import.meta.url)));
            base.chainId=31337;base.admin=privateKeyToAccount(key).address;
            await Deno.writeTextFile(directory+'/network.json',JSON.stringify(base));
            await Deno.writeTextFile(directory+'/network-nft.json',JSON.stringify(base));
            const ios={...base,ResearchBadges:'0x'+'aa'.repeat(20),PersonalBadgeAccountFactory:'0x'+'bb'.repeat(20),iosCategory:'0x'+'66'.repeat(32),iosAdapter:'0x'+'77'.repeat(20),iosCDRegistry:'0x'+'88'.repeat(20)};
            if(mode==='wrong-registry')ios.DemoV1='0x'+'99'.repeat(20);
            if(mode==='wrong-sponsor')ios.admin='0x'+'99'.repeat(20);
            if(mode==='reused-category')ios.iosCategory=base.macCategory;
            if(mode!=='absent')await Deno.writeTextFile(directory+'/network-ios.json',JSON.stringify(ios));
            const {default:handler}=await import('file://'+directory+'/server.ts');
            const context={env:{PRIVATE_KEY:key,RPC_URL:'http://127.0.0.1:'+rpc.addr.port,SPONSOR_WRITES_PAUSED:mode==='maintenance'?'true':'false'},dataDir:directory+'/data'};
            if(mode==='maintenance') {
                const status=await (await handler(new Request('http://relay/status'),context)).json();
                if(status.sponsorWritesPaused!==true)throw new Error('Maintenance not visible');
                const registration=new Request('http://relay/ios/register-build',{method:'POST',body:JSON.stringify({cd:'0x01',page0:'0x'+'00'.repeat(16384),ent:'0x01'})});
                const result=await handler(registration,context);const body=await result.json();
                if(body.error!=='sponsor maintenance; retry shortly')throw new Error('Write was not blocked: '+JSON.stringify(body));
                const after=await (await handler(new Request('http://relay/status'),context)).json();
                if(after.pending.length||after.completed)throw new Error('Maintenance created a journal entry');
                return;
            }
            const result=await handler(new Request('http://relay/ios/info'),context);
            const body=await result.json();
            const expected=mode==='absent'?'iPhone route not configured':mode==='reused-category'?'iPhone route requires a separate admission policy':'iPhone route must share NFT chain, sponsor and registry';
            if(result.status!==(mode==='absent'?404:503)||body.error!==expected)
                throw new Error('Unexpected configuration guard: '+JSON.stringify(body));
        } finally {await rpc.shutdown();await Deno.remove(directory,{recursive:true});}
    });
}

Deno.test('directory check-in list is restored from and written to the state file',async()=>{
    const key='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    const directory=await Deno.makeTempDir(),now=Math.floor(Date.now()/1000);
    const block={number:'0x64',hash:'0x'+'bc'.repeat(32),parentHash:'0x'+'00'.repeat(32),timestamp:toHex(now),transactions:[],gasLimit:'0x1',gasUsed:'0x0',logsBloom:'0x'+'00'.repeat(256),miner:'0x'+'00'.repeat(20),extraData:'0x',size:'0x1',difficulty:'0x0',nonce:'0x0000000000000000'};
    const rpc=Deno.serve({hostname:'127.0.0.1',port:0,onListen:()=>{}},async request=>{
        const value=await request.json();
        const results:Record<string,unknown>={eth_chainId:'0x7a69',eth_getBlockByNumber:block,eth_call:'0x'+'00'.repeat(31)+'01'};
        if(!results[value.method])throw new Error('Unexpected RPC call: '+value.method);
        return Response.json({jsonrpc:'2.0',id:value.id,result:results[value.method]});
    });
    const check=(condition:unknown,message:string)=>{if(!condition)throw new Error(message);};
    try {
        for(const name of ['server.ts','directory.ts','abi.json','badge-abi.json'])
            await Deno.copyFile(new URL(name,import.meta.url),directory+'/'+name);
        const fixture=JSON.parse(await Deno.readTextFile(new URL('network.json',import.meta.url)));
        fixture.chainId=31337;fixture.admin=privateKeyToAccount(key).address;
        delete fixture.ResearchBadges;delete fixture.PersonalBadgeAccountFactory;
        const nft={...fixture,DemoV1:'0x1111111111111111111111111111111111111111',macCategory:'0x'+'22'.repeat(32)};
        await Deno.writeTextFile(directory+'/network.json',JSON.stringify(fixture));
        await Deno.writeTextFile(directory+'/network-nft.json',JSON.stringify(nft));
        const session=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
        const sessionPublic=toHex(new Uint8Array(await crypto.subtle.exportKey('raw',session.publicKey)));
        const member=('0x'+'ab'.repeat(32)) as Hex,context=('0x'+'cd'.repeat(32)) as Hex,iso=(s:number)=>new Date(s*1000).toISOString();
        const record={id:'0x'+'ef'.repeat(32),member,account:{status:'unavailable',address:null,participantToken:null},accountGeneration:'0',label:'seed-1',version:{selfReported:'0.2.0',buildNumber:'5',admittedCodeHash:'0x'+'17'.repeat(32),measurement:null},checkIn:{lastVerifiedAt:iso(now-10),expiresAt:iso(now+80),status:'fresh'},sync:{scope:'0x'+'00'.repeat(32),keyEpoch:'1',groupPublicFingerprint:null,status:'unverified',receiptTransaction:null,receiptCheckedAt:null,receiptBlockTime:null}};
        const dataDir=directory+'/data';await Deno.mkdir(dataDir);
        await Deno.writeTextFile(dataDir+'/state.json',JSON.stringify({transactions:{},boxes:{},directories:{nft:{entries:[[member,{record,sessionPublic,context,epoch:'1',receiptBlock:null}]],counters:[]}}}));
        const {default:handler}=await import('file://'+directory+'/server.ts');
        const env={PRIVATE_KEY:key,RPC_URL:'http://127.0.0.1:'+rpc.addr.port,NATIVE_DIRECTORY_ENABLED:'true'};
        const listed=await (await handler(new Request('http://relay/nft/directory'),{env,dataDir})).json();
        check(listed.status==='available'&&listed.nodes.length===1&&listed.nodes[0].member===member&&listed.nodes[0].label==='seed-1','redeploy emptied the directory: '+JSON.stringify(listed));
        const {leavePayload}=await import('file://'+directory+'/directory.ts');
        const signature=toHex(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},session.privateKey,leavePayload(nft,member,sessionPublic,context,now))));
        const left=await (await handler(new Request('http://relay/nft/directory/leave',{method:'POST',body:JSON.stringify({member,context,at:now,signature})}),{env,dataDir})).json();
        check(left.left===true,'leave failed: '+JSON.stringify(left));
        check(JSON.parse(await Deno.readTextFile(dataDir+'/state.json')).directories.nft.entries.length===0,'leave not written to the state file');
    } finally {await rpc.shutdown();await Deno.remove(directory,{recursive:true});}
});
