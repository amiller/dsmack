// Discovery hints are untrusted; the authenticated guest is checked after dialing.
export function tunnel(entry) {
 const u=new URL(entry.url)
 if(u.protocol!=="wss:" || !/^[a-z0-9-]+\.trycloudflare\.com$/.test(u.hostname) || u.port || u.username || u.password || u.pathname!=="/" || u.search || u.hash)throw Error("expected public quick-tunnel WSS URL")
 for(const k of ["relayPeer","guestPeer"])if(!/^12D3KooW[1-9A-HJ-NP-Za-km-z]{44}$/.test(entry[k]))throw Error("invalid "+k)
 if(!Number.isSafeInteger(entry.expiresAt))throw Error("invalid expiry")
 return {url:u.href,relayPeer:entry.relayPeer,guestPeer:entry.guestPeer,expiresAt:entry.expiresAt}
}
export function address(e) {const u=new URL(e.url);return `/dns4/${u.hostname}/tcp/443/wss/p2p/${e.relayPeer}/p2p-circuit/p2p/${e.guestPeer}`}
export async function discover(config,report,onEntry=()=>{}) {
 const found=new Map()
 const consume=(values,source)=>{if(!Array.isArray(values)||values.length>32)throw Error("expected at most 32 tunnel entries");for(const value of values){try{const e=tunnel(value);report({source,url:e.url,status:e.expiresAt>Date.now()/1000?"discovered":"expired"});if(e.expiresAt<=Date.now()/1000)continue;const key=address(e);const prior=found.get(key);if(prior)prior.sources.push(source);else {const candidate={...e,sources:[source]};found.set(key,candidate);onEntry(candidate)}}catch(err){report({source,url:String(value?.url??""),status:"invalid",error:err.message})}}}
 const get=async(source,load)=>{report({source,status:"reading"});try{consume(await load(),source);report({source,status:"read"})}catch(e){report({source,status:"failed",error:e.message})}}
 await Promise.all([
  get(config.broker,async()=>{const r=await fetch(config.broker,{signal:AbortSignal.timeout(8000),redirect:"error"});if(!r.ok)throw Error("HTTP "+r.status);return await r.json()}),
  ...config.rpcs.map(rpc=>get(rpc,async()=>{
   const r=await fetch(rpc,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"eth_call",params:[{to:config.registry,data:config.entriesSelector},"latest"]}),signal:AbortSignal.timeout(8000),redirect:"error"})
   if(!r.ok)throw Error("HTTP "+r.status);const reply=await r.json();if(reply.error)throw Error(reply.error.message)
   const raw=reply.result;if(!/^0x[0-9a-f]+$/i.test(raw)||raw.length<130)throw Error("invalid registry ABI reply")
   const off=Number(BigInt("0x"+raw.slice(2,66)))*2+2
   const length=Number(BigInt("0x"+raw.slice(off,off+64)));if(length>16384||off+64+length*2>raw.length)throw Error("registry entry length")
   return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Uint8Array.from(raw.slice(off+64,off+64+length*2).match(/../g)??[],b=>parseInt(b,16))))
  }))
 ])
 return [...found.values()]
}
