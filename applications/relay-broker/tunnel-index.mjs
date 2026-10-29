import { tunnel } from "../browser-p2p/tunnels.mjs";
let entries=[];
export async function tunnelIndex(req,operatorHash) {
 const headers={"access-control-allow-origin":"*","access-control-allow-methods":"GET, POST, OPTIONS","access-control-allow-headers":"content-type, authorization","cache-control":"no-store","content-type":"application/json"};
 const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method==='GET')return reply(entries.filter(e=>e.expiresAt>Date.now()/1000));
 if(req.method!=='POST')return reply({error:'method'},405);
 const auth=req.headers.get('authorization')??'';
 const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(auth.slice(7)))),b=>b.toString(16).padStart(2,'0')).join('');
 if(!operatorHash || !auth.startsWith('Bearer ') || digest!==operatorHash)return reply({error:'operator authentication'},403);
 try {
  let chunks=[],size=0;for await(const b of req.body??[]){size+=b.length;if(size>16384)return reply({error:'body limit'},413);chunks.push(b)}
  const raw=new Uint8Array(size);let at=0;for(const b of chunks){raw.set(b,at);at+=b.length}
  const values=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));if(!Array.isArray(values)||values.length>32)throw Error('at most 32 entries');
  const next=values.map(tunnel);const now=Date.now()/1000;
  if(next.some(e=>e.expiresAt<=now||e.expiresAt>now+3600))throw Error('expiry must be within one hour');
  entries=next;return reply(entries);
 }catch(e){return reply({error:e.message},400)}
}
