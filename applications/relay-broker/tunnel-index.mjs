import { tunnel } from "../browser-p2p/tunnels.mjs";
import { verifyMessage } from "../payments/schema.mjs";
const memory={entries:[],publishers:[]};let pending=Promise.resolve();
const canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))):x);
export function tunnelIndex(req,operatorHash,path) {
 const result=pending.then(()=>handleIndex(req,operatorHash,path));
 pending=result.then(()=>{},()=>{});return result;
}
async function handleIndex(req,operatorHash,path) {
 let state=memory;
 if(path){try{state=JSON.parse(await Deno.readTextFile(path))}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;state={entries:[],publishers:[]}}}
 let entries=state.entries;const publishers=new Map(state.publishers);
 const headers={"access-control-allow-origin":"*","access-control-allow-methods":"GET, POST, OPTIONS","access-control-allow-headers":"content-type, authorization","cache-control":"no-store","content-type":"application/json"};
 const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method==='GET'){const now=Date.now()/1000;for(const [id,v] of publishers)if(v.expiry<=now)publishers.delete(id);return reply([...entries,...[...publishers.values()].flatMap(v=>v.entries)].filter(e=>e.expiresAt>now).slice(-32))}
 if(req.method!=='POST')return reply({error:'method'},405);
 const auth=req.headers.get('authorization')??'';
 const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(auth.slice(7)))),b=>b.toString(16).padStart(2,'0')).join('');
 const operator=operatorHash&&auth.startsWith('Bearer ')&&digest===operatorHash;
 try {
  let chunks=[],size=0;for await(const b of req.body??[]){size+=b.length;if(size>16384)return reply({error:'body limit'},413);chunks.push(b)}
  const raw=new Uint8Array(size);let at=0;for(const b of chunks){raw.set(b,at);at+=b.length}
  const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  if(!operator&&Array.isArray(body))return reply({error:'publisher signature required'},403);
  let publisher;const values=operator?body:body.entries;
  if(!operator){
   const {signature,...unsigned}=body;publisher=String(body.publisher).toLowerCase();
   if(!/^0x[0-9a-f]{40}$/.test(publisher)||verifyMessage('dsmack-tunnels/1\n'+canonical(unsigned),signature).toLowerCase()!==publisher)throw Error('publisher signature');
   if(!Number.isSafeInteger(body.expiresAt)||body.expiresAt<=Date.now()/1000||body.expiresAt>Date.now()/1000+3600)throw Error('publisher expiry');
  }
  if(!Array.isArray(values)||values.length>32)throw Error('at most 32 entries');
  const next=values.map(tunnel);const now=Date.now()/1000;
  if(next.some(e=>e.expiresAt<=now||e.expiresAt>now+3600))throw Error('expiry must be within one hour');
  if(operator)entries=next;else{
   const prior=publishers.get(publisher);if(prior&&(prior.expiry>body.expiresAt||(prior.expiry===body.expiresAt&&prior.signature!==body.signature)))throw Error('stale publisher update');
   publishers.delete(publisher);publishers.set(publisher,{entries:next,expiry:body.expiresAt,signature:body.signature});while(publishers.size>32)publishers.delete(publishers.keys().next().value)
  }
  const saved={entries,publishers:[...publishers]};
  if(path){await Deno.writeTextFile(path+'.tmp',JSON.stringify(saved),{mode:0o600});await Deno.rename(path+'.tmp',path)}
  else Object.assign(memory,saved);
  return reply(next);
 }catch(e){return reply({error:e.message},400)}
}
