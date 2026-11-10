import {getCollateral,PHALA_PCCS_URL} from 'npm:@phala/dcap-qvl@0.6.5';
import {EmailGate} from './email-gate.mjs';
const gates=new Map();
const enc=new TextEncoder(),dec=new TextDecoder();
async function socketPost(path,method,body) {
  const connection=await Deno.connect({transport:'unix',path});
  try {
    const payload=JSON.stringify(body),wire=enc.encode(`POST /${method} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${enc.encode(payload).length}\r\nConnection: close\r\n\r\n${payload}`);
    for(let offset=0;offset<wire.length;)offset+=await connection.write(wire.subarray(offset));
    const chunks=[];let size=0;
    while(true){const buffer=new Uint8Array(65536),count=await connection.read(buffer);if(count===null)break;size+=count;if(size>8_000_000)throw Error('Attestation response too large');chunks.push(buffer.slice(0,count));}
    const joined=new Uint8Array(size);let offset=0;for(const chunk of chunks){joined.set(chunk,offset);offset+=chunk.length;}
    const text=dec.decode(joined),boundary=text.indexOf('\r\n\r\n'),headers=text.slice(0,boundary);
    if(!/^HTTP\/1\.[01] 200\b/.test(headers))throw Error('dstack attestation request failed');
    let content=text.slice(boundary+4);
    if(/transfer-encoding:\s*chunked/i.test(headers)) {
      let rest=content;content='';
      while(true){const e=rest.indexOf('\r\n'),n=parseInt(rest.slice(0,e),16);if(!Number.isFinite(n))throw Error('Invalid attestation response');if(n===0)break;content+=rest.slice(e+2,e+2+n);rest=rest.slice(e+2+n+2);}
    }
    return JSON.parse(content);
  } finally{connection.close();}
}
export async function emailGate(req,ctx) {
  if(!ctx?.dataDir)return new Response(JSON.stringify({error:'Email recovery storage is unavailable'}),{status:503,headers:{'content-type':'application/json'}});
  if(!gates.has(ctx.dataDir))gates.set(ctx.dataDir,(async()=>{
    const file=ctx.dataDir+'/email-gate.json';
    return new EmailGate({
      load:async()=>{try{return JSON.parse(await Deno.readTextFile(file));}catch(e){if(e instanceof Deno.errors.NotFound)return null;throw e;}},
      save:async(state)=>{await Deno.mkdir(ctx.dataDir,{recursive:true});await Deno.writeTextFile(file+'.tmp',JSON.stringify(state),{mode:0o600});await Deno.rename(file+'.tmp',file);},
      quote:async(reportData)=>{
        const result=await socketPost(ctx.env.DSTACK_SOCKET,'GetQuote',{report_data:Array.from(reportData,b=>b.toString(16).padStart(2,'0')).join('')});
        const quote=result.quote.replace(/^0x/,'');
        const quoteBytes=Uint8Array.from(quote.match(/../g),x=>parseInt(x,16));
        return {quote,eventLog:typeof result.event_log==='string'?JSON.parse(result.event_log):result.event_log,collateral:await getCollateral(PHALA_PCCS_URL,quoteBytes)};
      },
    }).initialize();
  })());
  return (await gates.get(ctx.dataDir)).handle(req);
}
export {socketPost};
