import { openSync, readSync, fstatSync, closeSync, constants, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

// Deliberately discards console contents. These host observations are advisory;
// they do not attest a result or expose model prompts, code, tool args or logs.
export function consolePhase(line) {
  if(line.startsWith('DSMACK_SUPERVISOR_START '))return 'boot';
  if(line==='DSMACK_DOCKERD_READY'||line.startsWith('DSMACK_OCI_PULL '))return 'pull';
  if(line.startsWith('DSMACK_BROKER_READY '))return 'agent';
  if(line.startsWith('DSMACK_RUNNER_DONE '))return 'review';
  if(line==='DSMACK_POWERING_OFF')return 'done';
  return null;
}
export class ConsoleObserver {
  constructor(){this.partial='';this.phase='launch';this.offset=0;}
  feed(buffer){const text=this.partial+buffer.toString('utf8');const lines=text.split('\n');this.partial=lines.pop();if(this.partial.length>65536)this.partial='';const phases=[];for(let line of lines){if(line.length>65536)continue;line=line.replace(/\r$/,'');const phase=consolePhase(line);if(phase&&phase!==this.phase){this.phase=phase;phases.push({phase,kind:'phase'});}}return phases;}
}
export async function observe({consolePath,attempt,url,token,duration=900,interval=5000,send}){
  if(!/^[a-f0-9]{32}$/.test(attempt)||!Number.isSafeInteger(duration)||duration<1||duration>4200)throw Error('invalid observation bounds');
  const base=new URL(url);if(base.protocol!=='https:'&&!(base.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(base.hostname)))throw Error('HTTPS required outside loopback');
  const observer=new ConsoleObserver();let fd;
  const start=Date.now();const deliver=send??(async event=>{const r=await fetch(new URL('/api/attempts/'+attempt+'/progress',base),{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify(event)});if(!r.ok)throw Error('progress refused: HTTP '+r.status);});
  try{while(Date.now()-start<duration*1000){
    if(fd===undefined){try{fd=openSync(consolePath,constants.O_RDONLY|constants.O_NOFOLLOW);}catch(e){if(e.code!=='ENOENT')throw e;}}
    if(fd!==undefined){const st=fstatSync(fd);if(!st.isFile()||st.nlink!==1||st.size>16777216||st.size<observer.offset)throw Error('console bounds or ownership changed');
      while(observer.offset<st.size){const b=Buffer.alloc(Math.min(65536,st.size-observer.offset));const n=readSync(fd,b,0,b.length,observer.offset);if(!n)throw Error('incomplete console read');observer.offset+=n;for(const event of observer.feed(b.subarray(0,n)))await deliver(event);}
    }
    if(observer.phase==='done')return {observed_guest_poweroff:true,verified:false};
    await deliver({phase:observer.phase,kind:'heartbeat',counters:{elapsed_ms:Date.now()-start}});
    await new Promise(r=>setTimeout(r,interval));
  }return {observation_timeout:true,verified:false};
  }finally{if(fd!==undefined)closeSync(fd);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const [consolePath,attempt]=process.argv.slice(2);if(!consolePath||!attempt||!process.env.BOUNTY_TOKEN_FILE)throw Error('usage: BOUNTY_TOKEN_FILE=... node observe.mjs PUBLIC_CONSOLE ATTEMPT; optional BOUNTY_URL/OBSERVE_SECONDS');
  console.log(JSON.stringify(await observe({consolePath,attempt,url:process.env.BOUNTY_URL??'http://127.0.0.1:8787',token:readFileSync(process.env.BOUNTY_TOKEN_FILE,'utf8').trim(),duration:Number(process.env.OBSERVE_SECONDS??900)})));
}
