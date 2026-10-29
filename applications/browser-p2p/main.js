import { createLibp2p } from 'libp2p'
import { webSockets } from '@libp2p/websockets'
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { multiaddr } from '@multiformats/multiaddr'
import { verify, cat, enc, hex } from './verify.js'
import { discover, address } from './tunnels.mjs'
const output=document.querySelector('pre')
async function read(stream) {let parts=[],n=0;for await(const part of stream){const b=part.subarray();n+=b.length;if(n>65536)throw Error('stream size');parts.push(b)};return cat(...parts)}
const attempts=[]
function report(event){attempts.push({...event,time:new Date().toISOString()});window.attempts=attempts;output.textContent=JSON.stringify({attempts},null,2)}
async function connect(config, entry) {
  const start=performance.now(),target=address(entry)
  report({sources:entry.sources,url:entry.url,target,status:'dialing'})
  const node=await createLibp2p({addresses:{listen:[]},transports:[webSockets(),circuitRelayTransport()],connectionEncrypters:[noise()],streamMuxers:[yamux()],services:{identify:identify(),ping:ping()}})
  try {
    const conn=await node.dial(multiaddr(target),{signal:AbortSignal.timeout(8000)})
    const connected=performance.now()
    const stream=await conn.newStream('/dsmack/attest/1',{runOnLimitedConnection:true,signal:AbortSignal.timeout(30000)})
    const blob=await read(stream);await stream.close()
    const fetched=performance.now(), checked=await verify(blob,conn.remotePeer,config)
    const verified=performance.now()
    const echo=await conn.newStream('/dsmack/echo/1',{runOnLimitedConnection:true,signal:AbortSignal.timeout(10000)})
    const msg=enc.encode('browser to attested Mac guest');echo.send(msg);await echo.close()
    if(hex(await read(echo))!==hex(msg))throw Error('echo mismatch')
    const result={...checked,attempts,target,transport:conn.remoteAddr.toString(),encryption:conn.encryption,attestationBytes:blob.length,attestationHex:hex(blob),timingsMs:{connect:connected-start,fetch:fetched-connected,verify:verified-fetched,total:performance.now()-start},echo:true}
    report({sources:entry.sources,url:entry.url,status:'verified'});window.pendingResult=result; output.textContent=JSON.stringify({...result,attestationHex:'saved by probe'},null,2);return result
  } finally {await node.stop()}
}
async function run(){
 const response=await fetch('./config.json');if(!response.ok)throw Error('config HTTP '+response.status)
 const config=await response.json(),queue=[];let done=false,notify=()=>{}
 const sources=discover(config.discovery,report,entry=>{queue.push(entry);notify()}).finally(()=>{done=true;notify()})
 while(!done || queue.length){
  if(!queue.length){await new Promise(resolve=>{notify=resolve});continue}
  const entry=queue.shift()
  try{const result=await connect(config,entry);await sources;window.result=result;output.textContent=JSON.stringify({...result,attestationHex:'saved by probe'},null,2);return result}
  catch(e){report({sources:entry.sources,url:entry.url,status:'failed',error:e.message})}
 }
 await sources
 throw Error('All discovered tunnels failed; see source and URL attempts')
}
run().catch(e=>{window.failure=e.stack;output.textContent=JSON.stringify({attempts,error:e.stack},null,2);console.error(e)})
