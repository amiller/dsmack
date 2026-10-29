import { createLibp2p } from 'libp2p'
import { webSockets } from '@libp2p/websockets'
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { multiaddr } from '@multiformats/multiaddr'
import { verify, cat, enc, hex } from './verify.js'
const output=document.querySelector('pre')
async function read(stream) {let parts=[],n=0;for await(const part of stream){const b=part.subarray();n+=b.length;if(n>65536)throw Error('stream size');parts.push(b)};return cat(...parts)}
async function run() {
  const start=performance.now(), config=await (await fetch('./config.json')).json()
  const target=new URLSearchParams(location.hash.slice(1)).get('target')
  if(!target) throw Error('Supply #target=<circuit multiaddr>')
  if(!/^\/dns4\/[^/]+\/tcp\/443\/wss\/p2p\/[^/]+\/p2p-circuit\/p2p\/[^/]+$/.test(target))throw Error('Public WSS circuit address required')
  const node=await createLibp2p({addresses:{listen:[]},transports:[webSockets(),circuitRelayTransport()],connectionEncrypters:[noise()],streamMuxers:[yamux()],services:{identify:identify(),ping:ping()}})
  try {
    const conn=await node.dial(multiaddr(target),{signal:AbortSignal.timeout(30000)})
    const connected=performance.now()
    const stream=await conn.newStream('/dsmack/attest/1',{runOnLimitedConnection:true,signal:AbortSignal.timeout(30000)})
    const blob=await read(stream);await stream.close()
    const fetched=performance.now(), checked=await verify(blob,conn.remotePeer,config)
    const verified=performance.now()
    const echo=await conn.newStream('/dsmack/echo/1',{runOnLimitedConnection:true,signal:AbortSignal.timeout(10000)})
    const msg=enc.encode('browser to attested Mac guest');echo.send(msg);await echo.close()
    if(hex(await read(echo))!==hex(msg))throw Error('echo mismatch')
    const result={...checked,target,transport:conn.remoteAddr.toString(),encryption:conn.encryption,attestationBytes:blob.length,attestationHex:hex(blob),timingsMs:{connect:connected-start,fetch:fetched-connected,verify:verified-fetched,total:performance.now()-start},echo:true}
    window.result=result; output.textContent=JSON.stringify({...result,attestationHex:'saved by probe'},null,2)
  } finally {await node.stop()}
}
run().catch(e=>{window.failure=e.stack;output.textContent=e.stack;console.error(e)})
