import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tunnelIndex } from './tunnel-index.mjs'
import { discover } from '../browser-p2p/tunnels.mjs'

test('only an operator can replace quick-tunnel hints; public reads are CORS enabled',async()=>{
 const token='test-operator', hash=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))).toString('hex')
 const entries=[{url:'wss://test-route.trycloudflare.com/',relayPeer:'12D3KooW'+'a'.repeat(44),guestPeer:'12D3KooW'+'b'.repeat(44),expiresAt:Math.floor(Date.now()/1000)+600}]
 const post=(value,auth)=>new Request('https://index.test/tunnels',{method:'POST',headers:{authorization:auth,'content-type':'application/json'},body:JSON.stringify(value)})
 assert.equal((await tunnelIndex(post(entries,''),hash)).status,403)
 assert.equal((await tunnelIndex(post([{...entries[0],url:'wss://evil.test/'}],'Bearer '+token),hash)).status,400)
 assert.equal((await tunnelIndex(post(entries,'Bearer '+token),hash)).status,200)
 const response=await tunnelIndex(new Request('https://index.test/tunnels'),hash)
 assert.equal(response.headers.get('access-control-allow-origin'),'*');assert.deepEqual(await response.json(),entries)
})

test('a failed broker remains visible while RPC hints still produce a candidate',async()=>{
 const original=globalThis.fetch, events=[]
 const values=[{url:'wss://chain-route.trycloudflare.com/',relayPeer:'12D3KooW'+'a'.repeat(44),guestPeer:'12D3KooW'+'b'.repeat(44),expiresAt:Math.floor(Date.now()/1000)+600}]
 const text=Buffer.from(JSON.stringify(values)),word=n=>BigInt(n).toString(16).padStart(64,'0')
 const abi='0x'+word(32)+word(text.length)+text.toString('hex').padEnd(Math.ceil(text.length/32)*64,'0')
 globalThis.fetch=async url=>url==='https://broker.test'?new Response('offline',{status:503}):Response.json({result:abi})
 try{const out=await discover({broker:'https://broker.test',rpcs:['https://rpc.test'],registry:'0x'+'11'.repeat(20),entriesSelector:'0x0fc99376'},e=>events.push(e));assert.equal(out.length,1);assert.equal(out[0].url,values[0].url);assert(events.some(e=>e.source==='https://broker.test'&&e.status==='failed'&&e.error==='HTTP 503'))}finally{globalThis.fetch=original}
})

test('Mac publishers sign and clear only their own scoped hints; forged/stale updates fail',async()=>{
 const { Wallet }=await import('../payments/schema.mjs')
 const first=Wallet.createRandom(),second=Wallet.createRandom(),now=Math.floor(Date.now()/1000)
 const entry=id=>({url:`wss://${id}.trycloudflare.com/`,relayPeer:'12D3KooW'+'c'.repeat(44),guestPeer:'12D3KooW'+'d'.repeat(44),expiresAt:now+600})
 const request=async(wallet,entries,expiresAt)=>{const unsigned={entries,expiresAt,publisher:wallet.address.toLowerCase()};const sorted=JSON.stringify(unsigned,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))):x);return {...unsigned,signature:await wallet.signMessage('dsmack-tunnels/1\n'+sorted)}}
 const post=body=>tunnelIndex(new Request('https://index.test/tunnels',{method:'POST',body:JSON.stringify(body)}),'')
 const a=await request(first,[entry('first')],now+600),b=await request(second,[entry('second')],now+600)
 assert.equal((await post({...a,publisher:second.address.toLowerCase()})).status,400)
 assert.equal((await post(a)).status,200);assert.equal((await post(b)).status,200)
 assert.equal((await post(await request(first,[],now+601))).status,200)
 assert.equal((await post(a)).status,400)
 const values=await (await tunnelIndex(new Request('https://index.test/tunnels'),'')).json()
 assert(!values.some(v=>v.url===entry('first').url));assert(values.some(v=>v.url===entry('second').url))
})
