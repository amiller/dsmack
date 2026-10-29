import { decode as cbor } from 'cborg'
import { decodeAttestation, authData, cat, hex, sha256 as sha } from '../../dstack-compat/secret-release/policy.mjs'
export { cat, hex }
export const enc = new TextEncoder()
const need = (ok, why) => { if (!ok) throw Error(why) }
function canonical(o) {
 if(o===null || typeof o!=='object')return JSON.stringify(o)
 if(Array.isArray(o))return '['+o.map(canonical).join(',')+']'
 return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}'
}
function rawSignature(der) {
  need(der[0] === 0x30 && der[1] === der.length-2, 'ECDSA DER sequence')
  let p=2; const out = new Uint8Array(64)
  for(let i=0;i<2;i++) {
    need(der[p++] === 2, 'ECDSA DER integer'); const n=der[p++]; let b=der.slice(p,p+n);p+=n
    if(b.length===33 && b[0]===0) b=b.slice(1)
    need(b.length<=32, 'ECDSA integer size');out.set(b,(i+1)*32-b.length)
  }
  need(p===der.length,'ECDSA trailing data'); return out
}
// The immutable page pins an enrollment key checked against Apple's root by bootstrap.py.
export async function verify(blob, remotePeer, trust, entry) {
  need(blob.length<=65536,'attestation size')
  const a=await decodeAttestation(blob)
  need(hex(a.key_id)===trust.keyId,'enrollment key')
  need(Date.now()/1000<trust.expires,'enrollment expired')
  const template=structuredClone(trust.manifestTemplate), compose=JSON.parse(template.docker_compose_file)
  compose.services.peer.command[0]=new URL(entry.url).hostname
  compose.services.peer.command[1]=entry.relayPeer
  template.docker_compose_file=canonical(compose)
  const expectedManifest=hex(await sha(enc.encode(canonical(template))))
  need(hex(a.os_image_hash)===trust.osImage && hex(a.manifest_sha256)===expectedManifest,'measurement')
  need(hex(a.caller)===hex(await sha(enc.encode('peer'))),'caller')
  const report=cat(await sha(cat(enc.encode('dsmack-libp2p-peer/1'),remotePeer.toMultihash().bytes)),new Uint8Array(32))
  need(hex(a.report_data)===hex(report),'PeerId binding')
  const assertion=cbor(a.assertion), auth=assertion.authenticatorData, ad=authData(auth,3)
  need(hex(ad.rp)===hex(await sha(enc.encode(trust.appId))),'app identity')
  need(hex(ad.cdhash)===trust.cdhash,'runner code')
  need(ad.counter>0,'assertion counter')
  const key=await crypto.subtle.importKey('jwk',trust.publicKey,{name:'ECDSA',namedCurve:'P-256'},false,['verify'])
  need(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,rawSignature(assertion.signature),await sha(cat(auth,a.client_data_hash))),'App Attest assertion signature')
  return {peerId:remotePeer.toString(),counter:ad.counter,run:hex(a.run),head:hex(a.head),binding:true,assertion:true}
}
