import { Contract, JsonRpcProvider, keccak256, verifyMessage } from "../payments/schema.mjs";
import { canonical } from "./grants.mjs";
import { hex } from "../../dstack-compat/secret-release/policy.mjs";

export const headAbi = ["function heads(address) view returns(uint256 counter,bytes32 digest)", "function commit(address,uint256,bytes32)"];
const need = (ok, message, status = 400) => { if (!ok) throw Object.assign(new Error(message), { status }); };
export const decode = (v) => {
  need(typeof v === "string" && /^[A-Za-z0-9_-]+$/.test(v), "base64url ciphertext required");
  return Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
};
export async function cidFor(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let bits = 0, value = 0, out = "b";
  for (const b of [1, 0x55, 0x12, 0x20, ...digest]) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += "abcdefghijklmnopqrstuvwxyz234567"[(value >>> bits) & 31]; }
  }
  if (bits) out += "abcdefghijklmnopqrstuvwxyz234567"[(value << (5 - bits)) & 31];
  return out;
}
export const headDigest = (head) => keccak256(new TextEncoder().encode(canonical(head)));
export class Continuity {
  constructor({ cfg, key, anchorKey, state = { heads: {}, wraps: {} }, save, put, get, now = () => Math.floor(Date.now()/1000), chain = undefined }) {
    Object.assign(this, { cfg, key, anchorKey, state, save, put, get, now });
    this.pending = Promise.resolve(); this.nonces = new Map();
    this.chain = chain ?? (cfg.anchor ? new Contract(cfg.anchor, headAbi, anchorKey.connect(new JsonRpcProvider(cfg.rpc, 84532, {staticNetwork:true,cacheTimeout:-1}))) : null);
  }
  serial(fn) { const p = this.pending.then(fn); this.pending = p.catch(() => {}); return p; }
  authorize(r, action) {
    need(r.action === action && /^0x[\da-fA-F]{40}$/.test(r.wallet) && /^[\da-f]{32}$/.test(r.nonce), "signed wallet request required", 403);
    need(Number.isSafeInteger(r.issuedAt) && Math.abs(this.now()-r.issuedAt)<=120, "expired sync request", 403);
    const {sig,...unsigned}=r;
    let signer; try { signer=verifyMessage(canonical(unsigned),sig).toLowerCase(); } catch { /* refused below */ }
    need(signer===r.wallet.toLowerCase(),"invalid sync wallet signature",403);
    for (const [n, until] of this.nonces) if (until < this.now()) this.nonces.delete(n);
    need(!this.nonces.has(r.wallet+":"+r.nonce),"replayed sync request",403);
    need(this.nonces.size<10000,"too many sync requests",429);
    this.nonces.set(r.wallet+":"+r.nonce,this.now()+120);
    return r.wallet.toLowerCase();
  }
  async signedHead(head) {
    const signature=hex(new Uint8Array(await crypto.subtle.sign("Ed25519",this.key.priv,new TextEncoder().encode(canonical(head)))));
    return {head,signature,publicKey:this.key.public_key};
  }
  async call(action,r) {
    if (action === "wrap/get") {
      need(typeof r.credentialId === "string" && /^[A-Za-z0-9_-]{8,2048}$/.test(r.credentialId),"credential id required");
      const result=Object.hasOwn(this.state.wraps,r.credentialId) && this.state.wraps[r.credentialId]; need(result,"passkey wrap not found",404); return result;
    }
    const wallet=this.authorize(r,"sync-"+action.replaceAll("/","-"));
    if (action === "head") return this.serial(async () => {
      need(this.chain,"sync chain anchor not configured",503);
      const live=await this.chain.heads(wallet), saved=this.state.heads[wallet];
      need(Number(live.counter)===(saved?.head.counter??0),"broker head differs from chain anchor",409);
      if(saved) need(live.digest===headDigest(saved.head),"broker head digest differs from chain anchor",409);
      return saved ?? {head:null};
    });
    if (action === "blob") {
      const bytes=decode(r.ciphertext); need(bytes.length>=29&&bytes.length<=2*1024*1024,"ciphertext size must be 29 bytes to 2 MiB");
      const cid=await cidFor(bytes); await this.put(cid,r.ciphertext); return {cid};
    }
    if (action === "read") {
      need(/^bafkre[a-z2-7]{53}$/.test(r.cid),"raw CIDv1 required");
      const ciphertext=await this.get(r.cid); need(ciphertext,"ciphertext not found",404);
      need(await cidFor(decode(ciphertext))===r.cid,"stored ciphertext CID mismatch",500);
      return {cid:r.cid,ciphertext};
    }
    if(action === "wrap/put") return this.serial(async()=>{
      need(typeof r.credentialId === "string" && /^[A-Za-z0-9_-]{8,2048}$/.test(r.credentialId),"credential id required");
      need(r.envelope&&JSON.stringify(r.envelope).length<=16384,"encrypted wrap required");
      const old=this.state.wraps[r.credentialId];need(!old||old.wallet===wallet,"credential belongs to another wallet",403);
      const value={wallet,envelope:r.envelope};
      const next={...this.state,wraps:{...this.state.wraps,[r.credentialId]:value}};await this.save(next);this.state=next;return {stored:true};
    });
    if(action === "commit") return this.serial(async()=>{
      need(this.chain,"sync chain anchor not configured",503);
      need(Number.isSafeInteger(r.previous)&&r.previous>=0,"previous counter required");
      need(/^bafkre[a-z2-7]{53}$/.test(r.cid)&&await this.get(r.cid),"manifest CID must be pinned first");
      const old=this.state.heads[wallet];need((old?.head.counter??0)===r.previous,"head changed; merge and retry",409);
      const live=await this.chain.heads(wallet);need(Number(live.counter)===r.previous,"chain head changed; merge and retry",409);
      const head={v:1,wallet,counter:r.previous+1,cid:r.cid,anchor:this.cfg.anchor,chainId:84532};
      const envelope=await this.signedHead(head);
      const tx=await this.chain.commit(wallet,r.previous,headDigest(head));
      // Persist the candidate before waiting, so a mined transaction survives a runtime restart.
      let next={...this.state,heads:{...this.state.heads,[wallet]:{...envelope,anchorTx:tx.hash}}};
      await this.save(next);this.state=next;
      const receipt=await tx.wait();need(receipt.status===1,"sync anchor transaction reverted",503);
      return this.state.heads[wallet];
    });
    throw Object.assign(new Error("sync route not found"),{status:404});
  }
}
