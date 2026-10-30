import { Contract, JsonRpcProvider, keccak256 } from "ethers";
import { store, walletBody } from "./credit.mjs";

const encoder = new TextEncoder();
const canonical = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map(k => [k,o[k]])));
const need = (ok,message) => { if(!ok) throw new Error(message); };
const unhex = (v) => Uint8Array.from(v.match(/../g)??[],x=>parseInt(x,16));
const decode = (v) => Uint8Array.from(atob(v.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const encode = (v) => {
  let s="";for(let i=0;i<v.length;i+=8192)s+=String.fromCharCode(...v.subarray(i,i+8192));
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
};
async function cidFor(bytes) {
  const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));let bits=0,value=0,out="b";
  for(const b of [1,0x55,0x12,0x20,...digest]) { value=(value<<8)|b;bits+=8;while(bits>=5){bits-=5;out+="abcdefghijklmnopqrstuvwxyz234567"[(value>>>bits)&31];} }
  if(bits)out+="abcdefghijklmnopqrstuvwxyz234567"[(value<<(5-bits))&31];return out;
}
export function mergeSessions(left,right) {
  const out={...left};
  for(const [id,r] of Object.entries(right)) { const l=out[id];if(!l||r.counter>l.counter||(r.counter===l.counter&&r.writer>l.writer))out[id]=r; }
  return out;
}
export class ChatSync {
  constructor({cfg,credit,keys,storage,api,changed=()=>{}}) {
    Object.assign(this,{cfg,credit,keys,storage,api,changed});this.pending=Promise.resolve();
  }
  async loadState() {
    if(this.state)return;
    this.wallet=this.credit.address.toLowerCase();this.stateKey="sync:"+this.wallet;
    this.state=await store(this.stateKey)??{counter:0,sessions:{},pending:[]};
    this.writer=await store("sync-writer")??crypto.randomUUID();await store("sync-writer",this.writer);
  }
  async init() {
    await this.loadState();
    this.key=await crypto.subtle.importKey("raw",decode(this.keys.dk),"AES-GCM",false,["encrypt","decrypt"]);
    need(this.cfg.syncAnchor&&this.cfg.syncAnchorCodeHash,"Chat sync chain anchor is not configured.");
    this.rpc=new JsonRpcProvider(this.cfg.rpc,84532,{staticNetwork:true,cacheTimeout:-1});
    need(Number(await this.rpc.send("eth_chainId",[]))===84532,"Chat sync RPC is not Base Sepolia.");
    need(keccak256(await this.rpc.getCode(this.cfg.syncAnchor))===this.cfg.syncAnchorCodeHash,"Chat sync anchor code differs from the deployment pin.");
    this.chain=new Contract(this.cfg.syncAnchor,["function heads(address) view returns(uint256 counter,bytes32 digest)"],this.rpc);
    this.initialized=true;
  }
  async request(action,fields={}) { return this.api("/sync/"+action,await walletBody(this.credit,"sync-"+action.replaceAll("/","-"),fields)); }
  async seal(value,context) {
    const nonce=crypto.getRandomValues(new Uint8Array(12));
    const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:encoder.encode("dsmack-chat-v1:"+this.wallet+":"+context)},this.key,encoder.encode(JSON.stringify(value))));
    const bytes=new Uint8Array(12+encrypted.length);bytes.set(nonce);bytes.set(encrypted,12);
    const ciphertext=encode(bytes), result=await this.request("blob",{ciphertext});
    need(result.cid===await cidFor(bytes),"Broker returned a different ciphertext CID.");return result.cid;
  }
  async open(cid,context) {
    const response=await this.request("read",{cid}),bytes=decode(response.ciphertext);
    need(await cidFor(bytes)===cid,"Encrypted chat CID mismatch.");
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes.slice(0,12),additionalData:encoder.encode("dsmack-chat-v1:"+this.wallet+":"+context)},this.key,bytes.slice(12));
    return JSON.parse(new TextDecoder().decode(plain));
  }
  async remote(attempt=0) {
    const envelope=await this.request("head"),head=envelope.head;
    const live=await this.chain.heads(this.wallet);
    if(!head){need(Number(live.counter)===0&&this.state.counter===0,"Chat sync head disappeared or rolled back.");return {counter:0,sessions:{}};}
    need(head.wallet===this.wallet&&head.anchor.toLowerCase()===this.cfg.syncAnchor.toLowerCase()&&head.chainId===84532,"Chat sync head identity mismatch.");
    const pub=await crypto.subtle.importKey("raw",unhex(this.cfg.brokerKey),"Ed25519",false,["verify"]);
    need(await crypto.subtle.verify("Ed25519",pub,unhex(envelope.signature),encoder.encode(canonical(head))),"Broker chat head signature is invalid.");
    if(Number(live.counter)>head.counter&&attempt<2)return this.remote(attempt+1);
    need(Number(live.counter)===head.counter&&live.digest===keccak256(encoder.encode(canonical(head))),"Chat sync head differs from the on-chain anchor.");
    need(head.counter>=this.state.counter,"Chat sync head rolled back.");
    const manifest=await this.open(head.cid,"manifest");
    need(manifest.v===1&&manifest.wallet===this.wallet&&manifest.counter===head.counter&&manifest.sessions&&typeof manifest.sessions==="object","Invalid encrypted chat manifest.");
    for(const [id,item] of Object.entries(manifest.sessions))need(id.length<=200&&item&&typeof item.cid==="string"&&Number.isSafeInteger(item.counter)&&item.counter>0&&typeof item.writer==="string","Invalid encrypted chat entry.");
    return manifest;
  }
  serial(fn) { const p=this.pending.then(fn);this.pending=p.catch(()=>{});return p; }
  pull() { return this.serial(async()=>{
    if(!this.initialized)await this.init();
    const remote=await this.remote(), merged=mergeSessions(this.state.sessions,remote.sessions);
    for(const [id,entry] of Object.entries(merged)) {
      const local=this.state.sessions[id];
      if(this.state.pending.includes(id))continue;
      if(!local||local.cid!==entry.cid||!await this.storage.sessions.get(id)) {
        const record=await this.open(entry.cid,"session:"+id);
        need(record.data.id===id&&record.metadata.id===id,"Encrypted session id mismatch.");
        await this.storage.sessions.save(record.data,record.metadata);
      }
    }
    this.state={...this.state,counter:remote.counter,sessions:merged};await store(this.stateKey,this.state);this.changed();return remote;
  }); }
  push(id) { return this.serial(async()=>{
    await this.loadState();
    const data=await this.storage.sessions.get(id),metadata=await this.storage.sessions.getMetadata(id);
    need(data&&metadata,"Saved chat is missing.");
    if(!this.state.pending.includes(id))this.state.pending.push(id);await store(this.stateKey,this.state);
    if(!this.initialized)await this.init();
    const cid=await this.seal({data,metadata},"session:"+id);
    for(let attempt=0;attempt<4;attempt++) {
      const remote=await this.remote(),sessions=mergeSessions(this.state.sessions,remote.sessions);
      sessions[id]={cid,counter:Math.max(remote.counter,sessions[id]?.counter??0)+1,writer:this.writer};
      const manifest={v:1,wallet:this.wallet,counter:remote.counter+1,sessions};
      const manifestCid=await this.seal(manifest,"manifest");
      try {
        await this.request("commit",{previous:remote.counter,cid:manifestCid});
        this.state={counter:manifest.counter,sessions,pending:this.state.pending.filter(x=>x!==id)};
        await store(this.stateKey,this.state);this.changed();return;
      }catch(error){if(!/head changed|chain head changed/i.test(error.message)||attempt===3)throw error;}
    }
  }); }
  async flush() {
    await this.pending;
    await this.loadState();
    const ids=new Set(this.state.pending);
    for(const metadata of await this.storage.sessions.getAllMetadata()) {
      if(!this.state.sessions[metadata.id])ids.add(metadata.id);
    }
    for(const id of ids) {
      const data=await this.storage.sessions.get(id),wallet=data?.dsmack?.wallet;
      if(!data?.messages?.some(message=>message.role==="user")||(wallet&&wallet.toLowerCase()!==this.wallet)) {
        this.state.pending=this.state.pending.filter(pending=>pending!==id);await store(this.stateKey,this.state);continue;
      }
      await this.push(id);
    }
  }
}
