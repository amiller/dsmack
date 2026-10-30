import {verifyDkimRecovery} from './dkim-verifier.mjs';
import {bytes,b64,unb64,digest,random,seal,open,quoteBinding,emailRecoveryLabel} from './email-gate-crypto.mjs';
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json','cache-control':'no-store'}});
export class EmailGate {
  constructor({load,save,sendEmail,quote,verifyDkim=verifyDkimRecovery,now=()=>Date.now()}) {Object.assign(this,{load,save,sendEmail,quote,verifyDkim,now});this.serial=Promise.resolve();}
  async initialize() {
    this.state=await this.load();
    if(!this.state){
      const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
      this.state={v:1,privateKey:await crypto.subtle.exportKey('jwk',pair.privateKey),publicKey:b64(await crypto.subtle.exportKey('raw',pair.publicKey)),storageKey:random(),accounts:{},challenges:{},limits:{}};
      await this.save(this.state);
    }
    this.privateKey=await crypto.subtle.importKey('jwk',this.state.privateKey,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
    this.storageKey=await crypto.subtle.importKey('raw',unb64(this.state.storageKey),'AES-GCM',false,['encrypt','decrypt']);
    return this;
  }
  async atRest(value,label='dsmack-email-storage/1') {
    const iv=crypto.getRandomValues(new Uint8Array(12));
    return {iv:b64(iv),ciphertext:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes(label)},this.storageKey,bytes(value)))};
  }
  async fromRest(value,label='dsmack-email-storage/1') {return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(value.iv),additionalData:bytes(label)},this.storageKey,unb64(value.ciphertext))));}
  handle(req) {
    const task=this.serial.then(()=>this.route(req));
    this.serial=task.catch(()=>{});
    return task.catch(error=>json({error:error.status?error.message:'Email recovery is unavailable'},error.status||503));
  }
  async route(req) {
    const url=new URL(req.url),path=url.pathname;
    if(path==='/continuity/attestation'&&req.method==='GET') {
      const nonce=url.searchParams.get('nonce');
      if(!nonce||!/^[A-Za-z0-9_-]{43}$/.test(nonce))fail(400,'A fresh 32-byte nonce is required');
      return json({v:1,nonce,publicKey:this.state.publicKey,...await this.quote(await quoteBinding(nonce,this.state.publicKey))});
    }
    if(req.method!=='POST')return json({error:'Not found'},404);
    if(Number(req.headers.get('content-length')||0)>65536)fail(413,'Request too large');
    const raw=await req.text();if(raw.length>65536)fail(413,'Request too large');
    let body;try{body=JSON.parse(raw);}catch{fail(400,'Invalid JSON');}
    if(!body||typeof body!=='object'||Array.isArray(body))fail(400,'Expected a JSON object');
    if(path==='/continuity/email/dkim') {
      if(!['enroll','recover'].includes(body.purpose))fail(400,'Unknown email operation');
      const email=String(body.email||'').trim().toLowerCase();
      let proof;try{proof=await this.verifyDkim({...body,email},{now:this.now()});}catch(error){fail(403,error.message);}
      const label=emailRecoveryLabel(email,body.userId),account=await digest(label);
      this.state.dkimAccounts??={};
      if(body.purpose==='enroll') {
        if(this.state.dkimAccounts[account])fail(409,'This email already has recovery keys; recover them instead');
        let bundle;try{bundle=await open(this.privateKey,body.publicKey,body.sealed,label+'|enroll|'+proof.nonce);}catch{fail(400,'Invalid sealed recovery keys');}
        if(bundle?.v!==1||!/^[A-Za-z0-9_-]{43}$/.test(bundle.dk||'')||!/^0x[0-9a-fA-F]{64}$/.test(bundle.walletKey||''))fail(400,'Invalid recovery keys');
        this.state.dkimAccounts[account]=await this.atRest(bundle,label);
        await this.save(this.state);
        return json({enrolled:true});
      }
      const stored=this.state.dkimAccounts[account];if(!stored)fail(404,'No recovery keys are enrolled for this email');
      return json({sealed:await seal(this.privateKey,body.publicKey,await this.fromRest(stored,label),label+'|recover|'+proof.nonce)});
    }
    if(path==='/continuity/email/request') {
      const email=String(body.email||'').trim().toLowerCase();
      if(email.length>254||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))fail(400,'Enter an email address');
      if(!['enroll','recover'].includes(body.purpose))fail(400,'Unknown email operation');
      try{await crypto.subtle.importKey('raw',unb64(body.publicKey),{name:'ECDH',namedCurve:'P-256'},false,[]);}catch{fail(400,'Invalid browser public key');}
      const account=await digest(email),time=this.now();
      const limits=this.state.limits[account]||{start:time,sends:0,guesses:0};
      if(time-limits.start>=15*60_000)Object.assign(limits,{start:time,sends:0,guesses:0});
      if(limits.sends>=3)fail(429,'Wait 15 minutes before requesting another code');
      limits.sends++;this.state.limits[account]=limits;
      for(const [id,c] of Object.entries(this.state.challenges))if(c.expires<time)delete this.state.challenges[id];
      const id=random(),code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1_000_000).padStart(6,'0');
      this.state.challenges[id]={account,purpose:body.purpose,publicKey:body.publicKey,codeHash:await digest(id+'|'+code),attempts:0,expires:time+10*60_000};
      await this.save(this.state);
      await this.sendEmail({to:email,code});
      return json({id,expires:this.state.challenges[id].expires});
    }
    if(path==='/continuity/email/confirm') {
      const c=this.state.challenges[body.id];
      if(!c||c.expires<this.now())fail(403,'Code expired or already used');
      const limits=this.state.limits[c.account];
      if(c.attempts>=5||limits.guesses>=10)fail(429,'Too many code guesses; request a new code later');
      c.attempts++;limits.guesses++;
      await this.save(this.state);
      if(!/^\d{6}$/.test(body.code||'')||await digest(body.id+'|'+body.code)!==c.codeHash)fail(403,'Incorrect email code');
      delete this.state.challenges[body.id];
      await this.save(this.state);
      if(c.purpose==='enroll') {
        if(this.state.accounts[c.account])fail(409,'This email already has recovery keys; recover them instead');
        let bundle;try{bundle=await open(this.privateKey,c.publicKey,body.sealed,'dsmack-email-enroll/1|'+body.id);}catch{fail(400,'Invalid sealed recovery keys');}
        if(bundle?.v!==1||!/^[A-Za-z0-9_-]{43}$/.test(bundle.dk||'')||!/^0x[0-9a-fA-F]{64}$/.test(bundle.walletKey||''))fail(400,'Invalid recovery keys');
        this.state.accounts[c.account]=await this.atRest(bundle);
        await this.save(this.state);
        return json({enrolled:true});
      }
      const stored=this.state.accounts[c.account];if(!stored)fail(404,'No recovery keys are enrolled for this email');
      return json({sealed:await seal(this.privateKey,c.publicKey,await this.fromRest(stored),'dsmack-email-recover/1|'+body.id)});
    }
    return json({error:'Not found'},404);
  }
}
