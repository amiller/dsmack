import {verifyDkimRecovery} from './dkim-verifier.mjs';
import {bytes,b64,unb64,digest,random,seal,open,quoteBinding,emailRecoveryLabel,recoveryControlId,recoveryControlKey,recoveryControlMessage} from './email-gate-crypto.mjs';
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json','cache-control':'no-store'}});
export class EmailGate {
  constructor({load,save,quote,verifyDkim=verifyDkimRecovery,now=()=>Date.now()}) {Object.assign(this,{load,save,quote,verifyDkim,now});this.serial=Promise.resolve();}
  async initialize() {
    this.state=await this.load();
    if(!this.state){
      const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
      this.state={v:1,privateKey:await crypto.subtle.exportKey('jwk',pair.privateKey),publicKey:b64(await crypto.subtle.exportKey('raw',pair.publicKey)),storageKey:random(),dkimAccounts:{},recoveries:{}};
    }
    // Retire outbound email-code wraps and challenges from persisted v1 state.
    delete this.state.accounts;delete this.state.challenges;delete this.state.limits;
    this.state.recoveries??={};
    await this.save(this.state);
    this.privateKey=await crypto.subtle.importKey('jwk',this.state.privateKey,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
    this.storageKey=await crypto.subtle.importKey('raw',unb64(this.state.storageKey),'AES-GCM',false,['encrypt','decrypt']);
    return this;
  }
  async atRest(value,label) {
    const iv=crypto.getRandomValues(new Uint8Array(12));
    return {iv:b64(iv),ciphertext:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes(label)},this.storageKey,bytes(value)))};
  }
  async fromRest(value,label) {return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(value.iv),additionalData:bytes(label)},this.storageKey,unb64(value.ciphertext))));}
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
      const bundle=await this.fromRest(stored,label),controlId=await recoveryControlId(bundle.dk);
      let pending=this.state.recoveries[controlId];
      if(pending?.nonce===proof.nonce) {
        if(pending.cancelled)fail(410,'Email recovery was cancelled by an existing device');
      } else {
        if(pending&&!pending.cancelled&&!pending.released)fail(409,'An email recovery is already pending');
        // The browser knows this ID before POST, so a lost reply is resumable.
        pending={id:proof.nonce,account,label,publicKey:body.publicKey,nonce:proof.nonce,releaseAt:this.now()+48*60*60_000};
        this.state.recoveries[controlId]=pending;
        await this.save(this.state);
      }
      return json({pending:true,id:pending.id,releaseAt:pending.releaseAt},202);
    }
    if(path==='/continuity/email/release') {
      const pending=Object.values(this.state.recoveries).find(p=>p.id===body.id);
      if(!pending)fail(404,'Recovery request not found');
      if(pending.cancelled)fail(410,'Email recovery was cancelled by an existing device');
      if(this.now()<pending.releaseAt)return json({pending:true,id:pending.id,releaseAt:pending.releaseAt},202);
      const bundle=await this.fromRest(this.state.dkimAccounts[pending.account],pending.label);
      pending.released=true;
      await this.save(this.state);
      return json({sealed:await seal(this.privateKey,pending.publicKey,bundle,pending.label+'|recover|'+pending.nonce)});
    }
    if(['/continuity/email/status','/continuity/email/cancel'].includes(path)) {
      const action=path.endsWith('/cancel')?'cancel':'status';
      if(!/^[A-Za-z0-9_-]{43}$/.test(body.controlId||'')||!Number.isSafeInteger(body.ts)||Math.abs(this.now()-body.ts)>60_000)fail(403,'Invalid recovery control request');
      const pending=this.state.recoveries[body.controlId];
      if(!pending)return json({pending:null});
      const bundle=await this.fromRest(this.state.dkimAccounts[pending.account],pending.label);
      let valid=false;
      try { valid=await crypto.subtle.verify('HMAC',await recoveryControlKey(bundle.dk),unb64(body.auth),recoveryControlMessage(action,body)); } catch { fail(403,'Invalid recovery control signature'); }
      if(!valid)fail(403,'Invalid recovery control signature');
      if(action==='cancel') {
        if(body.id!==pending.id)fail(409,'Recovery request changed; refresh and try again');
        if(pending.released)fail(409,'Email recovery has already completed');
        pending.cancelled=true;
        await this.save(this.state);
      }
      return json({pending:pending.cancelled||pending.released?null:{id:pending.id,releaseAt:pending.releaseAt}});
    }
    return json({error:'Not found'},404);
  }
}
