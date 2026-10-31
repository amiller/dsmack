import {verify,Quote,utils,oids} from '@phala/dcap-qvl';
import {createGateAuthorization,unauthorizedGate} from './gate-authorization.mjs';
import {bytes,random,ephemeral,seal,open,quoteBinding,emailRecoveryLabel,emailRecoveryNonce} from './email-gate-crypto.mjs';
const hex=(value)=>Array.from(new Uint8Array(value),b=>b.toString(16).padStart(2,'0')).join('');
const unhex=(value)=>{if(!/^(?:[0-9a-f]{2})*$/i.test(value))throw Error('Invalid attestation hex');return Uint8Array.from(value.match(/../g)||[],x=>parseInt(x,16));};
const cat=(...parts)=>new Uint8Array(parts.flatMap(p=>Array.from(p)));
const require=(ok,message)=>{if(!ok)throw Error(message);};
const authorizeGate=createGateAuthorization();
export async function replayGateEvents(eventLog) {
  let mr=new Uint8Array(48),ready=false,bootMr;const boot={};
  for(const event of eventLog) {
    if(event.imr!==3)continue;
    const eventType=new Uint8Array(4);new DataView(eventType.buffer).setUint32(0,event.event_type,true);
    const preimage=cat(eventType,bytes(':'+event.event+':'),unhex(event.event_payload));
    const digest=new Uint8Array(await crypto.subtle.digest('SHA-384',preimage));
    require(!event.digest||hex(digest)===event.digest,'Email gate event digest differs');
    mr=new Uint8Array(await crypto.subtle.digest('SHA-384',cat(mr,digest)));
    if(!ready&&['app-id','compose-hash','instance-id','os-image-hash'].includes(event.event)) {
      require(event.event==='os-image-hash'||!bootMr,'Email gate boot identity follows its boot boundary');
      require(!boot[event.event],'Duplicate email gate boot identity');boot[event.event]=event.event_payload;
    }
    if(event.event==='boot-mr-done') {require(!bootMr&&!ready,'Invalid email gate boot boundary');bootMr=mr.slice();}
    if(event.event==='system-ready')ready=true;
  }
  return {mr,ready,boot,bootMr};
}
export async function verifyGateAttestation(attestation,nonce,policy) {
  require(policy?.appId&&policy?.kms&&policy?.mrtd&&policy?.rtmr?.length===3,'Email gate attestation policy is not configured');
  require(attestation.nonce===nonce,'Email gate returned a stale nonce');
  const quoteBytes=unhex(attestation.quote);
  const result=await verify(quoteBytes,attestation.collateral,Math.floor(Date.now()/1000));
  require(['UpToDate','SWHardeningNeeded'].includes(result.status),'Email gate TDX TCB status refused: '+result.status);
  const report=result.report.asTd10()||result.report.asTd15()?.base;
  require(report,'Email gate requires a TDX quote');
  require(hex(report.reportData)===hex(await quoteBinding(nonce,attestation.publicKey)),'Email gate key or challenge is not bound to its quote');
  // SDK 0.6.5's combined PCK-extension helper swallows an unrelated SGX_TYPE
  // decoding error and returns an empty PPID. Read only PPID, strictly, from
  // the same PCK leaf that verify() authenticated (collateral takes priority).
  const pckChain=attestation.collateral.pck_certificate_chain||Quote.parse(quoteBytes).rawCertChain();
  const pck=utils.extractCerts(pckChain)[0];
  const ppid=utils.findExtension([oids.PPID],utils.getIntelExtension(pck));
  require(ppid.length===16,'Email gate attestation has no verified device identity');
  require(hex(report.mrTd)===policy.mrtd,'Email gate OS measurement differs');
  for(let i=0;i<3;i++)require(hex(report['rtMr'+i])===policy.rtmr[i],'Email gate boot measurement differs');
  const {mr,ready,boot,bootMr}=await replayGateEvents(attestation.eventLog);
  require(hex(mr)===hex(report.rtMr3),'Email gate event log does not match its quote');
  require(ready&&bootMr,'Email gate boot event log is incomplete');
  if(boot['app-id']!==policy.appId)throw unauthorizedGate();
  require(/^[0-9a-f]{64}$/.test(boot['compose-hash'])&&/^[0-9a-f]{40}$/.test(boot['instance-id'])&&/^[0-9a-f]{64}$/.test(boot['os-image-hash']),'Email gate boot identity is incomplete');
  const sha256=async(...parts)=>'0x'+hex(await crypto.subtle.digest('SHA-256',cat(...parts)));
  const system=[report.mrTd,report.rtMr0,report.rtMr1,report.rtMr2];
  const owner=[report.mrConfigId,report.mrOwner,report.mrOwnerConfig];
  const authorization=await authorizeGate({
    appId:'0x'+boot['app-id'],composeHash:'0x'+boot['compose-hash'],instanceId:'0x'+boot['instance-id'],
    // dstack 0.5.8 authorizes SHA-256 of the verifier's authenticated PCK PPID.
    deviceId:await sha256(ppid),
    mrSystem:await sha256(...system,new Uint8Array(32)),
    mrAggregated:await sha256(...system,bootMr,...(owner.some(part=>part.some(b=>b!==0))?owner:[])),
    osImageHash:'0x'+boot['os-image-hash'],tcbStatus:result.status,advisoryIds:result.advisory_ids,
  },policy);
  return {publicKey:attestation.publicKey,status:result.status,authorization};
}
export function createEmailGate({base='',policy}) {
  const api=async(path,body,{signal,pending=false}={})=>{
    const response=await fetch(base+path,{method:body?'POST':'GET',headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined,cache:'no-store',signal});
    if(pending&&(response.status===202||response.status===404||(response.status>=500&&response.status<600)))return null;
    const result=await response.json().catch(()=>({}));if(!response.ok){const error=Error(result.error||'Email recovery failed (HTTP '+response.status+')');error.status=response.status;throw error;}return result;
  };
  let verified;
  return {
    async verify(){const nonce=random();verified=await verifyGateAttestation(await api('/continuity/attestation?nonce='+nonce),nonce,policy);return verified;},
    async requestDkim(email,purpose='recover') {
      email=String(email).trim().toLowerCase();
      require(email.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),'Enter an email address');
      require(['enroll','recover'].includes(purpose),'Unknown email operation');
      await this.verify();
      const {receiverAddress}=await api('/continuity/email/config');
      require(typeof receiverAddress==='string'&&/^[^\s@?&#]+@[^\s@?&#]+\.[^\s@?&#]+$/.test(receiverAddress),'The recovery receiver is not configured');
      const pair=await ephemeral(),userId=email,ts=Date.now();
      const nonce=await emailRecoveryNonce(pair.publicKey,userId,ts);
      return {...pair,email,userId,ts,nonce,purpose,gatePublicKey:verified.publicKey,
        receiverAddress,subject:'dsmack-recover '+nonce,
        mailto:'mailto:'+receiverAddress+'?subject='+encodeURIComponent('dsmack-recover '+nonce)};
    },
    async waitDkim(context,{signal,onWaiting=()=>{}}={}) {
      require(context?.gatePublicKey,'Verify the email gate before sending recovery email');
      const timeoutMessage="We didn't receive your email at recover@soc1024.com within 5 minutes. Check it was sent from "+context.email+".";
      const expires=Date.now()+5*60_000;
      const deadline=new AbortController();
      const timer=setTimeout(()=>deadline.abort(),5*60_000);
      const combined=signal?AbortSignal.any([signal,deadline.signal]):deadline.signal;
      try {
        while(Date.now()<expires) {
          combined.throwIfAborted();
          let result;
          try { result=await api('/email-recovery/headers/'+context.nonce,undefined,{signal:combined,pending:true}); }
          catch(error) {
            if(combined.aborted)throw error;
            if(error.status>=400&&error.status<500&&error.status!==404)throw error;
          }
          if(result?.headers)return result.headers;
          onWaiting();
          await new Promise((resolve,reject)=>{
            const abort=()=>{clearTimeout(sleep);reject(combined.reason);};
            const sleep=setTimeout(()=>{combined.removeEventListener('abort',abort);resolve();},Math.min(2000,Math.max(0,expires-Date.now())));
            combined.addEventListener('abort',abort,{once:true});
            if(combined.aborted)abort();
          });
        }
        throw Error(timeoutMessage);
      } catch(error) {
        if(signal?.aborted)throw new DOMException('Email recovery cancelled','AbortError');
        if(deadline.signal.aborted||Date.now()>=expires)throw Error(timeoutMessage);
        throw error;
      } finally { clearTimeout(timer); }

    },
    async confirmDkim(context,headers,bundle) {
      require(context?.gatePublicKey,'Verify the email gate before sending recovery email');
      const label=emailRecoveryLabel(context.email,context.userId);
      const sealed=context.purpose==='enroll'?await seal(context.privateKey,context.gatePublicKey,bundle,label+'|enroll|'+context.nonce):undefined;
      const result=await api('/continuity/email/dkim',{
        purpose:context.purpose,email:context.email,userId:context.userId,ts:context.ts,
        publicKey:context.publicKey,nonce:context.nonce,headers,sealed});
      return context.purpose==='enroll'?result:await open(context.privateKey,context.gatePublicKey,result.sealed,label+'|recover|'+context.nonce);
    },
    async request(email,purpose='recover') {
      await this.verify();
      const pair=await ephemeral();
      return {...await api('/continuity/email/request',{email,purpose,publicKey:pair.publicKey}),...pair,purpose,gatePublicKey:verified.publicKey};
    },
    async confirm(context,code,bundle) {
      require(context?.gatePublicKey,'Verify the email gate before requesting a code');
      const sealed=context.purpose==='enroll'?await seal(context.privateKey,context.gatePublicKey,bundle,'dsmack-email-enroll/1|'+context.id):undefined;
      const result=await api('/continuity/email/confirm',{id:context.id,code,sealed});
      return context.purpose==='enroll'?result:await open(context.privateKey,context.gatePublicKey,result.sealed,'dsmack-email-recover/1|'+context.id);
    },
  };
}
