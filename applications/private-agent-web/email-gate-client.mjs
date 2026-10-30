import {verify} from '@phala/dcap-qvl';
import {bytes,random,ephemeral,seal,open,quoteBinding} from './email-gate-crypto.mjs';
const hex=(value)=>Array.from(new Uint8Array(value),b=>b.toString(16).padStart(2,'0')).join('');
const unhex=(value)=>{if(!/^(?:[0-9a-f]{2})*$/i.test(value))throw Error('Invalid attestation hex');return Uint8Array.from(value.match(/../g)||[],x=>parseInt(x,16));};
const cat=(...parts)=>new Uint8Array(parts.flatMap(p=>Array.from(p)));
const require=(ok,message)=>{if(!ok)throw Error(message);};
export async function verifyGateAttestation(attestation,nonce,policy) {
  require(policy?.appId&&policy?.composeHash&&policy?.mrtd&&policy?.rtmr?.length===3,'Email gate attestation policy is not configured');
  require(attestation.nonce===nonce,'Email gate returned a stale nonce');
  const result=await verify(unhex(attestation.quote),attestation.collateral,Math.floor(Date.now()/1000));
  require(['UpToDate','SWHardeningNeeded'].includes(result.status),'Email gate TDX TCB status refused: '+result.status);
  const report=result.report.asTd10()||result.report.asTd15()?.base;
  require(report,'Email gate requires a TDX quote');
  require(hex(report.reportData)===hex(await quoteBinding(nonce,attestation.publicKey)),'Email gate key or challenge is not bound to its quote');
  require(hex(report.mrTd)===policy.mrtd,'Email gate OS measurement differs');
  for(let i=0;i<3;i++)require(hex(report['rtMr'+i])===policy.rtmr[i],'Email gate boot measurement differs');
  let mr=new Uint8Array(48),ready=false;const boot={};
  for(const event of attestation.eventLog) {
    if(event.imr!==3)continue;
    const eventType=new Uint8Array(4);new DataView(eventType.buffer).setUint32(0,event.event_type,true);
    const preimage=cat(eventType,bytes(':'+event.event+':'),unhex(event.event_payload));
    require(hex(await crypto.subtle.digest('SHA-384',preimage))===event.digest,'Email gate event digest differs');
    mr=new Uint8Array(await crypto.subtle.digest('SHA-384',cat(mr,unhex(event.digest))));
    if(!ready&&['app-id','compose-hash'].includes(event.event)) {
      require(!boot[event.event],'Duplicate email gate boot identity');boot[event.event]=event.event_payload;
    }
    if(event.event==='system-ready')ready=true;
  }
  require(hex(mr)===hex(report.rtMr3),'Email gate event log does not match its quote');
  require(ready&&boot['app-id']===policy.appId&&boot['compose-hash']===policy.composeHash,'Email gate app or compose is not approved');
  return {publicKey:attestation.publicKey,status:result.status};
}
export function createEmailGate({base='',policy}) {
  const api=async(path,body)=>{
    const response=await fetch(base+path,{method:body?'POST':'GET',headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined,cache:'no-store'});
    const result=await response.json();if(!response.ok)throw Error(result.error||'Email recovery failed');return result;
  };
  let verified;
  return {
    async verify(){const nonce=random();verified=await verifyGateAttestation(await api('/continuity/attestation?nonce='+nonce),nonce,policy);return verified;},
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
