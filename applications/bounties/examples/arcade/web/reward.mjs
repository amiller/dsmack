import {walletSteps,assertTransaction} from './view.mjs';
const order={submit:1,resolve:2,withdraw:3,received:4};
export class RewardFlow{
 constructor({api,record,persist,task,wallet,account,onChange,requestId}){Object.assign(this,{api,record,persist,task,wallet,account,onChange,requestId});this.claim=null;this.busy=false;}
 update(c){
  this.claim=c;if(c.stage||['failed','uncertain'].includes(c.status)){this.record.claimRequest=null;this.persist(this.record);}const pending=this.record.pendingWallet;
  if(pending&&order[c.stage]>order[pending.stage]){this.record.pendingWallet=null;this.persist(this.record);}
  const waiting=!!c.pending_job_id||c.status==='pending';
  let label='Prepare my reward steps',text='This checks escrow and prepares the next step without sending a wallet transaction.';
  if(waiting){label='Check reward preparation';text='The escrow observation is in progress. This button reads its status.';}
  else if(c.stage==='gas_grant_pending'){label='Check testnet gas grant';text='The operator is sending testnet gas to your receiving wallet. No wallet action is needed yet; your wallet will still sign each reward step.';}
  else if(c.stage==='received'&&c.payment_received===true){label='View confirmed withdrawal';text='The verifier observed a successful withdrawal. No further wallet transaction is needed.';}
  else if(c.transactions?.[c.stage]&&walletSteps[c.stage]){label=this.record.pendingWallet?'Check my submitted transaction':'Check for an updated reward step';text=this.record.pendingWallet?'A wallet request has already been made. Do not submit it again. Check escrow to see whether it was recorded.':walletSteps[c.stage].description;}
  else if(['failed','uncertain'].includes(c.status)){label='Check escrow again';text='The last escrow observation did not finish. A fresh observation will not resend your wallet transaction.';}
  this.onChange({claim:c,label,text,waiting,walletStep:!waiting&&!this.record.pendingWallet&&walletSteps[c.stage]&&c.transactions?.[c.stage]?c.stage:null});
 }
 async read(){const c=await this.api('attempts/'+this.record.attempt_id+'/claim');this.update(c);return c;}
 async continue(){
  if(this.busy)return;this.busy=true;
  try{const c=await this.read();if(c.pending_job_id||c.status==='pending'||c.stage==='received')return;
   if(c.transactions?.[c.stage]&&!this.record.pendingWallet)return; // Present an explicit signing button.
   const id=this.record.claimRequest??this.requestId();this.record.claimRequest=id;this.persist(this.record);
   try{await this.api('attempts/'+this.record.attempt_id+'/claim','POST',{request_id:id},this.record.capability);}catch(e){throw Error('Could not confirm whether the escrow check was queued. Use the same button to recover that request. '+e.message);}
   this.record.claimRequest=null;this.persist(this.record);this.update({status:'pending'});
  }finally{this.busy=false;}
 }
 async send(stage){
  if(this.busy)return;this.busy=true;
  try{
   if(this.record.pendingWallet)throw Error('A wallet request is already pending or uncertain. Do not send it again.');
   const displayed=this.claim,current=await this.api('attempts/'+this.record.attempt_id+'/claim');
   if(current.pending_job_id||current.stage!==stage||JSON.stringify(current.transactions?.[stage])!==JSON.stringify(displayed?.transactions?.[stage])){this.update(current);throw Error('The reward step changed. Review the updated step before signing.');}
   const tx=current.transactions[stage];assertTransaction(this.task,this.record,this.account(),await this.wallet.request({method:'eth_chainId'}),tx);
   this.record.pendingWallet={stage,hash:null};this.persist(this.record);this.update(current);
   try{const hash=await this.wallet.request({method:'eth_sendTransaction',params:[tx]});if(!/^0x[0-9a-fA-F]{64}$/.test(hash))throw Error('The wallet returned an invalid transaction hash.');this.record.pendingWallet.hash=hash;this.persist(this.record);this.update(current);return hash;}
   catch(e){if(e.code===4001){this.record.pendingWallet=null;this.persist(this.record);this.update(current);throw Error('Wallet request cancelled. No transaction was sent by this page.');}throw Error('The wallet response is uncertain. Do not send again; inspect wallet activity and check escrow status.');}
  }finally{this.busy=false;}
 }
}
export const ENROLL_MAX=65536;
const exactKeys=(v,keys)=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join();
export async function signEnrollment({raw,account,task,api,wallet,now=Date.now()}){
 const refuse=m=>{throw Error('Enrollment file refused: '+m+'. Nothing was signed.');};
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>ENROLL_MAX)refuse('not a REG-AUTH.json under 64 KB');
 if(!account)refuse('connect the wallet that will receive rewards first');
 let f;try{f=JSON.parse(raw);}catch{refuse('not JSON');}
 const r=f?.request,c=f?.challenge;
 if(!exactKeys(f,['request','challenge'])||!exactKeys(r,['purpose','payee','request_id','candidate_commit'])||!exactKeys(c,['authorization_id','message','expires_at']))refuse('unexpected fields; use the file written by client.py authorization');
 if(r.purpose!=='registration'||r.candidate_commit!==null)refuse('not a registration authorization');
 if(r.payee!==account)refuse('payee is not the connected wallet');
 if(typeof r.request_id!=='string'||!/^[A-Za-z0-9_-]{16,100}$/.test(r.request_id)||typeof c.authorization_id!=='string'||typeof c.message!=='string'||!Number.isInteger(c.expires_at))refuse('malformed request or challenge');
 if(c.expires_at<=Math.floor(now/1000))refuse('expired; run client.py authorization again');
 const lines=c.message.split('\n'),want=[`Task: ${task.slug}`,`Policy: ${task.policy_sha256}`,'Purpose: registration',`Payee: ${account}`,'Candidate: none',`Request: ${r.request_id}`,`Authorization: ${c.authorization_id}`,`Expires: ${c.expires_at}`];
 if(lines[0]!=='Dsmack Arcade authorization / 1'||!want.every(x=>lines.includes(x)))refuse('message is not for this task, wallet and request');
 const s=await api('authorization-challenges','POST',{request_id:r.request_id,purpose:'registration',payee:account,candidate_commit:null});
 if(s.authorization_id!==c.authorization_id||s.message!==c.message||s.expires_at!==c.expires_at)refuse('the service does not hold this exact challenge');
 const hex='0x'+Array.from(new TextEncoder().encode(s.message),x=>x.toString(16).padStart(2,'0')).join('');
 let sig;try{sig=await wallet.request({method:'personal_sign',params:[hex,account]});}catch(e){throw Error(e?.code===4001?'Signing cancelled in the wallet. Nothing was signed or sent.':'The wallet did not return a signature.');}
 if(typeof sig!=='string'||!/^0x[0-9a-fA-F]{130}$/.test(sig))throw Error('The wallet returned an invalid signature.');
 return sig;
}
