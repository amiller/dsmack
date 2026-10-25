export function storageKeys(moduleURL){
 const base=new URL('.',moduleURL).pathname;
 const prefix=base==='/arcade-pilot/'?'dsmack-arcade':'dsmack-bounty:'+base;
 return {store:prefix+'-attempt',intent:prefix+'-create-intent',history:prefix+'-history'};
}
export const eligible=a=>!!a&&['verified','claim_uncertain','claim_failed'].includes(a.state)&&a.verdict?.accepted===true&&a.verdict.verification_level==='full';
export function rewardAmount(wei){if(!/^[0-9]+$/.test(wei??''))return 'Published testnet reward';const n=BigInt(wei),whole=n/10n**18n,fraction=String(n%10n**18n).padStart(18,'0').replace(/0+$/,'');return `${whole}${fraction?'.'+fraction:''} test ETH`;}
export function progress(a){
 if(!a)return {title:'No attempt registered',execution:'Choose a commit',checks:'Not run',payment:'Not available',next:'Connect your receiving wallet and register your full commit below.',canRun:false,canClaim:false};
 const good=eligible(a),claim=a.claim;
 let execution='Waiting for your run request',checks='Not run',next='Choose your own Mac or request a best-effort Mac run.';
 if(a.state==='queued'){execution='Waiting for a Mac';next='Your request is queued until an enrolled Mac picks it up.';}
 if(a.state==='preparing'){execution='Preparing the pinned task';next='The service is building the task inputs for this exact commit.';}
 if(a.state==='prepared'){execution=a.node_lease?'Picked up by a Mac':'Task prepared';next=a.node_lease?'A node has picked up this task. Waiting for its original execution evidence.':'The signed task is ready. Your Mac client can download and run it.';}
 if(a.state==='verifying'){execution='Evidence uploaded';checks='Verification in progress';next='The verifier is checking the original execution evidence and the seven browser checks.';}
 if(good){execution='Execution verified';checks='All seven checks passed';next='Prepare the reward steps below. Each on-chain step still needs an explicit wallet confirmation.';}
 if(a.state==='failed'){execution='Result received';checks='Checks did not pass';next='This attempt did not pass. Read the result details, fix your code, then register a new commit.';}
 if(/failed|error|uncertain/.test(a.state??'')&&!good&&a.state!=='failed'){execution='Needs attention';checks='No verified passing result';next='The run or verification could not finish. Keep this attempt record and inspect the details before trying again; this page will not restart it.';}
 let payment=good?'Ready to prepare reward':'Waiting for passing checks';
 if(a.claim_pending_job_id||a.claim_state==='pending')payment='Checking escrow state';
 else if(['failed','uncertain'].includes(a.claim_state))payment='Escrow check needs another observation';
 else if(claim?.stage==='submit')payment='Ready to submit result commitments';
 else if(claim?.stage==='resolve')payment='Submission recorded; ready to authorize reward';
 else if(claim?.stage==='withdraw')payment='Reward credited; ready to withdraw';
 else if(claim?.stage==='received'&&claim.payment_received===true){payment='Withdrawal confirmed';next='The verifier observed your successful withdrawal on Base Sepolia.';}
 return {title:a.state==='failed'?'Your attempt did not pass':good?'Your checks passed':'Your attempt',execution,checks,payment,next,canRun:a.state==='registered',canClaim:good};
}
export const walletSteps={submit:{label:'Sign: submit verified result',description:'Record this candidate, evidence and delivery in escrow. The next two steps credit and withdraw the reward.'},resolve:{label:'Sign: relay reward approval',description:'Send the verifier’s existing signatures to escrow to credit the reward. Anyone may relay this step; it may already be done for you.'},withdraw:{label:'Sign: withdraw reward to my wallet',description:'Withdraw the credited test ETH from escrow to your receiving wallet.'}};
export function assertTransaction(task,record,account,chain,tx){
 if(!account||account!==record.payee)throw Error('Connect the receiving wallet used for this attempt.');
 if(chain!=='0x14a34')throw Error('Switch your wallet to Base Sepolia (chain84532).');
 if(!tx||Object.keys(tx).sort().join()!==['chainId','data','from','to','value'].sort().join()||tx.to?.toLowerCase()!==task.contract||tx.from?.toLowerCase()!==record.payee||tx.chainId!=='0x14a34'||tx.value!=='0x0'||!/^0x[0-9a-f]+$/.test(tx.data))throw Error('The transaction does not match this task and receiving wallet.');
}
