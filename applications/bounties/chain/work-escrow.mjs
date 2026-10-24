// Exact WorkEscrow v2 public decision domain. Signing/recovery uses cast or the
// selected original actor; this module never implements elliptic-curve crypto.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {need,address,hash} from '../service/core.mjs';
const exec=promisify(execFile),uint=v=>typeof v==='string'&&/^[1-9][0-9]*$/.test(v)&&BigInt(v)<2n**256n;
export function decisionTypedData({contract,assignment_id,task_id,package_hash,policy_hash,payee,candidate,evidence,delivery,payout}){
 need(address(contract)&&address(payee)&&uint(assignment_id)&&uint(task_id)&&uint(payout),'invalid chain identity');for(const v of [package_hash,policy_hash,candidate,evidence,delivery])need(hash(v),'invalid chain commitment');
 return {types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],Decision:[{name:'assignmentId',type:'uint256'},{name:'taskId',type:'uint256'},{name:'packageHash',type:'bytes32'},{name:'policyHash',type:'bytes32'},{name:'worker',type:'address'},{name:'candidate',type:'bytes32'},{name:'evidence',type:'bytes32'},{name:'delivery',type:'bytes32'},{name:'outcome',type:'uint8'},{name:'payout',type:'uint256'}]},primaryType:'Decision',domain:{name:'DsmackWorkEscrow',version:'2',chainId:84532,verifyingContract:contract},message:{assignmentId:assignment_id,taskId:task_id,packageHash:'0x'+package_hash,policyHash:'0x'+policy_hash,worker:payee,candidate:'0x'+candidate,evidence:'0x'+evidence,delivery:'0x'+delivery,outcome:2,payout}};
}
export async function transactions(cast,context,signatures){
 decisionTypedData(context);need(Array.isArray(signatures)&&signatures.length===3&&signatures.every(s=>/^0x[0-9a-fA-F]{130}$/.test(s)),'three verifier signatures required');
 const encode=async(signature,...args)=>{const r=await exec(cast,['calldata',signature,...args],{timeout:10000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin'}});const data=r.stdout.trim();need(/^0x[0-9a-f]+$/.test(data),'cast encoding refused');return {chainId:'0x14a34',to:context.contract,from:context.payee,value:'0x0',data};};
 return {submit:await encode('submit(uint256,bytes32,bytes32,bytes32)',context.assignment_id,'0x'+context.candidate,'0x'+context.evidence,'0x'+context.delivery),resolve:await encode('resolve(uint256,uint8,bytes,bytes,bytes)',context.assignment_id,'2',...signatures),withdraw:await encode('withdraw()')};
}
