// Disposable loopback-only Anvil. All signatures, evidence and currency are synthetic.
// Run with reviewed precompiled WorkEscrow artifact; this performs no compilation.
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {openSync,closeSync,readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {syntheticFixture} from './rehearsal-fixture.mjs';
import {project} from './projection.mjs';
import {sha} from '../bounty-demo/core.mjs';

const [artifactFile,outputDirectory]=process.argv.slice(2);
if(!artifactFile||!outputDirectory)throw Error('Usage: node rehearse-local.mjs REVIEWED_ARTIFACT NEW_OUTPUT_DIRECTORY');
const out=resolve(outputDirectory);mkdirSync(out,{mode:0o700});
const artifact=JSON.parse(readFileSync(artifactFile)),cast=process.env.DSMACK_CAST||'cast';
const anvilBinary=process.env.DSMACK_ANVIL||'anvil';
const run=(args)=>execFileSync(cast,args,{encoding:'utf8',timeout:15000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const key=n=>'0x'+BigInt(n).toString(16).padStart(64,'0');
const addr=n=>run(['wallet','address','--private-key',key(n)]).toLowerCase();
const requester=addr(1),worker=addr(2),execution=addr(11),reviewer=addr(12),delivery=addr(13),adjudicator=addr(14);
const server=createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;await new Promise(r=>server.close(r));
const url='http://127.0.0.1:'+port,log=openSync(join(out,'anvil.log'),'wx',0o600);
const child=spawn(anvilBinary,['--host','127.0.0.1','--port',String(port),'--chain-id','31337','--silent'],{stdio:['ignore',log,log]});closeSync(log);
let fixture;const receipts=[];
async function rpc(method,params=[]){const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(10000)});assert.ok(response.ok);const body=await response.json();if(body.error)throw Error(JSON.stringify(body.error));return body.result;}
async function send(from,to,data,value='0x0'){
 const hash=await rpc('eth_sendTransaction',[{from,...(to?{to}:{}),data,value,gas:'0x989680'}]);
 for(let i=0;i<100;i++){const receipt=await rpc('eth_getTransactionReceipt',[hash]);if(receipt){receipts.push(receipt);return receipt;}await delay(25)}throw Error('receipt deadline');
}
const abi=(signature,...args)=>run(['calldata',signature,...args]);
const call=async(to,signature,...args)=>rpc('eth_call',[{to,data:abi(signature,...args)},'latest']);
const balance=async a=>BigInt(await rpc('eth_getBalance',[a,'latest']));
const ok=r=>assert.equal(BigInt(r.status),1n,'transaction failed');
const fail=r=>assert.equal(BigInt(r.status),0n,'expected refusal');
const topic=x=>run(['keccak',x]);
const typedHash=data=>{
 const type=data.types.Decision.map(e=>e.type+' '+e.name).join(',');
 const body=run(['abi-encode','f(bytes32,'+data.types.Decision.map(e=>e.type).join(',')+')',topic('Decision('+type+')'),...data.types.Decision.map(e=>String(data.message[e.name]))]);
 const d=data.domain;
 const domain=run(['abi-encode','f(bytes32,bytes32,bytes32,uint256,address)',topic('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),topic(d.name),topic(d.version),String(d.chainId),d.verifyingContract]);
 return topic('0x1901'+topic(domain).slice(2)+topic(body).slice(2));
};
try{
 for(let i=0;i<100;i++){try{if(await rpc('eth_chainId')==='0x7a69')break;}catch{}if(child.exitCode!==null)throw Error('owned Anvil exited');if(i===99)throw Error('Anvil readiness deadline');await delay(50);}
 for(const a of [requester,worker]){await rpc('anvil_setBalance',[a,'0x'+(1000n*10n**18n).toString(16)]);await rpc('anvil_impersonateAccount',[a]);}
 const deployed=await send(requester,null,artifact.bytecode.object);ok(deployed);const contract=deployed.contractAddress.toLowerCase();
 assert.equal((await rpc('eth_getCode',[contract,'latest'])).toLowerCase(),artifact.deployedBytecode.object.toLowerCase(),'deployed bytecode differs from selected artifact');
 fixture=syntheticFixture('review',worker);const t=fixture.store.task('board-search');
 const terms=['0x'+t.terms_sha256,'0x'+t.checker_sha256,requester,execution,reviewer,delivery,adjudicator,'0','1000000000000000000','3600','3600','3600'];
 const createSig='createTask((bytes32,bytes32,address,address,address,address,address,uint96,uint96,uint32,uint32,uint32))';
 const created=await send(requester,contract,abi(createSig,'('+terms.join(',')+')'),'0x'+(2n*10n**18n).toString(16));ok(created);
 const assigned=await send(requester,contract,abi('assign(uint256,address)','1',worker));ok(assigned);
 const taskId=BigInt(created.logs.find(x=>x.topics[0]===topic('TaskCreated(uint256,address,bytes32,bytes32,uint256)')).topics[1]).toString();
 const assignedLog=assigned.logs.find(x=>x.topics[0]===topic('Assigned(uint256,uint256,address,uint256,uint256)'));
 const assignmentId=BigInt(assignedLog.topics[1]).toString();assert.equal(BigInt(assignedLog.topics[2]).toString(),taskId);
 fixture.chain={...fixture.chain,contract,task_id:taskId,assignment_id:assignmentId,assignment_task_id:taskId};
 fixture.expected.chain=Object.fromEntries(['chain_id','contract','task_id','assignment_id','completion_pay_wei'].map(k=>[k,fixture.chain[k]]));
 const proposal=project(fixture),submitData=abi('submit(uint256,bytes32,bytes32,bytes32)',...proposal.submit.args);
 fail(await send(requester,contract,submitData)); // Mac operator is not the assigned payee.
 ok(await send(worker,contract,submitData));
 const words=(await call(contract,'assignment(uint256)',assignmentId)).slice(2).match(/.{64}/g);
 assert.equal(BigInt('0x'+words[0]).toString(),taskId);assert.equal('0x'+words[1].slice(-40),worker);assert.equal(BigInt('0x'+words[2]),2n);
 for(const [i,v] of [proposal.typed_data.message.candidate,proposal.typed_data.message.evidence,proposal.typed_data.message.delivery].entries())assert.equal('0x'+words[6+i],v);
 const digest=typedHash(proposal.typed_data);assert.equal(digest,await call(contract,'decisionDigest(uint256,uint8)',assignmentId,'2'));
 const dataFile=join(out,'synthetic-typed-data.json');writeFileSync(dataFile,JSON.stringify(proposal.typed_data,null,2)+'\n');
 const signatures=[11,12,13].map(n=>run(['wallet','sign','--data','--from-file',dataFile,'--private-key',key(n)]));
 for(let i=0;i<3;i++)assert.match(run(['wallet','verify','--no-hash','--address',[execution,reviewer,delivery][i],digest,signatures[i]]),/success|succeeded|valid/i);
 const resolveData=abi('resolve(uint256,uint8,bytes,bytes,bytes)',assignmentId,'2',...signatures);
 // Valid signatures under altered domain/body must refuse before a valid resolve.
 const mutationResults=[];
 for(const [section,k,v] of [['domain','chainId','8453'],['domain','verifyingContract','0x'+'9'.repeat(40)],['domain','version','1'],...Object.entries({assignmentId:'9',taskId:'9',packageHash:'0x'+'f'.repeat(64),policyHash:'0x'+'f'.repeat(64),worker:requester,candidate:'0x'+'f'.repeat(64),evidence:'0x'+'f'.repeat(64),delivery:'0x'+'f'.repeat(64),outcome:1,payout:'2'}).map(([k,v])=>['message',k,v])]){
  const mutated=structuredClone(proposal.typed_data);mutated[section][k]=v;const path=join(out,'mutated-typed-data.json');writeFileSync(path,JSON.stringify(mutated));
  const wrong=run(['wallet','sign','--data','--from-file',path,'--private-key',key(12)]);
  fail(await send(requester,contract,abi('resolve(uint256,uint8,bytes,bytes,bytes)',assignmentId,'2',signatures[0],wrong,signatures[2])));mutationResults.push(section+'.'+k);
 }
 ok(await send(requester,contract,resolveData));assert.equal(BigInt(await call(contract,'withdrawable(address)',worker)),10n**18n);
 fail(await send(requester,contract,resolveData));assert.equal(BigInt(await call(contract,'withdrawable(address)',worker)),10n**18n);
 const before=await balance(worker),contractBefore=await balance(contract);const withdrawn=await send(worker,contract,abi('withdraw()'));ok(withdrawn);
 const gas=BigInt(withdrawn.gasUsed)*BigInt(withdrawn.effectiveGasPrice);assert.equal(await balance(worker)-before+gas,10n**18n);assert.equal(contractBefore-await balance(contract),10n**18n);
 assert.equal(BigInt(await call(contract,'withdrawable(address)',worker)),0n);fail(await send(worker,contract,abi('withdraw()')));
 const closed=await send(requester,contract,abi('closeTask(uint256)',taskId));ok(closed);ok(await send(requester,contract,abi('withdraw()')));assert.equal(await balance(contract),0n);
 // A separate submitted assignment receives no authority signatures; after both
 // fixed windows the requester must expire, close AND withdraw to receive funds.
 const recoveryCreated=await send(requester,contract,abi(createSig,'('+terms.join(',')+')'),'0x'+(10n**18n).toString(16));ok(recoveryCreated);
 const recoveryTask=BigInt(recoveryCreated.logs.find(x=>x.topics[0]===topic('TaskCreated(uint256,address,bytes32,bytes32,uint256)')).topics[1]).toString();
 const recoveryAssigned=await send(requester,contract,abi('assign(uint256,address)',recoveryTask,worker));ok(recoveryAssigned);
 const recoveryId=BigInt(recoveryAssigned.logs.find(x=>x.topics[0]===topic('Assigned(uint256,uint256,address,uint256,uint256)')).topics[1]).toString();
 ok(await send(worker,contract,abi('submit(uint256,bytes32,bytes32,bytes32)',recoveryId,...proposal.submit.args.slice(1))));
 fail(await send(requester,contract,abi('expireUnresolved(uint256)',recoveryId)));
 await rpc('evm_increaseTime',[7201]);await rpc('evm_mine');
 ok(await send(requester,contract,abi('expireUnresolved(uint256)',recoveryId)));
 assert.equal(BigInt(await call(contract,'withdrawable(address)',requester)),0n,'expiry is not a withdrawal credit');
 ok(await send(requester,contract,abi('closeTask(uint256)',recoveryTask)));
 assert.equal(BigInt(await call(contract,'withdrawable(address)',requester)),10n**18n);
 const refundBefore=await balance(requester);const refund=await send(requester,contract,abi('withdraw()'));ok(refund);
 assert.equal(await balance(requester)-refundBefore+BigInt(refund.gasUsed)*BigInt(refund.effectiveGasPrice),10n**18n);
 fail(await send(requester,contract,abi('resolve(uint256,uint8,bytes,bytes,bytes)',recoveryId,'2',...signatures)));
 assert.equal(BigInt(await call(contract,'withdrawable(address)',worker)),0n);assert.equal(await balance(contract),0n);
 const result={schema:'dsmack-synthetic-settlement-roundtrip/1',synthetic:true,genuine_bounty:false,real_funds:false,chain_id:31337,contract,taskId,assignmentId,artifact_sha256:sha(readFileSync(artifactFile)),typed_data_digest:digest,digest_matches_deployed_contract:true,operator_submit_refused:true,payee_submit_passed:true,mutations_refused:mutationResults,duplicate_resolve_refused:true,worker_withdrawal_received_wei:'1000000000000000000',worker_receipt:withdrawn.transactionHash,worker_balance_gas_adjusted:true,requester_unspent_refund_received:true,submitted_timeout_refund_wei:'1000000000000000000',submitted_timeout_refund_receipt:refund.transactionHash,expiry_not_withdrawal_credit:true,expired_assignment_resolve_refused:true,chain_time_accelerated_seconds:7201,escrow_final_balance_wei:'0'};
 writeFileSync(join(out,'RESULT.json'),JSON.stringify(result,null,2)+'\n');writeFileSync(join(out,'receipts.json'),JSON.stringify(receipts,null,2)+'\n');console.log(JSON.stringify(result));
}finally{
 fixture?.store.close();child.kill('SIGTERM');for(let i=0;i<100&&child.exitCode===null&&child.signalCode===null;i++)await delay(25);if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));}
 writeFileSync(join(out,'cleanup.json'),JSON.stringify({owned_anvil_pid:child.pid,exited:child.exitCode!==null||child.signalCode!==null})+'\n');
}
