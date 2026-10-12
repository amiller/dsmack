import {createPublicClient,http,parseAbi,decodeFunctionData,decodeEventLog,keccak256,type Hex} from 'npm:viem@2.38.0';
import type {BudgetDependencies} from './sponsor-policy.ts';
const OWNER='0xe45C80da8A992447E9Da6d2d82Fe4b6Fa2d48C61',REGISTRY='0xd4B33C83576a6049d29c6B849ec73491e52781a0',CDS='0x9e513E19fCE48563c89E91C4ca571b1B089484a4',BUILD='0xac1f04d42034e3ce2a387cadb226626b995990ad6d7fba5d351d6ae8ffc9bdfb',ZERO=('0x'+'00'.repeat(32)) as Hex;
const need=(ok:unknown,message:string)=>{if(!ok)throw Error(message);};
const client=createPublicClient({transport:http('https://sepolia.base.org',{timeout:20000,retryCount:0})});
const readAbi=parseAbi(['function owner() view returns(address)','function keyEpochs(bytes32) view returns(uint64)','function buildId() view returns(bytes32)','function isAdmitted(bytes32,uint256) view returns(bool)','function getL1FeeUpperBound(uint256) view returns(uint256)','function getOperatorFee(uint256) view returns(uint256)']);
const abi=JSON.parse(await Deno.readTextFile(new URL('./abi.json',import.meta.url)));
// Admission baseline: the legacy CDRegistry buildId, or with a MeasurementRegistry the pinned M's open window.
export type MeasuredAdmission={registry:Hex,measurement:Hex};
async function admitted(blockNumber:bigint,measured?:MeasuredAdmission){
 if(measured)return await client.readContract({address:measured.registry,abi:readAbi,functionName:'isAdmitted',args:[measured.measurement,blockNumber],blockNumber});
 return await client.readContract({address:CDS,abi:readAbi,functionName:'buildId',blockNumber})===BUILD;
}
export function nativeSponsorChecks(protectedFutureReserve:bigint,measured?:MeasuredAdmission):BudgetDependencies{return {
 async feeEnvelope(gas,bytes){need(bytes<=40000,'approved raw size exceeded');const oracle='0x420000000000000000000000000000000000000f';return 2n*await client.readContract({address:oracle,abi:readAbi,functionName:'getL1FeeUpperBound',args:[BigInt(bytes)]})+2n*await client.readContract({address:oracle,abi:readAbi,functionName:'getOperatorFee',args:[gas]});},
 async preSignCheck(requiredFee=0n){
  need(await client.getChainId()===84532,'wrong sponsorship chain');const block=await client.getBlock(),now=BigInt(Math.floor(Date.now()/1000));need(block.timestamp<=now+5n&&now<block.timestamp+45n,'stale/future chain clock');
  need((await client.readContract({address:REGISTRY,abi:readAbi,functionName:'owner',blockNumber:block.number})).toLowerCase()===OWNER.toLowerCase()&&(await client.readContract({address:CDS,abi:readAbi,functionName:'owner',blockNumber:block.number})).toLowerCase()===OWNER.toLowerCase(),'native owner changed');
  need(await admitted(block.number,measured)&&await client.readContract({address:REGISTRY,abi:readAbi,functionName:'keyEpochs',args:[ZERO],blockNumber:block.number})===2n,'final C baseline/epoch changed');
  need(await client.getBalance({address:OWNER,blockNumber:block.number})>=protectedFutureReserve+10000000000000n+requiredFee,'protected native capacity/balance exhausted');
  need((await client.getBlock({blockNumber:block.number})).hash===block.hash,'sponsorship block reorged');
 },
 async verifyHello(unknownBody){
  const body=unknownBody as Record<string,string>;need(/^0x[0-9a-f]{64}$/.test(body.joinTx||''),'invalid join transaction');const hash=body.joinTx as Hex;
  const [receipt,transaction]=await Promise.all([client.getTransactionReceipt({hash}),client.getTransaction({hash})]);need(receipt.status==='success'&&transaction.to?.toLowerCase()===REGISTRY.toLowerCase()&&transaction.from.toLowerCase()===OWNER.toLowerCase(),'join route/status differs');
  const decoded=decodeFunctionData({abi:abi.demo,data:transaction.input});need(decoded.functionName==='execute','not native execute');const r=(decoded.args as any)[0];need(Number(r.action)===0&&r.category==='0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6'&&r.owner.toLowerCase()===OWNER.toLowerCase()&&r.memberSigner.toLowerCase()===OWNER.toLowerCase()&&r.scope===ZERO,'not selected native Join');
  const events=receipt.logs.filter(log=>log.address.toLowerCase()===REGISTRY.toLowerCase()).map(log=>{try{return decodeEventLog({abi:abi.demo,data:log.data,topics:log.topics}) as any;}catch{return undefined;}}).filter(event=>event?.eventName==='Checked');need(events.length===1,'ambiguous Join check');const args=events[0]!.args as any;
  const block=await client.getBlock({blockNumber:receipt.blockNumber}),now=BigInt(Math.floor(Date.now()/1000));need(block.hash===receipt.blockHash&&block.timestamp<=now+5n&&now<block.timestamp+120n,'stale/reorged HELLO join');
  need(await client.readContract({address:REGISTRY,abi:readAbi,functionName:'keyEpochs',args:[ZERO],blockNumber:receipt.blockNumber})===2n&&await admitted(receipt.blockNumber,measured),'join belongs to old epoch/admission');
  need(args.category===r.category&&args.member===body.member&&/^0x[0-9a-f]{130}$/.test(body.sessionPublic||'')&&args.sessionKeyHash===keccak256(body.sessionPublic as Hex),'HELLO recipient binding differs');need((await client.getBlock({blockNumber:receipt.blockNumber})).hash===receipt.blockHash,'HELLO block reorged during reads');return {joinTx:hash,sessionKeyHash:args.sessionKeyHash as Hex,member:args.member as Hex};
 }
};}

const factory='0x18B5c72c48622661aEEadb596443C5E0E99F5188',badges='0x6Ac5fb83f5BF615842b5A9a6C50b8011FaB50c3B';
const personalAbi=parseAbi(['function accountAddress(uint256,uint256) view returns(address)','function isAccount(address) view returns(bool)','function participantOf(address) view returns(uint256)']);
export function pilotAccountAddress(x:bigint,y:bigint){return client.readContract({address:factory,abi:personalAbi,functionName:'accountAddress',args:[x,y]});}
export async function pilotAccountEligibleForFirstClaim(account:import('npm:viem@2.38.0').Address){return await client.readContract({address:factory,abi:personalAbi,functionName:'isAccount',args:[account]})&&await client.readContract({address:badges,abi:personalAbi,functionName:'participantOf',args:[account]})===0n;}
