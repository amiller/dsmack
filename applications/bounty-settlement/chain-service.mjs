// Operator-selected mapping; HTTP callers cannot choose contracts, RPC or receipts.
import {need} from '../bounty-demo/core.mjs';
import {createChainObserver} from './chain-observation.mjs';
export function taskChainReader(store,selections,options){
 const snapshot=JSON.parse(JSON.stringify(selections));
 const observe=createChainObserver(snapshot,options);
 return async id=>{
  const {task,attempt}=store.detail(id),s=snapshot[id];
  if(!s)return {status:'not_configured'};
  need(s.terms.packageHash==='0x'+task.terms_sha256&&s.terms.policyHash==='0x'+task.checker_sha256,'chain mapping must match frozen task and policy');
  if(attempt)need(s.worker===attempt.payee,'chain worker must match assigned payee');
  if(attempt?.candidate_sha256&&s.expected_commitments)need(s.expected_commitments.candidate==='0x'+attempt.candidate_sha256,'chain candidate must match submission');
  return observe(id);
 };
}
