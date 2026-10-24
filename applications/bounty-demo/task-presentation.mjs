// Read-only operator notes. Never mutate terms, attempt state, verdict or money.
import {exact,need} from './core.mjs';
const id=x=>typeof x==='string'&&/^[a-z0-9-]{1,80}$/.test(x);
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
export function taskPresentation(store,entries=[]){
  need(Array.isArray(entries)&&entries.length<=100,'bounded task annotations required');
  const selected=new Map();
  for(const row of entries){
    exact(row,['task_id','terms_sha256','checker_sha256','reason','noted_at','replacement']);
    need(id(row.task_id)&&hash(row.terms_sha256)&&hash(row.checker_sha256)&&row.reason==='transport-blocked'&&Number.isSafeInteger(row.noted_at)&&row.noted_at>0,'invalid operator annotation');
    need(!selected.has(row.task_id),'duplicate task annotation');
    const task=store.task(row.task_id);need(task.terms_sha256===row.terms_sha256&&task.checker_sha256===row.checker_sha256,'annotation subject mismatch');
    let replacement=null;
    if(row.replacement!==null){
      exact(row.replacement,['task_id','terms_sha256']);need(id(row.replacement.task_id)&&row.replacement.task_id!==row.task_id&&hash(row.replacement.terms_sha256),'invalid replacement task');
      const next=store.task(row.replacement.task_id);need(next.terms_sha256===row.replacement.terms_sha256,'replacement terms mismatch');replacement={...row.replacement};
    }
    selected.set(row.task_id,{...row,replacement,source:'operator-note',financial_authority:false,verification_authority:false});
  }
  return id=>selected.has(id)?structuredClone(selected.get(id)):null;
}
