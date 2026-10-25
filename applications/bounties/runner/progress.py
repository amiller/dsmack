"""Read-only attempt progress: server state, local run files and reward stage in plain words."""
import shlex

RUN_LIMIT=1320  # portable.coordinator subprocess timeout
CLOSED='this attempt cannot continue; keep its files. To try again, start a new attempt (README step 3) with the same or a new commit.'

def facts(local,native,read_doc):
    """Observe which local milestone files exist; never launches, deletes or rewrites."""
    control=local/('attempt-'+native+'.control') if native else None
    f={'local_dir':local.exists(),'task':(local/'task.json').exists(),'control':bool(control) and control.exists(),'plan':bool(control) and (control/'plan.json').exists(),'launch_requested_at':None,'controller':None,'submitted':(local/'EVIDENCE-SUBMITTED.json').exists(),'cleaned':(local/'CLEANUP-COMPLETE.json').exists()}
    if f['plan'] and (control/'launch-requested.json').exists():f['launch_requested_at']=int((control/'launch-requested.json').stat().st_mtime)
    if f['plan'] and (control/'controller-result.json').exists():
        r=read_doc(control/'controller-result.json');f['controller']='returned' if r.get('controller_returned') is True else 'error:'+str(r.get('error'))
    return f

def commands(base,attempt,registration):
    """Shell-quoted commands using the caller's own config, attempt and registration paths."""
    def c(sub,*extra):
        reg=['--registration',registration or 'REGISTRATION.json'] if sub=='prepare' else []
        return shlex.join([*base,sub,'--attempt',attempt,*reg,*extra])
    return c

def step(action,command=None,stop=False):return {'action':action,'command':command,'stop':stop}

def describe(a,claim,f,mode,now,c):
    """Map one attempt to (stage, message, next). Paid only after an observed withdrawal."""
    s=a['state'];check=step('Check again in a few minutes.',c('progress'));closed=lambda why:step(why+'; '+CLOSED+' Raw service record:',c('status'))
    if s=='registered':return 'registered','Attempt recorded; no execution requested yet.',step('Request your signed task.',c('prepare'))
    if mode=='best_effort':
        if s=='queued':return 'queued_for_preparation','The service is preparing the task for the shared node queue.',check
        if s=='prepared' and not a.get('node_lease'):return 'waiting_for_node','The task is prepared and waiting for a registered node to lease it.',check
        if s=='prepared':return 'leased_by_node',f'A node leased this task {(now-a["node_lease"]["created_at"])//60} min ago. The service has not received its evidence yet.',check
    if s=='preparing':return 'preparing','The service is building your signed task.',step('Repeat the same prepare command; it reuses its saved request.',c('prepare'))
    if s=='preparation_failed' or s.startswith('prepareExecution_'):return 'preparation_failed','The service could not prepare this task ('+s+').',closed('Preparation failed')
    if s=='prepared':
        if a.get('submission_id') and not f['submitted']:return 'submitting','Evidence upload started but has not completed.',step('Repeat submit; it resumes from the offsets the service stored.',c('submit'))
        if not f['task']:
            if f['local_dir']:return 'downloading','A previous download stopped part way.',step('Resume the download.',c('prepare','--resume-download'))
            return 'downloading','Signed task ready on the service; not yet downloaded to this Mac.',step('Download and prepare the task.',c('prepare'))
        if not f['control']:return 'local_prepare_incomplete','Task downloaded but the launch plan was not written.',step('Repeat prepare; it rebuilds only the launch plan from the same task.',c('prepare'))
        if not f['plan']:return 'local_prepare_uncertain','A launch-plan directory exists without a plan.',step('Do not delete or rerun anything. Send this output and the raw record to the maintainer.',c('status'),True)
        if f['launch_requested_at'] is None:return 'ready_to_run','Launch plan saved. Nothing has run yet.',step('Check, then run (the run takes up to 22 min).',c('check')+' && '+c('run'))
        if f['controller'] is None:
            age=now-f['launch_requested_at']
            if age<=RUN_LIMIT+60:return 'launch_requested',f'Launch was requested {age//60} min ago; no result is recorded yet. This does not show whether the VM is still running.',step('If your run command is still open, wait for it to return. Do not start run again. Afterwards:',c('progress'))
            return 'run_outcome_unknown',f'Launch was requested {age//60} min ago and no controller result was recorded. The run cannot be relaunched.',step('Do not delete or rerun anything. Send this output and the raw record to the maintainer.',c('status'),True)
        if f['controller']!='returned':return 'run_failed','The VM controller stopped with '+f['controller']+'.',closed('The run did not finish')
        return 'ready_to_submit','The run finished locally. The service has not received evidence yet.',step('Upload the evidence.',c('submit'))
    if s=='verifying':return 'verifying','The service is checking your evidence and running the protected checker.',check
    clean=c('cleanup') if f['task'] and not f['cleaned'] else None
    if s=='failed':return 'rejected','Evidence verified, but the commit did not pass the task checks. No reward for this attempt.',step('Free the task disks.' if clean else 'Nothing left to do for this attempt.',clean)
    if s=='verification_error' or s.startswith('verifyEvidence_'):return 'verification_error','The service could not finish verification ('+s+').',closed('Verification did not finish')
    if s in ('verified','claim_uncertain','claim_failed'):
        then=' Then free the task disks:' if clean else ''
        k=claim or {}
        if k.get('stage')=='received' and k.get('payment_received') is True:return 'paid','Withdrawal to your payee observed on Base Sepolia.',step('Free the task disks.' if clean else 'Done.',clean)
        if k.get('pending_job_id') or k.get('status')=='pending':return 'reward_pending','The service is checking escrow for your reward step.',step('Reopen the reward page and press "Check reward preparation".'+then,clean)
        if k.get('status') in ('failed','uncertain'):return 'reward_check_incomplete','The last escrow check did not finish. Nothing was sent from your wallet by it.',step('Reopen the reward page and press "Check escrow again".'+then,clean)
        if k.get('stage') in ('submit','resolve','withdraw'):return 'reward_'+k['stage'],f'Verified. Next wallet step: {k["stage"]}.',step(f'Open the reward page and sign the "{k["stage"]}" step in your wallet.'+then,clean)
        return 'verified','Accepted. Reward steps have not been prepared yet.',step('Open the reward page and press "Prepare my reward steps".'+then,clean)
    return s,'Unrecognized service state.',step('Do not delete or rerun anything. Send this output and the raw record to the maintainer.',c('status'),True)

def report(a,claim,f,mode,now,c):
    stage,message,nxt=describe(a,claim,f,mode,now,c)
    return {'stage':stage,'message':message,'next':nxt,'attempt_id':a['id'],'task':a.get('task_slug'),'candidate_commit':a['candidate_commit'],'payee':a['payee'],'elapsed_seconds':now-a['created_at'],'facts':f}

def render(r):
    n=r['next'];lines=[f'Attempt   {r["attempt_id"]}  (task {r["task"]})',f'Commit    {r["candidate_commit"]}',f'Payee     {r["payee"]}  (fixed when the attempt was signed)',f'Elapsed   {r["elapsed_seconds"]//60} min since the attempt was recorded',f'Stage     {r["stage"]}',f'Status    {r["message"]}',('STOP      ' if n['stop'] else 'Next      ')+n['action']]
    if n['command']:lines.append('          '+n['command'])
    return '\n'.join(lines)
