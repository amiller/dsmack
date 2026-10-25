"""Read-only attempt progress: server state, local run files and reward stage in plain words."""

RUN_LIMIT=1320  # portable.coordinator subprocess timeout
STOP='Stop here. Keep every file under the task directory and send this status output to the maintainer.'

def facts(local,native,read_doc):
    """Observe which local milestone files exist; never launches, deletes or rewrites."""
    control=local/('attempt-'+native+'.control') if native else None
    f={'task':(local/'task.json').exists(),'plan':bool(control) and (control/'plan.json').exists(),'launched_at':None,'controller':None,'submitted':(local/'EVIDENCE-SUBMITTED.json').exists(),'cleaned':(local/'CLEANUP-COMPLETE.json').exists()}
    if f['plan'] and (control/'launch-requested.json').exists():f['launched_at']=int((control/'launch-requested.json').stat().st_mtime)
    if f['plan'] and (control/'controller-result.json').exists():
        r=read_doc(control/'controller-result.json');f['controller']='returned' if r.get('controller_returned') is True else 'error:'+str(r.get('error'))
    return f

def describe(a,claim,f,mode,now):
    """Map one attempt to (stage, detail, next). Paid only after an observed withdrawal."""
    s=a['state'];cmd='python3 -I client.py --config CLIENT.json'
    if s=='registered':return 'registered','Attempt recorded; no execution requested yet.',f'{cmd} prepare --attempt ATTEMPT.json --registration REGISTRATION.json'
    if mode=='best_effort' and s in ('queued','prepared'):return 'node_running','A registered node is preparing, running or submitting this attempt. Your Mac has nothing to do.','Check again later: '+cmd+' progress --attempt ATTEMPT.json'
    if s=='preparing':
        return 'preparing','The service is building your signed task.',f'Repeat the same prepare command: {cmd} prepare --attempt ATTEMPT.json --registration REGISTRATION.json'
    if s=='preparation_failed' or s.startswith('prepareExecution_'):return 'preparation_failed','The service could not prepare this task ('+s+').',STOP
    if s=='prepared':
        if a.get('submission_id') and not f['submitted']:return 'submitting','Evidence upload started but has not completed.',f'Repeat: {cmd} submit --attempt ATTEMPT.json  (it resumes from the stored offsets)'
        if not f['task']:return 'downloading','Signed task ready on the service; not yet downloaded to this Mac.',f'{cmd} prepare --attempt ATTEMPT.json --registration REGISTRATION.json  (add --resume-download if a previous download stopped part way)'
        if not f['plan']:return 'local_prepare_incomplete','Task downloaded but the launch plan was not written.',STOP
        if f['launched_at'] is None:return 'ready_to_run','Launch plan saved. Nothing has run yet.',f'{cmd} check --attempt ATTEMPT.json, then {cmd} run --attempt ATTEMPT.json'
        if f['controller'] is None:
            age=now-f['launched_at']
            if age<=RUN_LIMIT+60:return 'executing',f'The VM run started {age//60} min ago (limit {RUN_LIMIT//60} min).','Wait for the run command to return. Do not start it again.'
            return 'run_interrupted',f'Launch was requested {age//60} min ago and no controller result was recorded. The run cannot be relaunched.',STOP
        if f['controller']!='returned':return 'run_failed','The VM controller stopped with '+f['controller']+'.',STOP
        return 'ready_to_submit','The run finished locally. The service has not received evidence yet.',f'{cmd} submit --attempt ATTEMPT.json'
    if s=='verifying':return 'verifying','The service is checking your evidence and running the protected checker.','Check again in a few minutes: '+cmd+' progress --attempt ATTEMPT.json'
    if s=='failed':return 'rejected','Evidence verified, but the commit did not pass the task checks. No reward for this attempt.',(f'{cmd} cleanup --attempt ATTEMPT.json' if f['task'] and not f['cleaned'] else '')
    if s=='verification_error' or s.startswith('verifyEvidence_'):return 'verification_error','The service could not finish verification ('+s+').',STOP
    if s in ('verified','claim_uncertain','claim_failed'):
        clean=f' Then free disk: {cmd} cleanup --attempt ATTEMPT.json' if f['task'] and not f['cleaned'] else ''
        c=claim or {}
        if c.get('stage')=='received' and c.get('payment_received') is True:return 'paid','Withdrawal to your payee observed on Base Sepolia.',clean.strip()
        if c.get('pending_job_id') or c.get('status')=='pending':return 'reward_pending','The service is checking escrow for your reward step.','Reopen the reward page and press "Check reward preparation".'+clean
        if c.get('status') in ('failed','uncertain'):return 'reward_check_incomplete','The last escrow check did not finish. Nothing was sent from your wallet by it.','Reopen the reward page and press "Check escrow again".'+clean
        if c.get('stage') in ('submit','resolve','withdraw'):return 'reward_'+c['stage'],f'Verified. Next wallet step: {c["stage"]}.','Open the reward page and sign the "'+c['stage']+'" step in your wallet.'+clean
        return 'verified','Accepted. Reward steps have not been prepared yet.','Open the reward page and press "Prepare my reward steps".'+clean
    return s,'Unrecognized service state.',STOP

def render(a,claim,f,mode,now):
    stage,detail,nxt=describe(a,claim,f,mode,now)
    lines=[f'Attempt   {a["id"]}',f'Commit    {a["candidate_commit"]}',f'Payee     {a["payee"]}  (fixed when the attempt was signed)',f'Elapsed   {(now-a["created_at"])//60} min since the attempt was recorded',f'Stage     {stage}',f'Status    {detail}']
    if nxt:lines.append('Next      '+nxt)
    return stage,'\n'.join(lines)
