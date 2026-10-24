#!/usr/bin/env python3
"""Privileged Zed pull worker: fixed local handlers, cached results, no blind retries."""
import argparse,base64,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
cp=Path(__file__).with_name('client.py');c={'__name__':'arcade_client','__file__':str(cp)};exec(compile(cp.read_bytes(),str(cp),'exec'),c)
p=c['_scope'];need=p['need'];canonical=p['canonical'];exclusive=p['exclusive'];read=p['read'];doc=p['document'];protected=p['protected']

def run_one(config,api):
    token_path=protected(config['credential_file']);need(not token_path.stat().st_mode&0o077,'private worker credential required');token=read(token_path,4096).decode().strip()
    lease=api.request('POST','/api/worker/lease',{'worker_id':config['worker_id'],'capabilities':sorted(config['handlers'])},token)
    if not lease:return False
    need(type(lease.get('lease_expires_at'))is int and time.time()+config['timeout_seconds']+30<lease['lease_expires_at'],'insufficient live lease budget')
    need(set(lease)=={'job_id','lease_id','lease_expires_at','action','input','input_sha256'},'lease fields')
    job=lease['job_id'];need(re.fullmatch('[a-f0-9]{32}',job) and re.fullmatch('[a-f0-9]{32}',lease['lease_id']),'lease identity')
    need(hashlib.sha256(canonical(lease['input'])).hexdigest()==lease['input_sha256'],'lease input commitment')
    root=protected(config['state_dir'],True);directory=root/job
    if not directory.exists():directory.mkdir(mode=0o700)
    protected(directory,True);resultpath=directory/'result.json';intent=directory/'intent.json'
    if resultpath.exists():
        saved=doc(read(resultpath));need(saved['lease_id']==lease['lease_id'] and saved['input_sha256']==lease['input_sha256'],'conflicting cached result')
    elif intent.exists():
        # A previous action might have enrolled, issued or consumed replay state.
        saved={'lease_id':lease['lease_id'],'input_sha256':lease['input_sha256'],'status':'uncertain','result':{'code':'prior_intent_without_terminal_result','automatic_retry':False}}
        exclusive(resultpath,canonical(saved))
    else:
        action=lease['action'];need(action in config['handlers'],'unselected action');handler=config['handlers'][action]
        need(p['pin'](handler['path'],1<<20)=={k:handler[k] for k in ('path','bytes','sha256')},'handler source changed')
        binding=config['binding'];need(p['pin'](binding['path'],1<<20)==binding,'binding configuration changed')
        exclusive(intent,canonical(lease));local_input=lease['input']
        if action=='prepareExecution' and local_input.get('mode')=='best_effort':
            registration=doc(read(config['best_effort_registration']));status=api.request('GET','/api/registrations/'+registration['registration_id']);need(status.get('state')=='enrolled'and status.get('enrollment'),'best-effort node enrollment pending');local_input={**local_input,'key_id':registration['key_id'],'enrollment':status['enrollment']}
        try:
            if action=='verifyEvidence':
                rows=local_input['files'];need(type(rows)is list and len(rows)==21 and {d['name']for d in rows}==set(p['ORIGINALS']),'original21 membership')
                originals=directory/'originals';originals.mkdir(mode=0o700);files=[]
                for d in rows:
                    need(type(d['bytes'])is int and 0<=d['bytes']<=p['ORIGINALS'][d['name']],'original size cap')
                    path=originals/d['name'];api.fetch(d,path,token);actual=p['pin'](path,p['ORIGINALS'][d['name']]);need(all(actual[k]==d[k] for k in ('bytes','sha256')),'original transport digest');files.append({'name':d['name'],**actual})
                local_input={**local_input,'files':files}
            invocation={'action':action,'input':local_input,'job_dir':str(directory),'input_sha256':lease['input_sha256']}
            proc=subprocess.run([config['python'],'-I','-B',handler['path'],'--config',binding['path'],'--config-sha256',binding['sha256']],input=canonical(invocation),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=config['timeout_seconds'],env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
            exclusive(directory/'handler.stdout',proc.stdout);exclusive(directory/'handler.stderr',proc.stderr)
            need(proc.returncode==0 and len(proc.stdout)<=1<<20,'handler refused; preserve original evidence')
            outcome=doc(proc.stdout);need(set(outcome)=={'public_result','artifacts'} and type(outcome['public_result'])is dict,'handler response contract')
            artifacts=outcome['artifacts'];need(type(artifacts)is list and len(artifacts)<=8,'artifact bound')
            if artifacts:
                rows=[]
                for d in artifacts:
                    path=protected(d['path']);need(path.is_relative_to(directory),'artifact outside owned job')
                    actual=p['pin'](path,4<<30);need(all(actual[k]==d[k] for k in ('bytes','sha256')),'prepared artifact changed');need(re.fullmatch('[a-zA-Z0-9._-]{1,80}',d['name']),'artifact name');rows.append({k:d[k]for k in ('name','bytes','sha256')})
                prepared=api.request('POST',f'/api/worker/jobs/{job}/artifacts',{'lease_id':lease['lease_id'],'files':rows},token)
                for d in artifacts:
                    offset=0
                    with Path(d['path']).open('rb')as f:
                        while offset<d['bytes']:
                            b=f.read(min(4194304,d['bytes']-offset));need(b,'truncated artifact')
                            api.request('PUT',f'/api/worker/jobs/{job}/artifacts/{d["name"]}',b,token,{'Content-Type':'application/octet-stream','Content-Range':f'bytes {offset}-{offset+len(b)-1}/{d["bytes"]}'},True);offset+=len(b)
                outcome['public_result']['artifacts']=[{**d,'url':config['api_url'].rstrip('/')+'/api/artifacts/'+job+'/'+d['name']}for d in rows]
            saved={'lease_id':lease['lease_id'],'input_sha256':lease['input_sha256'],'status':'completed','result':outcome['public_result']}
        except BaseException:
            saved={'lease_id':lease['lease_id'],'input_sha256':lease['input_sha256'],'status':'uncertain','result':{'code':'handler_or_transport_refused','automatic_retry':False}}
        exclusive(resultpath,canonical(saved))
    api.request('POST',f'/api/worker/jobs/{job}/result',saved,token)
    print(json.dumps({'job_id':job,'state':saved['status'],'result_posted':True}),flush=True);return True

def main():
    a=argparse.ArgumentParser();a.add_argument('--config',required=True);a.add_argument('--config-sha256',required=True);a.add_argument('--once',action='store_true');a.add_argument('--allow-loopback',action='store_true');x=a.parse_args()
    need(sys.flags.isolated,'invoke Python with -I');raw=read(x.config);need(hashlib.sha256(raw).hexdigest()==x.config_sha256,'independently selected worker config required');config=doc(raw)
    need(type(config['timeout_seconds'])is int and 0<config['timeout_seconds']<=1800,'bounded handler lifetime');api=c['API'](config['api_url'],x.allow_loopback)
    while True:
        ran=run_one(config,api)
        if x.once:return
        time.sleep(2 if ran else 10)

if __name__=='__main__':main()
