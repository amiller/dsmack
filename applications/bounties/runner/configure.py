#!/usr/bin/env python3
"""Materialize protected Zed adapter/worker configs from explicit root selections.
No signing, enrollment, disk build, network, VM or secret-file reads.
"""
import argparse,hashlib,json,os
from pathlib import Path
s=Path(__file__).with_name('portable.py');p={'__name__':'arcade_portable','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),p)
need=p['need'];read=p['read'];pin=p['pin'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive'];protected=p['protected']

def configure(v,out):
    need(str(out).startswith('/data/')and not out.exists(),'fresh protected Zed configuration directory')
    out.mkdir(mode=0o700);here=Path(__file__).parent
    for name in ('jobs','registrations','attempts'):(out/name).mkdir(mode=0o700)
    for name in ('factory','guest_driver'):
        need(pin(protected(v[name]['path']))==v[name],'selected '+name+' source')
    verifier={'root':str(protected(v['verifier_root'],True))}
    # Explicit public root/policy/report-key bytes are selected by their normal
    # descriptors. Private authority files are only named, never opened/hashed.
    authority={k:v[k]for k in ('policy','secret_file','store','replay','signing_key_file','report_key_id')}
    publisher=dict(v['publisher']);publisher.update(python=v['python'],verifier=verifier,replay=v['replay'],report_key_id=v['report_key_id'],report_verify_key_b64=v['report_verify_key_b64'],attempts_dir=str(out/'attempts'),signing_authorized=False,authority_builder=pin(here/'authority.py'),guest_driver=v['guest_driver'])
    adapter={'python':v['python'],'state_dir':str(out/'jobs'),'registration_keys_dir':str(out/'registrations'),'verifier':verifier,'authority':authority,'publisher':publisher,'factory':v['factory'],'input_auditor':pin(here/'audit_inputs.py')}
    exclusive(out/'adapter.json',canonical(adapter));binding=pin(out/'adapter.json')
    worker={'python':v['python'],'api_url':v['api_url'],'worker_id':v['worker_id'],'credential_file':v['worker_credential_file'],'state_dir':str(out/'jobs'),'timeout_seconds':1500,'binding':binding,'handlers':{action:pin(here/'server_adapter.py')for action in ('registration','prepareExecution','verifyEvidence')}}
    if 'best_effort_registration'in v:worker['best_effort_registration']=v['best_effort_registration']
    exclusive(out/'worker.json',canonical(worker));result={'adapter':binding,'worker':pin(out/'worker.json'),'signing_authorized':False,'authority_files_read':False,'execution_performed':False};exclusive(out/'CONFIG-FREEZE.json',canonical(result));return result

def main():
    a=argparse.ArgumentParser();a.add_argument('--selection',required=True);a.add_argument('--selection-sha256',required=True);a.add_argument('--out',required=True);x=a.parse_args();raw=read(x.selection);need(hashlib.sha256(raw).hexdigest()==x.selection_sha256,'selected configuration input');print(json.dumps(configure(doc(raw),Path(x.out)),sort_keys=True))
if __name__=='__main__':main()
