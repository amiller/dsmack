#!/usr/bin/env python3
"""Zed-only trusted adapter. Config/keys stay local; stdout contains safe public results.

prepareExecution is delegated only to an independently selected closed publisher
factory, never a worker-provided command. No fallback or synthetic verdict exists.
"""
import argparse,base64,hashlib,json,os,re,subprocess,sys
from pathlib import Path
source=Path(__file__).with_name('portable.py');p={'__name__':'arcade_portable','__file__':str(source)};exec(compile(source.read_bytes(),str(source),'exec'),p)
need=p['need'];read=p['read'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive'];pin=p['pin'];protected=p['protected']

def guarded(config,args,log):
    v=config['verifier'];root=protected(v['root'],True)
    for name in ('verify.py','SOURCE-PINS.json','QUALIFIED-LINUX-ENVIRONMENT.json'):
        need(pin(root/name)==v['pins'][name],'selected verifier changed')
    need(v['pins']['SOURCE-PINS.json']['sha256']==v['source_manifest_sha256'] and v['pins']['QUALIFIED-LINUX-ENVIRONMENT.json']['sha256']==v['environment_sha256'],'verifier authority mismatch')
    result=subprocess.run([config['python'],'-I','-B',str(root/'verify.py'),'--source-manifest-sha256',v['source_manifest_sha256'],'--environment-sha256',v['environment_sha256'],*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    exclusive(Path(str(log)+'.stdout'),result.stdout);exclusive(Path(str(log)+'.stderr'),result.stderr)
    need(result.returncode in (0,3) and len(result.stdout)<=1<<20,'original verifier refused')
    return [doc(x)for x in result.stdout.splitlines()if x.strip()]

def factory(config,action,value,job):
    f=config['factory'];need(pin(f['path'],1<<20)=={k:f[k]for k in ('path','bytes','sha256')},'selected publisher factory changed')
    ns={'__name__':'arcade_publisher_factory','__file__':f['path']};exec(compile(read(f['path']),f['path'],'exec'),ns)
    # Factory receives server-selected constants from protected config. It must
    # validate task/template identities before signing anything. No root authority
    # path or manifest may be selected by the untrusted candidate.
    return ns[action](config['publisher'],value,job)

def registration(config,value,job):
    # Service verifies wallet authorization and ownership of this registration ID.
    key=value['key_id'];need(len(base64.b64decode(key,validate=True))==32,'Apple key id')
    challenge=base64.b64decode(value['challenge']['challenge_b64'],validate=True);need(len(challenge)==32,'registration challenge')
    client=base64.b64decode(value['client_data_b64'],validate=True)
    need(client==canonical({'domain':'minimal-attested-run-enroll/1','challenge':challenge.hex()}),'attestation challenge substitution')
    attestation=base64.b64decode(value['attestation_b64'],validate=True);need(0<len(attestation)<=262144,'bounded attestation')
    exclusive(job/'attestation.cbor',attestation);exclusive(job/'clientData.bin',client);exclusive(job/'keyId.txt',key.encode())
    # Fresh-key only. Never lower/reset the authenticated replay floor for an
    # existing registration; the service deduplicates registrations before leasing.
    seen=protected(config['registration_keys_dir'],True);marker=seen/hashlib.sha256(key.encode()).hexdigest();exclusive(marker,canonical({'registration_id':value['registration_id'],'state':'ceremony-requested'}))
    authority=config['authority'];out=job/'enrollment.json'
    rows=guarded(config,['operator','enroll','--policy',authority['policy'],'--secret-file',authority['secret_file'],'--store',authority['store'],'--attestation',str(job/'attestation.cbor'),'--key-id-file',str(job/'keyId.txt'),'--challenge',str(job/'clientData.bin'),'--out',str(out),'--replay',authority['replay'],'--min-counter','0'],job/'enroll')
    need(len(rows)==1 and rows[0].get('enrolled')is True,'hardware enrollment refused')
    package=doc(read(out));need(package['key_id_b64']==key,'registered key mismatch')
    return {'public_result':{'registered':True,'registered_key_id':key,'enrollment_sha256':pin(out)['sha256'],'enrollment_public_package':package},'artifacts':[]}

def verify_evidence(config,value,job):
    # These references are selected by the closed factory from server immutable
    # task/attempt/execution records, never from worker-provided expected flags.
    selected=factory(config,'verification_context',value,job)
    required={'context','enrollment','compose_manifest','attempt_id','candidate_sha256','candidate_commit','payee','policy_sha256','manifest_sha256','native_execution_id','projection','workload_disk'}
    need(set(selected)==required,'closed verification context')
    for k in ('context','enrollment','compose_manifest','projection'):
        d=selected[k];need(pin(d['path'])==d,'selected context changed')
    ctx=doc(read(selected['context']['path']));manifest=doc(read(selected['compose_manifest']['path']))
    need(ctx['expected']['manifest_sha256']==selected['compose_manifest']['sha256'] and ctx['expected']['closure_context']['attempt_id']==selected['native_execution_id'],'independent expected context')
    rows=value['files'];need(type(rows)is list and len(rows)==21 and {x['name']for x in rows}==set(p['ORIGINALS']),'original21 required')
    originals=job/'verified-inputs';originals.mkdir(mode=0o700)
    for d in rows:
        actual=pin(d['path'],p['ORIGINALS'][d['name']]);need(all(actual[k]==d[k]for k in ('bytes','sha256')),'original evidence changed')
        # Transport has already downloaded worker uploads under this owned job.
        src=protected(d['path']);need(src.is_relative_to(job),'evidence outside owned job')
        # Do not duplicate the 1GiB result disk: move only owned received files.
        os.rename(src,originals/d['name'])
    bundle=job/'bundle';retained=job/'retained';authority=config['authority']
    guarded(config,['prepare','prepare','--app-out',str(originals),'--enrollment',selected['enrollment']['path'],'--context',selected['context']['path'],'--bundle',str(bundle)],job/'prepare')
    result=guarded(config,['prepare','verify','--bundle',str(bundle),'--context',selected['context']['path'],'--retained',str(retained),'--policy',authority['policy'],'--secret-file',authority['secret_file'],'--signing-key-file',authority['signing_key_file'],'--report-key-id',authority['report_key_id'],'--store',authority['store'],'--replay',authority['replay'],'--work-root',str(job),'--extractor-sha256',ctx['extractor_tool_sha256']],job/'verify')
    need(len(result)==2 and result[0].get('verified')is True,'full verification framing')
    full=result[1];exclusive(job/'COMPLETE-CHECK.json',canonical(full))
    need(full.get('checked')is True and full.get('verification_level')=='full','full execution evidence invalid')
    # Factory checker join must authenticate exact output bytes from retained
    # receipt/index, compare candidate/base/checker commitments and typed outcomes;
    # it cannot accept worker status booleans. Failure never becomes acceptance.
    auditor=config['input_auditor'];need(pin(auditor['path'])==auditor,'selected input auditor changed')
    v=config['verifier'];audit=subprocess.run([config['python'],'-I','-B',auditor['path'],'--verifier',v['root'],'--source-manifest-sha256',v['source_manifest_sha256'],'--environment-sha256',v['environment_sha256'],'--manifest',selected['compose_manifest']['path'],'--projection',selected['projection']['path'],'--receipt',str(retained/'receipt.json'),'--statement',str(retained/'statement.json'),'--workload-sha256',selected['workload_disk']['sha256'],'--workload-bytes',str(selected['workload_disk']['bytes'])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    exclusive(job/'INPUT-AUDIT.stdout',audit.stdout);exclusive(job/'INPUT-AUDIT.stderr',audit.stderr);need(audit.returncode==0 and doc(audit.stdout).get('public_envelope_commitment_recomputed')is True,'independent input binding failed')
    outcome=factory(config,'check_authenticated_outputs',{'selection':selected,'full_result':full,'retained':str(retained),'manifest':manifest},job)
    need(set(outcome)=={'functional_passed','report_sha256','checker_sha256','candidate_sha256'} and type(outcome['functional_passed'])is bool and outcome['candidate_sha256']==selected['candidate_sha256'],'functional join contract')
    receipt=doc(read(retained/'receipt.json'));passed=full.get('task_success')is True and outcome['functional_passed'] and full.get('subject',{}).get('outputs_verified')is True and receipt['outputs']['status']=='completed' and receipt['outputs']['exit_code']==0
    record_dir=protected(config['publisher']['attempts_dir'],True)/selected['attempt_id']
    record={'retained':str(retained),'originals':str(originals),'full_result':pin(job/'COMPLETE-CHECK.json'),'report':pin(retained/'report.json'),'original_files':[{ 'name':name,**pin(originals/name,cap)}for name,cap in p['ORIGINALS'].items()]}
    exclusive(record_dir/'VERIFICATION.json',canonical(record))
    report=doc(read(retained/'report.json',131072));expected=ctx['expected'];cleanup_context={'verifier':report['verifier'],'verifier_context':report['verifier_context'],'subject':{k:expected[k]for k in ('challenge','manifest_sha256','key_id_b64','receipt_selector','receipt_environment')}}
    return {'public_result':{'public_input_commitment_recomputed':True,'native_workload_rebound':True,'cleanup_evidence':{'report':report,'context':cleanup_context},'verification_level':'full','execution_valid':True,'functional_passed':passed,'functional_pass':passed,'task_passed':passed,'accepted':passed,'apple_verified':True,'outputs_verified':full.get('subject',{}).get('outputs_verified')is True,'expected_exit_code':0,'receipt_status':receipt['outputs']['status'],'payee':selected['payee'],'candidate_commit':selected['candidate_commit'],'manifest_sha256':selected['manifest_sha256'],'attempt_id':selected['attempt_id'],'candidate_sha256':selected['candidate_sha256'],'policy_sha256':selected['policy_sha256'],'checker_sha256':outcome['checker_sha256'],'report_sha256':outcome['report_sha256'],'full_result_sha256':pin(job/'COMPLETE-CHECK.json')['sha256']},'artifacts':[]}

def settlement_binding(config,value,job):
    selected=factory(config,'verification_context',value,job);attempt=selected['attempt_id'];directory=protected(config['publisher']['attempts_dir'],True)/attempt
    for key in ('context','enrollment','compose_manifest','projection'):need(pin(selected[key]['path'])==selected[key],'settlement source selection changed')
    record=doc(read(directory/'VERIFICATION.json'));retained=protected(record['retained'],True);originals=protected(record['originals'],True)
    need(pin(record['full_result']['path'])==record['full_result'] and pin(record['report']['path'])==record['report'],'retained verification records changed')
    full=doc(read(record['full_result']['path']));need(full.get('checked')is True and full.get('verification_level')=='full'and full.get('task_success')is True,'complete successful execution required')
    for row in record['original_files']:
        actual=pin(originals/row['name'],p['ORIGINALS'][row['name']]);need(all(actual[k]==row[k]for k in ('bytes','sha256')),'retained originals changed')
    # Relying-party check authenticates the ORIGINAL signed verifier report and
    # retained evidence again; it does not issue/consume another replay challenge.
    args=['operator','check','--context',selected['context']['path'],'--report',record['report']['path'],'--evidence',str(retained),'--launch-assertion-b64',base64.b64encode(read(originals/'launch-assertion.cbor')).decode(),'--result-assertion-b64',base64.b64encode(read(originals/'result-assertion.cbor')).decode()]
    checked=guarded(config,args,job/'relying-check');need(len(checked)==1 and checked[0].get('checked')is True and checked[0].get('task_success')is True,'original report relying check failed')
    # Recheck exact workload and public file commitment, independently of HTTP flags.
    auditor=config['input_auditor'];need(pin(auditor['path'])==auditor,'selected input auditor changed');v=config['verifier']
    result=subprocess.run([config['python'],'-I','-B',auditor['path'],'--verifier',v['root'],'--source-manifest-sha256',v['source_manifest_sha256'],'--environment-sha256',v['environment_sha256'],'--manifest',selected['compose_manifest']['path'],'--projection',selected['projection']['path'],'--receipt',str(retained/'receipt.json'),'--statement',str(retained/'statement.json'),'--workload-sha256',selected['workload_disk']['sha256'],'--workload-bytes',str(selected['workload_disk']['bytes'])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    exclusive(job/'INPUT-AUDIT.stdout',result.stdout);exclusive(job/'INPUT-AUDIT.stderr',result.stderr);need(result.returncode==0,'settlement input audit failed')
    outcome=factory(config,'check_authenticated_outputs',{'selection':selected,'full_result':full,'retained':str(retained),'manifest':doc(read(selected['compose_manifest']['path']))},job);need(outcome['functional_passed']is True,'protected checker does not pass')
    projection=doc(read(selected['projection']['path'],33554432));rows=[x for x in projection['files']if x['slot']=='candidate'];need(len(rows)==1,'one candidate projection')
    delivery=base64.b64decode(rows[0]['content_base64'],validate=True);tree=doc(delivery);need(hashlib.sha256(canonical({name:hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()for name,encoded in tree.items()})).hexdigest()==selected['candidate_sha256'],'delivered tree changed')
    # Resolve the exact committed source again, rather than treating availability
    # of a candidate hash or HTTP assertion as delivery.
    f=config['factory'];ns={'__name__':'arcade_factory_delivery','__file__':f['path']};raw=read(f['path']);need(hashlib.sha256(raw).hexdigest()==f['sha256'],'delivery factory changed');exec(compile(raw,f['path'],'exec'),ns)
    pub=config['publisher'];base=ns['git_tree'](pub['repository'],ns['BASE']);submitted=ns['git_tree'](pub['repository'],selected['candidate_commit']);projected=ns['project_candidate'](base,submitted)
    need({n:base64.b64decode(b,validate=True)for n,b in tree.items()}==projected,'exact committed delivery unavailable or changed')
    exclusive(job/'candidate-delivery.json',delivery)
    evidence=canonical({'report_sha256':record['report']['sha256'],'full_result_sha256':record['full_result']['sha256'],'originals':[{k:r[k]for k in ('name','bytes','sha256')}for r in record['original_files']]})
    binding={'schema':'dsmack-arcade-settlement-binding/1','attempt_id':attempt,'payee':selected['payee'],'candidate_commit':selected['candidate_commit'],'policy_sha256':selected['policy_sha256'],'report_sha256':outcome['report_sha256'],'candidate_sha256':selected['candidate_sha256'],'evidence_sha256':hashlib.sha256(evidence).hexdigest(),'delivery_sha256':hashlib.sha256(delivery).hexdigest(),'original_report_authenticated':True,'original_outputs_verified':True,'checker_recomputed':True,'delivery_rehashed':True}
    exclusive(job/'SETTLEMENT-BINDING.json',canonical(binding));return {'public_result':binding,'artifacts':[]}

def main():
    a=argparse.ArgumentParser();a.add_argument('--config',required=True);a.add_argument('--config-sha256',required=True);x=a.parse_args();need(sys.flags.isolated,'isolated Python required')
    raw=read(x.config);need(hashlib.sha256(raw).hexdigest()==x.config_sha256,'selected adapter config changed');config=doc(raw)
    raw=sys.stdin.buffer.read((1<<20)+1);need(len(raw)<=1<<20,'job input cap');request=doc(raw);need(set(request)=={'action','input','job_dir','input_sha256'},'job contract')
    job=protected(request['job_dir'],True);need(job.is_relative_to(protected(config['state_dir'],True)),'job outside owned state')
    cache=job/'.imports';cache.mkdir(mode=0o700);sys.pycache_prefix=str(cache);sys.dont_write_bytecode=True
    action=request['action']
    if action=='registration':result=registration(config,request['input'],job)
    elif action=='verifyEvidence':result=verify_evidence(config,request['input'],job)
    elif action=='settlementBinding':result=settlement_binding(config,request['input'],job)
    elif action=='prepareExecution':result=factory(config,'prepare_execution',request['input'],job)
    else:raise ValueError('unselected adapter action')
    need(set(result)=={'public_result','artifacts'},'adapter result contract');print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception:
        print('Adapter refused; preserve owned job and reconcile before retry',file=sys.stderr);raise SystemExit(2)
