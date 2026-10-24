"""Closed publisher factory for one deterministic browser bonus; Zed only.

Public candidates choose a commit in the configured repository, never a checker,
image, command, authority key, expected outcome or filesystem path.
"""
import base64,contextlib,copy,datetime,hashlib,io,json,os,re,secrets,subprocess,sys,tarfile
from pathlib import Path
source=Path(__file__).resolve().parents[2]/'runner/portable.py';p={'__name__':'arcade_portable','__file__':str(source)};exec(compile(source.read_bytes(),str(source),'exec'),p)
need=p['need'];read=p['read'];pin=p['pin'];canonical=p['canonical'];doc=p['document'];exclusive=p['exclusive'];protected=p['protected']
IMAGE='222c279f5a94a6ad7fdbcf781faf4536cd0d6edd40c18e711b714183dbd58ed3'
CONFIG='61c8f50f8b46b3badde245be0635dcaa1b530a3e87a8641d3a9ccc648c49ed76'
BASE='5c76d40e77db1f4864dabd4b9398d02589cff330';SELECTOR='bounty-board-search-primary-review-v1'
ALLOWED={'apps/board/index.html','apps/board/logic.js','apps/board/ui.js'}
CHECKER=('check.py','browser.mjs','base-files.json')
FILES=[('driver','/workspace/inputs/driver.py',65536),('checker','/workspace/inputs/check.py',65536),('browser','/workspace/inputs/browser.mjs',65536),('basefiles','/workspace/inputs/base-files.json',65536),('base','/workspace/inputs/base.json',16777216),('candidate','/workspace/inputs/candidate.json',16777216),('request','/workspace/inputs/request.json',65536)]

def selected(d,cap=1<<20):
    need(pin(d['path'],cap)==d,'publisher source changed');return read(d['path'],cap)

def git_tree(repository,commit):
    need(re.fullmatch('[a-f0-9]{40}',commit),'full immutable commit required');protected(repository,True)
    proc=subprocess.run(['git','-C',repository,'archive','--format=tar',commit],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    need(proc.returncode==0 and len(proc.stdout)<=12<<20,'bounded committed tree required');result={};total=0
    with tarfile.open(fileobj=io.BytesIO(proc.stdout),mode='r:')as archive:
        for m in archive:
            if m.isdir():continue
            name=m.name;parts=Path(name).parts;need(m.isfile()and not name.startswith('/')and all(x not in ('.','..')for x in parts)and '\\'not in name and name not in result and m.size<=1048576 and len(result)<128,'regular closed source tree')
            b=archive.extractfile(m).read(1048577);total+=len(b);need(len(b)==m.size and total<=8388608,'tree bytes bound');result[name]=b
    return result

def tree_digest(files):return hashlib.sha256(canonical({n:hashlib.sha256(b).hexdigest()for n,b in sorted(files.items())})).hexdigest()

def project_candidate(base,submitted):
    need(ALLOWED<=set(submitted),'candidate board file membership')
    candidate=dict(base)
    for name in ALLOWED:candidate[name]=submitted[name]
    return candidate

def checker_files(config):
    return {name:selected(config['checker'][name])for name in CHECKER}

def checker_digest(config):return hashlib.sha256(canonical({n:config['checker'][n]['sha256']for n in CHECKER})).hexdigest()

def manifest(config):
    m=doc(selected(config['reference_manifest']));need(m['network']['mode']=='none','offline reference required');m=copy.deepcopy(m)
    m['name']=SELECTOR;m['allowed_envs']=[];m['required_envs']=[];m.pop('credentials',None)
    service={'image':'127.0.0.1:5005/dsmack-bounty-review-v1@sha256:'+IMAGE,'entrypoint':['/usr/bin/python3','-I','-B'],'command':['/workspace/inputs/driver.py'],'read_only':True,'security_profile':'browser-sandbox-v1','volumes':[slot+':'+target+':ro'for slot,target,_ in FILES]+['state:/workspace/state:rw','artifacts:/workspace/artifacts:rw']}
    m['docker_compose_file']=canonical({'services':{'checker':service}}).decode();m['harness']['version']='arcade-deterministic-checker-v1'
    m['allowed_files']=[{'slot':slot,'target':target,'mode':'ro','audience':'workload','required':True,'max_bytes':cap}for slot,target,cap in FILES]
    m['limits']={'output_max_bytes':268435456,'timeout_s':300,'workspace_max_bytes':268435456}
    m['outputs']={'capture':['stdout','stderr'],'artifacts':[{'name':role+'-'+name.replace('.','-'),'path':'/workspace/artifacts/'+role+'-'+name}for role in ('baseline','candidate')for name in ('checker-result.json','final.png','trace.zip','video.webm')]}
    return m

def guest_modules(config):
    # Existing measured guest contract and original packer remain selected by
    # complete source descriptors. No candidate-controlled Python import roots.
    for d in config['guest_source_pins']:selected(d,16777216)
    path=Path(config['guest_source'])/'runner-content/lib';sys.path.insert(0,str(path))
    from dsmack_compose_contract.manifest import validate_manifest_bytes
    from dsmack_compose_contract.runtime_inputs import compute_commitment
    return validate_manifest_bytes,compute_commitment

def build_disk(config,mr,projection,native,job):
    """Reuse qualified public packer control flow, with only selected flat OCI globals."""
    helper=config['build_helper'];raw=selected(helper);source_root=Path(helper['path']).parent
    for d in config['build_helper_imports']:selected(d,16777216)
    # The selected helper's original transport_loader independently verifies its
    # dynamically loaded transport/closure/OCI helpers by their original pins.
    sys.path.insert(0,str(source_root));ns={'__name__':'arcade_selected_public_builder','__file__':helper['path']};exec(compile(raw,helper['path'],'exec'),ns)
    ns['IMAGE']='sha256:'+IMAGE;ns['CONFIG']='sha256:'+CONFIG
    prep=job/'preparation';prep.mkdir(mode=0o700);exclusive(prep/'compose-manifest.json',mr);exclusive(prep/'public-file-projection.json',projection)
    out=job/'disk';args=['builder','--preparation',str(prep),'--expected-manifest-sha256',hashlib.sha256(mr).hexdigest(),'--expected-projection-sha256',hashlib.sha256(projection).hexdigest(),'--guest-source',config['guest_source'],'--transport-module',config['transport_module']['path'],'--artifacts',config['base_artifacts'],'--expected-checksum-sha256',config['base_checksum_sha256'],'--oci-layout',config['oci_layout'],'--execution-attempt-id',native,'--out',str(out)]
    selected(config['transport_module'],16777216);old=sys.argv;sys.argv=args
    try:
        captured=io.StringIO()
        with contextlib.redirect_stdout(captured):ns['main']()
        exclusive(job/'PUBLIC-BUILDER.stdout',captured.getvalue().encode())
    finally:sys.argv=old
    return out/'workload.img'

def _stored(config,attempt):
    need(re.fullmatch('[a-f0-9]{32}',attempt),'attempt identity');return protected(config['attempts_dir'],True)/attempt

def prepare_execution(config,value,job):
    need(sys.platform=='linux'and str(job).startswith('/data/'),'heavy publisher preparation belongs on Zed/data')
    task=value['task'];attempt=value['attempt'];need(task['slug']==config['task_slug']and task['policy_sha256']==config['policy_sha256']and attempt['task_slug']==config['task_slug']and attempt['policy_sha256']==config['policy_sha256'],'immutable bonus policy')
    need(re.fullmatch('0x[0-9a-f]{40}',attempt['payee'])and task['repository']=='amiller/bounty-arcade'and re.fullmatch('[a-f0-9]{40}',attempt['candidate_commit']),'admitted repository candidate')
    need(config['repository_url']=='https://github.com/amiller/bounty-arcade.git','closed public repository')
    if config.get('fetch_public_candidate')is True:
        fetched=subprocess.run(['git','-C',config['repository'],'-c','protocol.file.allow=never','-c','protocol.ext.allow=never','fetch','--no-tags','--depth=1',config['repository_url'],attempt['candidate_commit']],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin','GIT_TERMINAL_PROMPT':'0'})
        exclusive(job/'CANDIDATE-FETCH.stdout',fetched.stdout);exclusive(job/'CANDIDATE-FETCH.stderr',fetched.stderr);need(fetched.returncode==0,'candidate not reachable in selected public repository')
    else:need(config.get('private_fixture_mode')is True,'public candidate reachability must be checked')
    need(value['key_id']==value['enrollment']['registered_key_id'],'enrollment/task key');package=value['enrollment']['enrollment_public_package'];need(package['key_id_b64']==value['key_id'],'enrollment package key')
    base=git_tree(config['repository'],BASE);submitted=git_tree(config['repository'],attempt['candidate_commit']);checker=checker_files(config)
    candidate=project_candidate(base,submitted)
    frozen=doc(checker['base-files.json']);need({n:hashlib.sha256(b).hexdigest()for n,b in base.items()}==frozen['files'],'pinned original base')
    need(set(base)==set(candidate)and all(n in ALLOWED for n in base if base[n]!=candidate[n]),'frozen-base39 plus candidate-board3 projection')
    m=manifest(config);mr=canonical(m);need(hashlib.sha256(mr).hexdigest()==config['manifest_sha256'],'selected closed pilot manifest')
    native=secrets.token_hex(16);context={'schema':'dsmack-result-closure-context/1','attempt_id':native,'selectors':[SELECTOR]}
    request={'schema':'dsmack-arcade-native-request/1','role':'primary-review','attempt_id':attempt['id'],'run_id':native,'candidate_commit':attempt['candidate_commit'],'candidate_projection_policy':'frozen-base39+candidate-board3/v1','candidate_tree_sha256':tree_digest(candidate),'base_tree_sha256':tree_digest(base),'policy_sha256':config['policy_sha256'],'payee':attempt['payee'],'checker_sha256':checker_digest(config)}
    driver=selected(config['guest_driver']);files={'driver':driver,'checker':checker['check.py'],'browser':checker['browser.mjs'],'basefiles':checker['base-files.json'],'base':canonical({n:base64.b64encode(b).decode()for n,b in base.items()}),'candidate':canonical({n:base64.b64encode(b).decode()for n,b in candidate.items()}),'request':canonical(request)}
    validate,commit=guest_modules(config);validate(mr)
    projection={'runtime_input_version':4,'manifest_sha256':hashlib.sha256(mr).hexdigest(),'files':[{'slot':slot,'content_base64':base64.b64encode(files[slot]).decode()}for slot,_,_ in FILES],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(files)},'inputs_sha256':'0'*64}}
    projection['commitments']['inputs_sha256']=commit(projection,m)
    disk=build_disk(config,mr,canonical(projection),native,job)
    directory=_stored(config,attempt['id']);directory.mkdir(mode=0o700)
    # Persist immutable source/input selection BEFORE signing/challenge issuance.
    for name,b in [('request.json',canonical(request)),('projection.json',canonical(projection)),('compose-manifest.json',mr),('enrollment.json',canonical(package)),('closure-context.json',canonical(context))]:exclusive(directory/name,b)
    out=factory_authority(config,attempt,value['key_id'],native,context,disk,directory)
    stored={'context':pin(directory/'checker-context.json'),'enrollment':pin(directory/'enrollment.json'),'compose_manifest':pin(directory/'compose-manifest.json'),'attempt_id':attempt['id'],'native_execution_id':native,'market_attempt_id':attempt['id'],'candidate_sha256':request['candidate_tree_sha256'],'candidate_commit':attempt['candidate_commit'],'payee':attempt['payee'],'policy_sha256':config['policy_sha256'],'manifest_sha256':config['manifest_sha256'],'projection':pin(directory/'projection.json'),'workload_disk':{k:pin(disk)[k]for k in ('bytes','sha256')}}
    exclusive(directory/'selection.json',canonical(stored))
    # The worker only uploads files underneath its current owned job.
    for name in ('closure-context.json','checker-context.json','workload-admission.json','workload.sig'):
        exclusive(job/name,read(directory/name))
    return {'public_result':{'schema':'dsmack-arcade-execution/1','attempt_id':attempt['id'],'native_execution_id':native,'key_id':value['key_id'],'profile_id':config['profile_id'],'release_inventory_sha256':config['inventory_sha256'],'manifest_sha256':config['manifest_sha256'],'closure_context':context,'checker_context':doc(read(directory/'checker-context.json')),'challenge_b64':out['challenge_b64']},'artifacts':[{'name':name,**pin(job/name if name!='workload.img'else disk)}for name in ('closure-context.json','checker-context.json','workload-admission.json','workload.sig','workload.img')]}

def factory_authority(config,attempt,key,native,context,disk,directory):
    # Selected root-owned signing/issuer script emits exact public admission and
    # checker context. Its own inputs are recomputed from this closed factory.
    authority=config['authority_builder'];raw=selected(authority);ns={'__name__':'arcade_selected_issuer','__file__':authority['path']};exec(compile(raw,authority['path'],'exec'),ns)
    return ns['issue'](config,attempt,key,native,context,pin(disk),directory)

def verification_context(config,value,job):
    selected_context=doc(read(_stored(config,value['attempt']['id'])/'selection.json'))
    need(value['attempt']['candidate_commit']==selected_context['candidate_commit']and value['attempt']['payee']==selected_context['payee']and value['task']['policy_sha256']==selected_context['policy_sha256'],'immutable evidence assignment')
    return {k:v for k,v in selected_context.items()if k not in ('market_attempt_id',)}

def check_authenticated_outputs(config,value,job):
    selected_context=value['selection'];retained=Path(value['retained']);receipt=doc(read(retained/'receipt.json'));rows=receipt['outputs']['artifacts'];expected={role+'-'+n.replace('.','-')for role in ('baseline','candidate')for n in ('checker-result.json','final.png','trace.zip','video.webm')}
    need({r['name']for r in rows}==expected and len(rows)==8,'exact protected checker output membership')
    records={}
    for r in rows:
        actual=pin(retained/'outputs/artifacts'/r['name'],268435456);need(all(actual[k]==r[k]for k in ('bytes','sha256')),'authenticated artifact changed')
        records[r['name']]=actual
    passed=True
    for role in ('baseline','candidate'):
        result=doc(read(records[role+'-checker-result-json']['path']));wanted='functional_failure'if role=='baseline'else'passed'
        need(result['schema']=='dsmack-arcade-checker-result/1'and result['task_slug']==config['task_slug']and result['base_commit']==BASE,'checker identity')
        expected_tree=tree_digest(git_tree(config['repository'],BASE))if role=='baseline'else selected_context['candidate_sha256'];need(result['candidate_tree_sha256']==expected_tree,'authenticated checker tree')
        typed=result['outcome']==wanted and result['passed']==(role=='candidate')
        typed=typed and (any(t['status']=='assertion_failed'for t in result['tests'])if role=='baseline'else len(result['tests'])==7 and all(t['status']=='passed'for t in result['tests']))
        passed=passed and typed
        need({a['name']for a in result['artifacts']}=={'final.png','trace.zip','video.webm'},'checker media membership')
        for d in result['artifacts']:need(all(records[role+'-'+d['name'].replace('.','-')][k]==d[k]for k in ('bytes','sha256')),'checker media descriptor')
    report={'schema':'dsmack-arcade-functional-verdict/1','candidate_sha256':selected_context['candidate_sha256'],'policy_sha256':selected_context['policy_sha256'],'checker_sha256':checker_digest(config),'functional_passed':passed,'artifacts':{n:{k:d[k]for k in ('bytes','sha256')}for n,d in records.items()}}
    exclusive(job/'FUNCTIONAL-CHECK.json',canonical(report))
    return {'functional_passed':passed,'report_sha256':pin(job/'FUNCTIONAL-CHECK.json')['sha256'],'checker_sha256':report['checker_sha256'],'candidate_sha256':selected_context['candidate_sha256']}
