"""Bounded PUBLIC stage assembly; no authority, credential, model or VM actions.

The operator must authenticate task/claim/policy, select all ten run IDs before
GEN, and independently authenticate each GEN suite before selecting its hash for
CI. This module checks selected bytes; it cannot establish those authorities.
"""
import hashlib,json,re,sys,subprocess,shutil
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bounty-runtime'))
import source_bundle as source
p=source.protocol
need=p.require
canonical=p.canonical_json
sha=source.sha
MODEL='claude-opus-4-8'
GEN='d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'
BROWSER='71023367bea2614acd730a0c24fb15c9e195b2c4fa9c87d5abcfd243249a5390'
BASE='ca3ff7c4e70d33a481e672079ac381037f3940b8102f09d7c9e1d3b8ce9ab553'
POLICY='38a63897a22cf1885843d479622759acfeb67a21dd14f5be6d793f7869eb9ea7'
TERMS='96619644fc67eedd2386aba34829104e228297c658632db27b639409aeebaddc'
REPEAT_TERMS='414c424772cfa8357334e8d676b97f687ee2cda347a60d28daf99a8e5abb4a8c'
DRIVER='85d4a792ca25b99278d5311e1c37744f8528d6c65642b66b674013e48c0c8c0d'
STAGES=tuple([f'{r}-{i}'for r in ('generate','base','candidate')for i in (1,2,3)]+['primary-review'])
ARTIFACTS=['public-input-audit','result-files','stage-checks']


def admit_suite_bytes(raw):
    """Reuse the exact generator/browser grammar; never S0's scalar grammar.

    Host assembly trusts an operator-selected Node24 on PATH, as it trusts the
    host interpreter and stable source namespace. No NODE_* or user config is
    passed to the fixed builtin-only parser. This does not authenticate a suite.
    """
    need(type(raw)is bytes and 0<len(raw)<=262144,'selected suite bytes bound')
    contract=Path(__file__).resolve().parents[1]/'bounty-judges/suite-contract.mjs'
    need(sha(contract.read_bytes())=='daf414ed2bfef9957a60338e89cfcfb10630a480ba41c19074337ac3b87bd958','reviewed suite grammar source')
    node=shutil.which('node');need(node is not None and Path(node).is_absolute(),'operator-selected Node24 required')
    environment={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
    version=subprocess.run([node,'--version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,env=environment)
    need(version.returncode==0 and re.fullmatch(rb'v24\.[0-9]+\.[0-9]+\n',version.stdout),'Node24 grammar runtime')
    parsed=subprocess.run([node,str(contract)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,env=environment)
    need(parsed.returncode==0 and parsed.stdout==raw and len(parsed.stderr)<=4096,'strict selected suite grammar')
    return raw


def case_identity(case):
    need(isinstance(case,str)and case in ('first','repeat-2'),'closed pilot case')
    return (TERMS,'board-search-opus48-pilot-v1')if case=='first'else(REPEAT_TERMS,'board-search-opus48-pilot-v1-repeat-2')


def plan(terms_raw,policy_raw,claim,specification,run_ids,*,case='first'):
    """Candidate-blind plan. Calling this does not authorize its selection."""
    terms_sha,task_id=case_identity(case)
    need(sha(terms_raw)==terms_sha and sha(policy_raw)==POLICY,'fixed requester terms/policy')
    p.keys(claim,('task_id','attempt_id','attempt_nonce','payee'),'selected claim')
    need(claim['task_id']==task_id,'selected pilot task')
    p.sha(claim['attempt_nonce'],'assignment nonce')
    need(isinstance(claim['attempt_id'],str)and re.fullmatch('[a-f0-9]{32}',claim['attempt_id'])and re.fullmatch('0x[a-f0-9]{40}',claim['payee']),'claim identity')
    p.keys(specification,('text','sha256'),'requester specification')
    need(canonical(specification)==canonical(json.loads(policy_raw)['specification']),'immutable requester specification')
    need(isinstance(specification['text'],str)and 0<len(specification['text'].encode())<=65536 and sha(specification['text'].encode())==specification['sha256'],'specification bytes')
    p.keys(run_ids,STAGES,'root-selected execution IDs')
    need(all(isinstance(v,str)and re.fullmatch('[a-f0-9]{32}',v)for v in run_ids.values())and len(set(run_ids.values()))==10 and claim['attempt_id']not in run_ids.values(),'ten distinct independently selected executions')
    result={'schema':'dsmack-bounty-candidate-blind-plan/1','claim':claim,'task_terms_sha256':terms_sha,'acceptance_profile_sha256':POLICY,'base_tree_sha256':BASE,'specification':specification,'model':MODEL,'generation_oci_sha256':GEN,'browser_primary_oci_sha256':BROWSER,'driver_sha256':DRIVER,'run_ids':{k:run_ids[k]for k in STAGES},'limits':{'generation_count':3,'tests_per_suite':16,'steps_per_test':64,'steps_total_per_suite':512,'result_bundle_bytes':16777216,'ten_stage_logical_bytes':67108864},'acceptance':{'base_outcome':'all-three-meaningful-assertion-failure','candidate_outcome':'all-three-pass','primary_browser_tests':4,'primary_logic_suites':4,'primary_logic_cases':80,'primary_feature_tests':6}}

    if case!='first':result['case']=case
    return result


def selected_plan(raw,expected_sha):
    need(sha(raw)==expected_sha,'independently selected common plan digest')
    v=p.parse_json(raw,262144)
    case=v.get('case','first');terms_sha,task_id=case_identity(case)
    need('case'not in v or case=='repeat-2','explicit repeat selector only')
    p.keys(v,('schema','claim','task_terms_sha256','acceptance_profile_sha256','base_tree_sha256','specification','model','generation_oci_sha256','browser_primary_oci_sha256','driver_sha256','run_ids','limits','acceptance')+(('case',)if 'case'in v else()),'closed candidate-blind plan')
    need(v['schema']=='dsmack-bounty-candidate-blind-plan/1','plan version')
    need(v['task_terms_sha256']==terms_sha and v['claim']['task_id']==task_id,'selected case identity')
    # Rebuild through the same closed constructor; no arbitrary/candidate fields.
    need(v['model']==MODEL and v['generation_oci_sha256']==GEN and v['browser_primary_oci_sha256']==BROWSER and v['driver_sha256']==DRIVER and v['base_tree_sha256']==BASE,'pinned plan runtime')
    need(raw==canonical(v),'canonical common plan')
    return v


def assemble(plan_raw,expected_plan_sha,stage_id,terms_raw,policy_raw,driver_raw,base_manifest,base_bundle,*,candidate_manifest=None,candidate_bundle=None,suite_raw=None,expected_suite_sha=None):
    """Return exact8/9 immutable public slot bytes, request digest and relation.

    Suite hashes must come from independent genuine GEN output verification.
    This function does not treat a caller digest or suite JSON as that proof.
    """
    v=selected_plan(plan_raw,expected_plan_sha);need(stage_id in STAGES,'closed stage ID')
    case=v.get('case','first');terms_sha,_=case_identity(case)
    need(sha(terms_raw)==terms_sha and sha(policy_raw)==POLICY and sha(driver_raw)==DRIVER,'selected immutable recipe bytes')
    need(canonical(plan(terms_raw,policy_raw,v['claim'],v['specification'],v['run_ids'],case=case))==plan_raw,'closed plan policy and claim')
    bm,bf=source.decode_source(base_bundle,base_manifest,BASE)
    role='primary-review'if stage_id=='primary-review'else stage_id.rsplit('-',1)[0]
    index=None if role=='primary-review'else int(stage_id[-1]);relation=None
    if role=='generate':
        need(candidate_manifest is None and candidate_bundle is None and suite_raw is None and expected_suite_sha is None,'candidate-blind generation inputs')
        sm,sb,tree=base_manifest,base_bundle,BASE
        profile={'schema':'dsmack-bounty-generation-stage-profile/1','specification':v['specification']}
    else:
        need(candidate_manifest is not None and candidate_bundle is not None,'complete candidate bytes required')
        cm=p.parse_json(candidate_manifest,4194304);tree=p.tree_digest(cm);cm,cf=source.decode_source(candidate_bundle,candidate_manifest,tree)
        relation=source.admission_relation(bm,bf,cm,cf)
        sm,sb=(base_manifest,base_bundle)if role=='base'else(candidate_manifest,candidate_bundle)
        if role=='base':tree=BASE
        profile=({'schema':'dsmack-bounty-base-review-stage-profile/1','base_tree_manifest_sha256':BASE}if role=='base'else{'schema':'dsmack-bounty-review-stage-profile/1','admission_transform':{'record':relation,'sha256':sha(canonical(relation))}})
    if role in ('base','candidate'):
        p.sha(expected_suite_sha,'independently authenticated suite hash');need(isinstance(suite_raw,bytes)and 0<len(suite_raw)<=262144 and sha(suite_raw)==expected_suite_sha,'selected suite bytes')
        admit_suite_bytes(suite_raw)
    else:need(suite_raw is None and expected_suite_sha is None,'no generation/primary suite input')
    pr=canonical(profile);claim=v['claim'];image=GEN if role=='generate'else BROWSER
    if role=='primary-review':
        terms=p.parse_json(terms_raw)
        request={'schema':p.REQUEST_SCHEMA,'task_id':claim['task_id'],'task_terms_sha256':terms_sha,'attempt_id':claim['attempt_id'],'attempt_nonce':claim['attempt_nonce'],'run_id':v['run_ids'][stage_id],'run_role':'review','acceptance_profile_sha256':POLICY,'base':{'repo':'https://github.com/'+terms['repo'],'commit':terms['base_commit'],'tree_manifest_sha256':BASE},'candidate':{'upstream_commit':None,'tree_manifest_sha256':tree,'admission_transform_sha256':sha(canonical(relation))},'toolchain':{'platform':'linux/arm64','image_digest':'sha256:'+image},'required_artifacts':ARTIFACTS}
        p.validate_request(request)
    else:
        request={'schema':'dsmack-bounty-child-request/1','task_id':claim['task_id'],'task_terms_sha256':terms_sha,'acceptance_profile_sha256':POLICY,'plan_sha256':expected_plan_sha,'attempt_id':claim['attempt_id'],'attempt_nonce':claim['attempt_nonce'],'payee':claim['payee'],'run_id':v['run_ids'][stage_id],'stage_id':stage_id,'role':role,'judge_index':index,'stage_profile_sha256':sha(pr),'oci_manifest_sha256':image,'source_tree_sha256':tree,'input_suite_sha256':expected_suite_sha,'requested_model':MODEL}
    rr=canonical(request);slots={'request':rr,'task_terms':terms_raw,'acceptance_profile':policy_raw,'plan':plan_raw,'stage_profile':pr,'driver':driver_raw,'source_manifest':sm,'source_bundle':sb}
    if suite_raw is not None:slots['suite']=suite_raw
    return {'files':slots,'request_sha256':sha(request['schema'].encode()+b'\0'+rr),'stage_profile_sha256':sha(pr),'source_tree_sha256':tree,'relation':relation,'scope':'public byte assembly only; independently selected claims, plan and authenticated suite hashes required'}
