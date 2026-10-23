"""Unprivileged application audit over nine immutable public input slots.

The independently prepared expected request digest is mandatory. This audit is
not authorization: the external verifier repeats these checks over retained bytes.
No private VDE, provider token, or worker-supplied verified flag is accepted.
"""
import hashlib
import os
from pathlib import Path
import stat
import source_bundle as source
p = source.protocol
need = p.require
sha = source.sha
SLOTS = ('request','task_terms','acceptance_profile','plan','stage_profile','driver','source_manifest','source_bundle','suite')
CHILD_KEYS = ('schema','task_id','task_terms_sha256','acceptance_profile_sha256','plan_sha256','attempt_id','attempt_nonce','payee','run_id','stage_id','role','judge_index','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256','input_suite_sha256','requested_model')


def regular(path, bound):
    path = Path(path); before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= bound, 'public input regular byte bound')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        with os.fdopen(os.dup(fd),'rb') as stream: raw = stream.read(bound+1)
        after = os.fstat(fd)
    finally: os.close(fd)
    identity = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size <= bound, 'public input changed')
    return raw


def audit(paths, expected_request_digest, expected_stage_profile_sha256, expected_driver_sha256, expected_plan_sha256):
    p.keys(paths,SLOTS,'semantic input paths')
    p.sha(expected_request_digest,'independently selected request digest')
    p.sha(expected_stage_profile_sha256,'independently selected stage profile')
    p.sha(expected_driver_sha256,'independently selected driver')
    p.sha(expected_plan_sha256,'independently selected plan')
    raw = {key:regular(value,source.MAX_BYTES if key == 'source_bundle' else 4*1024*1024)
           for key,value in paths.items() if value is not None}
    need(len({str(Path(v).resolve()) for v in paths.values() if v is not None}) == len(raw),'distinct semantic inputs')
    request = p.parse_json(raw['request']); profile = p.parse_json(raw['stage_profile'])
    need(sha(raw['stage_profile']) == expected_stage_profile_sha256,'independent stage profile identity')
    need(sha(raw['driver']) == expected_driver_sha256,'independent driver identity')
    need(sha(raw['plan']) == expected_plan_sha256,'independent plan identity')
    primary = request.get('schema') == p.REQUEST_SCHEMA
    digest = sha(request['schema'].encode()+b'\0'+p.canonical_json(request))
    need(raw['request'] == p.canonical_json(request) and digest == expected_request_digest, 'fixed request identity')
    for key in ('task_terms','acceptance_profile','stage_profile'):
        need(sha(raw[key]) == request[key+'_sha256'] if key != 'stage_profile' or not primary else True, 'request '+key+' binding')
    if primary:
        p.validate_request(request); need(request['run_role'] == 'review','primary review request')
        tree = request['candidate']['tree_manifest_sha256']; role = 'primary-review'
        transform = profile['admission_transform']; p.keys(transform,('record','sha256'),'admission transform')
        record = transform['record']
        p.keys(record,('schema','operation','base_tree_manifest_sha256','candidate_tree_manifest_sha256','allowed_paths','changed_files'),'admission transform v2')
        need(record['schema'] == 'dsmack-bounty-admission-transform/2' and record['operation'] == 'allowlisted-existing-file-replacement','transform v2 operation')
        need(record['allowed_paths'] == source.BOARD and record['candidate_tree_manifest_sha256'] == tree and record['base_tree_manifest_sha256'] == request['base']['tree_manifest_sha256'],'transform declared source binding')
        changed = record['changed_files']; need(isinstance(changed,list) and changed and changed == sorted(set(changed)) and set(changed) <= set(source.BOARD),'transform changed paths')
        need(sha(p.canonical_json(record)) == transform['sha256'] == request['candidate']['admission_transform_sha256'],'transform identity')
        # This stage deliberately has no base tree. The independently selected
        # plan/admission must verify admission_relation over BOTH retained trees.
    else:
        p.keys(request,CHILD_KEYS,'child request')
        need(request['schema'] == 'dsmack-bounty-child-request/1','child request version')
        role = request['role']; need(role in ('generate','base','candidate'),'child role')
        tree = request['source_tree_sha256']; p.sha(tree,'source tree')
        need(sha(raw['plan']) == request['plan_sha256'],'plan identity')
    need(('suite' in raw) == (role in ('base','candidate')),'stage suite presence')
    if 'suite' in raw: need(sha(raw['suite']) == request['input_suite_sha256'],'selected suite identity')
    manifest,files = source.decode_source(raw['source_bundle'],raw['source_manifest'],tree)
    if role == 'generate':
        spec = profile['specification']; p.keys(spec,('text','sha256'),'generation specification')
        need(isinstance(spec['text'],str) and 0 < len(spec['text'].encode()) <= 65536 and sha(spec['text'].encode()) == spec['sha256'],'generation specification bytes')
        need(profile.get('admission_transform') is None,'no candidate admission transform in generator')
    return {'role':role,'request':request,'stage_profile':profile,'source_manifest':manifest,'source_files':files,
            'input_bytes':raw,'request_sha256':digest,'source_tree_sha256':tree,
            'scope':'stage-local public input audit; external full-source relation and authorization mandatory'}
