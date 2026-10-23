"""Unauthoritative public input observations, bound as ordinary exported bytes.

External verification reconstructs this object from independently retained
nine-slot inputs and deterministic projection. Job JSON never grants authority.
"""
from pathlib import Path
import re
import os
import stat
from source_bundle import protocol as p, sha
from audit_stage import regular


def observation(audit, projection):
    raw=audit['input_bytes']
    p.require(all(name in raw and isinstance(raw[name],bytes) for name in ('acceptance_profile','stage_profile','plan','driver')),'incomplete audited public input bytes')
    return {'schema':'dsmack-bounty-public-input-observation/1','role':audit['role'],
            'request_sha256':audit['request_sha256'],'source_tree_sha256':audit['source_tree_sha256'],
            'acceptance_profile_sha256':sha(raw['acceptance_profile']),
            'stage_profile_sha256':sha(raw['stage_profile']),'plan_sha256':sha(raw['plan']),
            'driver_sha256':sha(raw['driver']),'projection_sha256':sha(p.canonical_json(projection))}


def compare_observation(raw, independently_audited, independently_projected):
    expected=p.canonical_json(observation(independently_audited,independently_projected))
    p.require(raw==expected,'public input observation differs from independent recomputation')
    return p.parse_json(raw)


def append_observation(output,audit,projection):
    output=Path(output)
    p.require(output.is_dir() and not output.is_symlink(),'child must create ordinary artifact directory')
    with (output/'public-input-audit.json').open('xb') as stream:
        stream.write(p.canonical_json(observation(audit,projection)))
    files=[];total=0
    for path in sorted(output.iterdir()):
        if path.name=='output-manifest.json':continue
        p.require(re.fullmatch(r'[a-z][a-z0-9.-]{0,79}',path.name) is not None,'artifact name')
        raw=regular(path,16*1024*1024);total+=len(raw)
        p.require(total<=64*1024*1024,'artifact aggregate byte bound')
        files.append({'name':path.name,'size':len(raw),'sha256':sha(raw)})
    p.require(0<len(files)<=64,'artifact count bound')
    manifest=output/'output-manifest.json'
    # Existing or dangling links never redirect this write. Inspect the opened
    # descriptor before truncation; exclusive-create handles the absent case.
    try:
        fd=os.open(manifest,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:
        fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'manifest must be ordinary single-link file')
        os.ftruncate(fd,0)
        raw=p.canonical_json({'schema':'dsmack-bounty-output-manifest/1','files':files})
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw)
    finally:os.close(fd)
    return files
