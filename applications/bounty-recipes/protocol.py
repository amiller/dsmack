"""Canonical public bounty request/source identities. No authority from caller flags."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

REQUEST_SCHEMA = 'dsmack-bounty-public-request/1'
TREE_DOMAIN = b'dsmack-bounty-source-tree/1\0'
MAX_SAFE_INTEGER = (1 << 53) - 1
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z')
ARTIFACT = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')


def require(ok, why):
    if not ok: raise ValueError(why)


def canonical_json(value):
    def valid(v,depth=0):
        require(depth<=32,'JSON nesting exceeds bound')
        if v is None:return
        if isinstance(v,str):
            try:v.encode('utf-8')
            except UnicodeEncodeError as exc:raise ValueError('invalid Unicode scalar') from exc
            return
        if type(v) is int:
            require(abs(v) <= MAX_SAFE_INTEGER,'unsafe JSON integer');return
        if isinstance(v,list):
            for item in v: valid(item,depth+1)
            return
        if isinstance(v,dict):
            require(all(isinstance(k,str) for k in v),'JSON keys must be strings')
            for item in v.values(): valid(item,depth+1)
            return
        raise ValueError('only strings, safe integers, null, arrays and objects are canonical')
    valid(value)
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def parse_json(raw,maximum=131072):
    require(isinstance(raw,bytes) and 0<len(raw)<=maximum,'JSON byte bound exceeded')
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate JSON member')
            result[key]=value
        return result
    def constant(value):raise ValueError('nonfinite JSON constant')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
    canonical_json(value)
    return value


def keys(value,expected,label):
    require(isinstance(value,dict) and set(value)==set(expected),label+' members differ from schema')


def sha(value,label):require(isinstance(value,str) and HEX.fullmatch(value) is not None,label+' must be lowercase SHA-256')

def commit(value,label):require(isinstance(value,str) and COMMIT.fullmatch(value) is not None,label+' must be full Git SHA')


def validate_request(request):
    keys(request,('schema','task_id','task_terms_sha256','attempt_id','attempt_nonce','run_id','run_role',
                  'acceptance_profile_sha256','base','candidate','toolchain','required_artifacts'),'request')
    require(request['schema']==REQUEST_SCHEMA,'wrong public request schema')
    for field in ('task_id','attempt_id','run_id'):
        require(isinstance(request[field],str) and ID.fullmatch(request[field]) is not None,'invalid '+field)
    for field in ('task_terms_sha256','attempt_nonce','acceptance_profile_sha256'):sha(request[field],field)
    require(request['run_role'] in ('review','develop'),'invalid run role')
    base=request['base'];keys(base,('repo','commit','tree_manifest_sha256'),'base')
    require(isinstance(base['repo'],str) and re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',base['repo']) is not None,'base repo must be canonical HTTPS GitHub URL')
    commit(base['commit'],'base commit');sha(base['tree_manifest_sha256'],'base tree')
    candidate=request['candidate']
    if request['run_role']=='develop':require(candidate is None,'development starts from base, not an asserted result candidate')
    else:
        keys(candidate,('upstream_commit','tree_manifest_sha256','admission_transform_sha256'),'candidate')
        if candidate['upstream_commit'] is not None:commit(candidate['upstream_commit'],'candidate upstream')
        sha(candidate['tree_manifest_sha256'],'candidate tree');sha(candidate['admission_transform_sha256'],'admission transform')
    toolchain=request['toolchain'];keys(toolchain,('platform','image_digest'),'toolchain')
    require(toolchain['platform']=='linux/arm64','funded Mac profile requires linux/arm64')
    require(isinstance(toolchain['image_digest'],str) and toolchain['image_digest'].startswith('sha256:'),'wrong OCI image digest')
    sha(toolchain['image_digest'][7:],'OCI image digest')
    artifacts=request['required_artifacts']
    require(isinstance(artifacts,list) and 1<=len(artifacts)<=32,'required artifacts missing/unbounded')
    require(all(isinstance(a,str) and ARTIFACT.fullmatch(a) is not None for a in artifacts),'invalid artifact name')
    require(artifacts==sorted(set(artifacts)),'required artifacts must be sorted unique names')
    canonical_json(request)
    return request


def request_digest(request):
    validate_request(request)
    return hashlib.sha256(REQUEST_SCHEMA.encode()+b'\0'+canonical_json(request)).hexdigest()


def validate_tree(manifest):
    require(isinstance(manifest,list) and len(manifest)<=10000,'source manifest is not bounded array')
    names=[]
    for entry in manifest:
        keys(entry,('path','mode','bytes','sha256'),'source entry')
        name=entry['path'];require(isinstance(name,str) and 0<len(name)<=512 and name.isascii(),'invalid source path')
        path=PurePosixPath(name)
        require(bool(path.parts) and not path.is_absolute() and str(path)==name and all(re.fullmatch(r'[A-Za-z0-9_.@+-]+',p) for p in path.parts),'noncanonical source path')
        require(all(p not in ('.','..','.git') for p in path.parts),'history/traversal source path')
        require(type(entry['mode']) is int and entry['mode'] in (420,493),'source mode must be 0644 or 0755')
        require(type(entry['bytes']) is int and 0<=entry['bytes']<=MAX_SAFE_INTEGER,'invalid source byte length')
        sha(entry['sha256'],'source content');names.append(name)
    require(names==sorted(set(names)),'source paths must be sorted unique ASCII names')
    files=set(names)
    for name in names:
        require(all(str(parent) not in files for parent in PurePosixPath(name).parents if str(parent)!='.'),
                'source file conflicts with an ancestor path')
    return manifest


def tree_digest(manifest):
    validate_tree(manifest)
    return hashlib.sha256(TREE_DOMAIN+canonical_json(manifest)).hexdigest()


def scan_tree(root,maximum_bytes=32*1024*1024):
    """Scan stable private/read-only staging, with finite before/after checks.

    This does not establish hostile concurrent namespace exclusion or permanent
    immutability. The public workload must separately bind and retain its inputs.
    """
    root=Path(root);require(root.is_dir() and not root.is_symlink(),'source root must be ordinary directory')
    result=[];total=0;members=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        members+=len(dirs)+len(files);require(members<=20000,'source membership exceeds bound')
        for name in dirs:
            path=Path(directory)/name
            require(name!='.git' and not path.is_symlink(),'source history or directory link')
        for name in files:
            path=Path(directory)/name;before=path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'source must be regular single-link files')
            require(stat.S_IMODE(before.st_mode) in (420,493),'noncanonical source file mode')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(maximum_bytes+1)
                after=os.fstat(fd)
            finally:os.close(fd)
            identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(identity(before)==identity(after) and len(data)==before.st_size,'source changed during scan')
            total+=len(data);require(total<=maximum_bytes,'source tree exceeds byte bound')
            result.append({'path':path.relative_to(root).as_posix(),'mode':stat.S_IMODE(before.st_mode),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    result.sort(key=lambda x:x['path']);validate_tree(result)
    return result
