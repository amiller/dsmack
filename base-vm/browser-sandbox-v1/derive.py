#!/usr/bin/env python3
"""Derive a reference guest from explicitly pinned existing base and templates.

Run heavy work on Zed /data. This never signs, launches a VM, publishes, imports
credentials or authenticates a bounty. Read README.md before running.
"""
import argparse,hashlib,json,os,re,shutil,stat,subprocess,time,uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
    return h.hexdigest()

def regular(path,row=None):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):raise ValueError('regular input required: '+str(path))
    if row and (path.stat().st_size!=row['bytes'] or digest(path)!=row['sha256']):raise ValueError('input pin mismatch: '+str(path))

def source_check(expected):
    raw=(HERE/'SOURCE-LOCK.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('independently selected source lock mismatch')
    lock=json.loads(raw)
    if lock.get('schema')!='dsmack-base-vm-source-lock/1':raise ValueError('source lock schema')
    actual=set()
    for path in (HERE/'source').rglob('*'):
        mode=path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):raise ValueError('source nonregular entry refused')
        if stat.S_ISREG(mode):actual.add(path.relative_to(HERE).as_posix())
    if actual!={n for n in lock['files'] if n.startswith('source/')}:raise ValueError('source membership mismatch')
    for name,row in lock['files'].items():
        path=HERE/name
        if '..' in Path(name).parts or Path(name).is_absolute():raise ValueError('lock path')
        regular(path,row)
    return lock

def validate_artifacts(directory,expected):
    records={}
    for path in directory.iterdir():
        regular(path)
        records[path.name]={'bytes':path.stat().st_size,'sha256':digest(path)}
    if records!=expected:raise ValueError('actual output artifact map differs from independently selected pins')
    return records

def invoke(argv,log,timeout,env):
    return subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=timeout,env=env,check=True)

def build(a):
    lock=source_check(a.source_lock_sha256)
    if a.check_source:return {'source_verified':True,'files':len(lock['files']),'execution':False}
    if not all((a.base_bundle,a.templates,a.out)):raise ValueError('--base-bundle --templates --out required for build')
    base,templates,out=map(lambda s:Path(s).absolute(),(a.base_bundle,a.templates,a.out))
    for directory,pins in ((base,lock['base_inputs']),(templates,lock['template_inputs'])):
        if directory.is_symlink() or not directory.is_dir():raise ValueError('ordinary selected input directory required')
        for name,row in pins.items():regular(directory/name,row)
    out.mkdir(mode=0o700) # Fresh namespace only. Never remove/reuse user paths.
    (out/'build').mkdir();(out/'docker-config').mkdir(mode=0o700)
    shutil.copyfile(HERE/'derive-in-container.sh',out/'derive_browser_guest.sh')
    env={'PATH':'/usr/bin:/bin:/usr/local/bin','HOME':str(out),'DOCKER_CONFIG':str(out/'docker-config'),'LANG':'C.UTF-8'}
    nonce=uuid.uuid4().hex;name='dsmack-base-derive-'+nonce
    create=['docker','--host','unix:///var/run/docker.sock','create','--name',name,'--label','dev.dsmack.derive='+nonce,'--cpus','4','--memory','4g','--pids-limit','256','--network','none',
      '--mount',f'type=bind,src={out},dst=/w','--mount',f'type=bind,src={HERE}/source,dst=/w/source,readonly',
      '--mount',f'type=bind,src={base},dst=/prior-image,readonly','--mount',f'type=bind,src={templates},dst=/selected-templates,readonly',
      lock['builder_image'],'bash','/w/derive_browser_guest.sh']
    (out/'BUILD-COMMAND.json').write_text(json.dumps(create,indent=2)+'\n')
    started=time.monotonic();cid=None;removed=False;error=None
    try:
        r=subprocess.run(create,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env,check=True)
        cid=r.stdout.decode().strip()
        if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('Docker create returned invalid owned id')
        (out/'OWNED-CONTAINER.json').write_text(json.dumps({'id':cid,'name':name,'nonce':nonce})+'\n')
        with (out/'build.log').open('wb') as log:invoke(['docker','--host','unix:///var/run/docker.sock','start','-a',cid],log,900,env)
        observation=subprocess.run(['docker','--host','unix:///var/run/docker.sock','inspect',cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env=env,check=True)
        state=json.loads(observation.stdout)[0]['State']
        if state.get('Running') or state.get('ExitCode')!=0 or state.get('OOMKilled'):
            raise ValueError('container did not complete successfully')
    except Exception as exc:
        error=type(exc).__name__
    finally:
        # Remove only acknowledged ID, or a uniquely named object whose label
        # proves ownership. Unknown creation/daemon state is an explicit failure.
        try:
            target=cid
            if target is None:
                r=subprocess.run(['docker','--host','unix:///var/run/docker.sock','inspect',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env=env)
                if r.returncode==0:
                    obj=json.loads(r.stdout)[0]
                    if obj['Config']['Labels'].get('dev.dsmack.derive')!=nonce:raise ValueError('container ownership mismatch')
                    target=obj['Id']
            if target:
                subprocess.run(['docker','--host','unix:///var/run/docker.sock','rm','-f',target],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env,check=True)
                r=subprocess.run(['docker','--host','unix:///var/run/docker.sock','inspect',target],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env=env)
                removed=r.returncode!=0 and b'No such' in r.stderr
        except Exception:
            removed=False
    record={'schema':'dsmack-base-vm-derivation/1','source_lock_sha256':a.source_lock_sha256,'builder_image':lock['builder_image'],
            'owned_container_id':cid,'owned_container_removed':removed,'elapsed_seconds':time.monotonic()-started,'error_type':error,'qualified_runtime':False,'reproducible_clean_build':False}
    try:
        if error or not removed:raise ValueError('build/owned cleanup incomplete')
        source_check(a.source_lock_sha256)
        for directory,pins in ((base,lock['base_inputs']),(templates,lock['template_inputs'])):
            for filename,row in pins.items():regular(directory/filename,row)
        artifacts=out/'build/legs/diagnostic/files'
        records=validate_artifacts(artifacts,lock['expected_artifacts'])
        record['artifacts']=records
        record['image_sha256']=records['sha256sum.txt']['sha256']
        if record['image_sha256']!=lock['expected_derived_image_sha256']:raise ValueError('new derived output differs from selected qualified input; independent review required')
        record['expected_output_matched']=True
    finally:
        (out/'DERIVATION-RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-lock-sha256',required=True)
    p.add_argument('--check-source',action='store_true')
    p.add_argument('--base-bundle');p.add_argument('--templates');p.add_argument('--out')
    a=p.parse_args()
    if not re.fullmatch('[0-9a-f]{64}',a.source_lock_sha256):raise ValueError('explicit source lock digest required')
    print(json.dumps(build(a),sort_keys=True))

if __name__=='__main__':main()
