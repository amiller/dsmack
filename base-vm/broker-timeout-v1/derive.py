#!/usr/bin/env python3
"""Owned Zed /data-only derivative; no sign/provider/VM/publication."""
import argparse,hashlib,json,os,shutil,stat,subprocess,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def need(ok,m):
 if not ok:raise ValueError(m)
def file_sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def pins(root,expected):
 for n,d in expected.items():
  p=root/n;meta=p.lstat();need(stat.S_ISREG(meta.st_mode)and meta.st_nlink==1 and meta.st_size==d['bytes']and file_sha(p)==d['sha256'],'selected artifact mismatch')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-freeze-sha256',required=True);ap.add_argument('--parent',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 raw=(HERE/'SOURCE-PINS.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==a.source_freeze_sha256,'independent sourcefreeze')
 for n,d in json.loads(raw)['files'].items():pins(HERE,{n:d})
 origin=json.loads((HERE/'SOURCE-ORIGIN.json').read_bytes());baseline=HERE.parent/'browser-sandbox-v1';need(sha(baseline/'SOURCE-LOCK.json')==origin['baseline_source_lock_sha256'],'originalsource lock')
 lock=json.loads((baseline/'SOURCE-LOCK.json').read_bytes());pins(baseline,lock['files']);need(all(not p.is_symlink()and(p.is_dir()or p.is_file())for p in(baseline/'source').rglob('*')),'ordinary originalsource entries');need({p.relative_to(baseline).as_posix()for p in(baseline/'source').rglob('*')if p.is_file()}=={n for n in lock['files']if n.startswith('source/')},'closed originalsource membership');need(sha(baseline/'source/build/assemble_leg.sh')==origin['assemble_original_sha256'],'assembler source')
 parent=Path(a.parent).absolute();pins(parent,origin['parent_artifacts']);need(file_sha(parent/'sha256sum.txt')==origin['parent_os_image_hash'],'parent image')
 out=Path(a.out).absolute();need(str(out).startswith('/data/')and not out.exists(),'fresh Zed/data output');out.mkdir(mode=0o700);shutil.copytree(baseline/'source',out/'source');(out/'build').mkdir();(out/'docker-config').mkdir(mode=0o700);env={'PATH':'/usr/bin:/bin:/usr/local/bin','HOME':str(out),'DOCKER_CONFIG':str(out/'docker-config'),'LANG':'C.UTF-8'};docker=['docker','--host','unix:///var/run/docker.sock']
 p=out/'source/build/assemble_leg.sh';s=p.read_text();old='IMAGE_VERSION=0.7.0.browser-sandbox-v1';need(s.count(old)==1,'assembler version target');p.write_text(s.replace(old,'IMAGE_VERSION='+origin['new_image_version']))
 shutil.copyfile(HERE/'derive-in-container.sh',out/'derive.sh');shutil.copyfile(HERE/'sentinel.py',out/'sentinel.py')
 staged={p.relative_to(out).as_posix():{'bytes':p.stat().st_size,'sha256':file_sha(p)}for p in(out/'source').rglob('*')if p.is_file()}
 expected_source={n:d for n,d in lock['files'].items()if n.startswith('source/')}
 original=(baseline/'source/build/assemble_leg.sh').read_bytes();changed=original.replace(b'IMAGE_VERSION=0.7.0.browser-sandbox-v1',('IMAGE_VERSION='+origin['new_image_version']).encode());expected_source['source/build/assemble_leg.sh']={'bytes':len(changed),'sha256':hashlib.sha256(changed).hexdigest()}
 need(staged==expected_source,'copied source correspondence');staged.update({'derive.sh':json.loads(raw)['files']['derive-in-container.sh'],'sentinel.py':json.loads(raw)['files']['sentinel.py']});pins(out,staged)
 name='dsmack-broker-timeout-'+uuid.uuid4().hex;cid=None;removed=False;start=time.monotonic()
 argv=docker+['create','--pull','never','--name',name,'--network','none','--cpus','4','--memory','4g','--pids-limit','256','--env','PYTHONDONTWRITEBYTECODE=1','--mount','type=bind,src='+str(out)+',dst=/w','--mount','type=bind,src='+str(out/'source')+',dst=/w/source,readonly','--mount','type=bind,src='+str(parent)+',dst=/prior-image,readonly','--mount','type=bind,src='+str(parent)+',dst=/selected-templates,readonly',origin['builder_image'],'bash','/w/derive.sh']
 try:
  cid=subprocess.check_output(argv,timeout=30,env=env).decode().strip();need(len(cid)==64,'owned container ID');(out/'OWNED-CONTAINER.json').write_text(json.dumps({'id':cid,'name':name})+'\n')
  with(out/'build.log').open('wb')as log:subprocess.run(docker+['start','-a',cid],stdout=log,stderr=subprocess.STDOUT,timeout=900,check=True,env=env)
  state=json.loads(subprocess.check_output(docker+['inspect',cid],timeout=15,env=env))[0]['State'];need(not state['Running']and state['ExitCode']==0 and not state['OOMKilled'],'build state')
 finally:
  if cid:
   subprocess.run(docker+['stop','-t','5',cid],capture_output=True,timeout=15,env=env);subprocess.run(docker+['rm','-f',cid],capture_output=True,timeout=15,check=True,env=env);removed=True
 need(sha(HERE/'SOURCE-PINS.json')==a.source_freeze_sha256,'postbuild sourcefreeze');pins(HERE,json.loads(raw)['files']);pins(baseline,lock['files']);pins(parent,origin['parent_artifacts']);pins(out,staged)
 need({p.relative_to(out).as_posix()for p in(out/'source').rglob('*')if p.is_file()}==set(expected_source),'postbuild stagedsource membership')
 files=out/'build/legs/diagnostic/files';expected={'Image','config-6.18.40-dstack','initramfs.cpio.gz','rootfs.squashfs.verity','metadata.json','sha256sum.txt','digest.txt','artifact-manifest.json','scratch-template.ext4','result-template.ext4','disk-templates.json'};need({p.name for p in files.iterdir()}==expected,'closed outputmembership')
 for p in files.iterdir():
  meta=p.lstat();need(stat.S_ISREG(meta.st_mode)and meta.st_nlink==1,'ordinary singlelink output')
 pins(files,{n:origin['parent_artifacts'][n]for n in ('Image','initramfs.cpio.gz','config-6.18.40-dstack','scratch-template.ext4','result-template.ext4','disk-templates.json')})
 rows=(files/'sha256sum.txt').read_text().splitlines();need(len(rows)==4 and {line.split('  ')[1]for line in rows}=={'Image','initramfs.cpio.gz','metadata.json','rootfs.squashfs.verity'},'closed imagechecksum membership')
 for line in rows:
  digest,n=line.split('  ');need(n in expected and file_sha(files/n)==digest,'actual outputchecksum')
 result={'schema':'dsmack-broker-timeout-base-derivation/1','source_freeze_sha256':a.source_freeze_sha256,'parent_os_image_hash':origin['parent_os_image_hash'],'artifacts':{p.name:{'bytes':p.stat().st_size,'sha256':file_sha(p)}for p in sorted(files.iterdir())},'elapsed_seconds':time.monotonic()-start,'owned_container_removed':removed,'qualified_runtime':False,'provider_calls':False,'vm_launched':False};(out/'DERIVATION-RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
