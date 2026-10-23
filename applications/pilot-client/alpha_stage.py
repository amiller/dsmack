"""Authenticated finite release staging. No credentials, downloads or VM launch."""
import argparse,fcntl,gzip,hashlib,json,os,re,stat,subprocess,tarfile,tempfile,shutil
from pathlib import Path

def need(ok,label):
 if not ok:raise ValueError(label)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def read_regular(path,limit,expected=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,'regular bounded input')
  b=b''
  while len(b)<=limit:
   chunk=os.read(fd,min(1048576,limit+1-len(b)))
   if not chunk:break
   b+=chunk
  need(len(b)<=limit,'input limit')
  if expected:need(len(b)==expected['bytes'] and hashlib.sha256(b).hexdigest()==expected['sha256'],'bootstrap pin')
  return b
 finally:os.close(fd)

def protected(path,private=False):
 path=Path(path);need(path.is_absolute(),'absolute path')
 for x in (path,*path.parents):
  s=os.lstat(x);need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'protected directory ancestry')
 if private:need(os.lstat(path).st_uid==os.getuid() and not os.lstat(path).st_mode&0o077,'private stage parent')

def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def write(fd,data):
 while data:
  n=os.write(fd,data);need(n>0,'short write');data=data[n:]

def authenticate(bootstrap,inventory,signature,root=None,profile=None,workload_admission=None,workload_signature=None):
 need(set(bootstrap)==({'schema','node','sources','trust_key','key_id','channel','min_sequence'}|({'runtime','runtime_dependencies'} if bootstrap.get('schema')=='dsmack-alpha-bootstrap/2' else set())),'bootstrap fields')
 need(bootstrap['schema'] in ('dsmack-alpha-bootstrap/1','dsmack-alpha-bootstrap/2'),'bootstrap schema')
 need(set(bootstrap['sources'])=={'alpha-release-cli.mjs','alpha-release.mjs','alpha-profile.mjs'},'complete Node source closure')
 dependencies=bootstrap.get('runtime_dependencies',[]);need(isinstance(dependencies,list) and len(dependencies)<=512,'runtime dependency limit')
 if bootstrap['schema']=='dsmack-alpha-bootstrap/2':
  rt=bootstrap['runtime'];need(set(rt)=={'node_version','node_arch','node_platform','shared_objects'} and isinstance(rt['node_version'],str) and re.fullmatch(r'v\d+\.\d+\.\d+',rt['node_version']) and rt['node_arch'] in ('arm64','x64') and rt['node_platform'] in ('darwin','linux'),'runtime metadata')
  objects=rt['shared_objects'];need(isinstance(objects,list) and len(objects)<=512 and all(isinstance(x,str) and len(x)<=4096 for x in objects) and objects==sorted(set(objects)),'runtime object set')
  external=[x for x in objects if x!='<node-executable>' and not x.startswith(('/System/Library/','/usr/lib/','/lib/','/lib64/')) and not x.startswith('linux-vdso.so.')]
  need(len(dependencies)==len(external) and {x.get('load_path') for x in dependencies}==set(external),'complete non-system dependency pins required')
 for item in dependencies:
  need(set(item)=={'load_path','path','bytes','sha256'} and isinstance(item['load_path'],str) and os.path.realpath(item['load_path'])==item['path'],'native dependency resolution changed')
  need(item['load_path']==item['path'],'native dependency aliases refused');protected(Path(item['load_path']).parent)
 for item in [bootstrap['node'],bootstrap['trust_key'],*bootstrap['sources'].values(),*dependencies]:
  need(set(item) in ({'path','bytes','sha256'},{'load_path','path','bytes','sha256'}) and isinstance(item['bytes'],int) and not isinstance(item['bytes'],bool) and item['bytes']>=0 and re.fullmatch('[a-f0-9]{64}',item['sha256'] or ''),'bootstrap descriptor')
  path=Path(item['path']);need(path.is_absolute(),'bootstrap absolute path');protected(path.parent)
  # Node is a selected executable, potentially large; hash by descriptor reads.
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not s.st_mode&0o022 and s.st_uid in (0,os.getuid()) and s.st_size==item['bytes'] and s.st_size<=268435456,'bootstrap file metadata')
   h=hashlib.sha256();total=0
   while True:
    b=os.read(fd,1048576)
    if not b:break
    h.update(b);total+=len(b)
   need(total==item['bytes'] and h.hexdigest()==item['sha256'],'bootstrap exact bytes')
  finally:os.close(fd)
 entry=Path(bootstrap['sources']['alpha-release-cli.mjs']['path'])
 need(all(Path(v['path'])==entry.parent/k for k,v in bootstrap['sources'].items()),'fixed relative import closure')
 need(isinstance(bootstrap['min_sequence'],int) and not isinstance(bootstrap['min_sequence'],bool) and bootstrap['min_sequence']>=0,'minimum sequence')
 argv=[bootstrap['node']['path'],str(entry),'--inventory',str(inventory),'--signature',str(signature),'--trust-key',bootstrap['trust_key']['path'],'--key-id',bootstrap['key_id'],'--channel',bootstrap['channel'],'--min-sequence',str(bootstrap['min_sequence'])]
 if root:argv+=['--root',str(root)]
 if profile:argv+=['--profile',profile]
 need(bool(workload_admission)==bool(workload_signature),'workload admission pair')
 if workload_admission:argv+=['--workload-admission',str(workload_admission),'--workload-signature',str(workload_signature)]
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180,env={'PATH':'/usr/bin:/bin','HOME':str(Path.home())},start_new_session=True)
 need(p.returncode==0 and len(p.stdout)<=524288,'exact Node admission refused')
 raw=p.stdout[:-1] if p.stdout.endswith(b'\n') else p.stdout
 value=json.loads(raw);need(raw==canonical(value),'canonical child output')
 need(set(value)=={'schema','inventory_sha256','inventory','staged_files_checked','profile','launch_ready','runtime','workload'} and value['schema']=='dsmack-alpha-authentication-result/3' and value['launch_ready'] is False,'child contract')
 need(value['inventory_sha256']==hashlib.sha256(read_regular(inventory,262144)).hexdigest() and value['staged_files_checked'] is bool(root),'child source correspondence')
 if bootstrap['schema']=='dsmack-alpha-bootstrap/2':
  need(set(bootstrap['runtime'])=={'node_version','node_arch','node_platform','shared_objects'} and value['runtime']==bootstrap['runtime'],'exact selected runtime/dependency closure changed')
 return value

def archive_identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def scan_archive(archive,expected,descriptor):
 # Preflight raw headers rather than letting TarFile normalize extension records.
 fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as raw:
  st=os.fstat(raw.fileno());need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==descriptor['bytes'] and st.st_size<=34359738368,'archive metadata')
  h=hashlib.sha256()
  while True:
   b=raw.read(1048576)
   if not b:break
   h.update(b)
  need(h.hexdigest()==descriptor['sha256'],'archive digest');raw.seek(0)
  magic=raw.read(2);need((magic==b'\x1f\x8b')==(descriptor['format']=='tar+gzip'),'archive encoding');raw.seek(0);stream=gzip.GzipFile(fileobj=raw) if magic==b'\x1f\x8b' else raw
  seen=set();dirs=set();members=0
  while True:
   block=stream.read(512);need(len(block)==512,'truncated tar header')
   if block==b'\0'*512:
    need(stream.read(512)==b'\0'*512,'two tar terminators required')
    trailing=stream.read(10241);need(len(trailing)<=10240 and not trailing.strip(b'\0'),'trailing archive payload refused')
    need(stream.read(1)==b'','trailing archive size');break
   member=tarfile.TarInfo.frombuf(block,'utf-8','strict');members+=1;need(members<=8192,'archive member bound')
   need(member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),'archive extension or nonregular type refused');need(block[257:265]==b'ustar'+bytes([0])+b'00','USTAR header required')
   name=member.name;need(name and not name.startswith('/') and '\\' not in name and all(x and x not in ('.','..') for x in name.rstrip('/').split('/')),'archive path')
   if member.isdir():
    name=name.rstrip('/');need(member.size==0 and name not in dirs and name not in expected and any(x.startswith(name+'/') for x in expected),'unknown or duplicate directory');dirs.add(name);continue
   need(name in expected and name not in seen,'unknown or duplicate member');e=expected[name];need(member.size==e['bytes'],'member declared size')
   h=hashlib.sha256();left=member.size
   while left:
    b=stream.read(min(1048576,left));need(b,'truncated member');left-=len(b);h.update(b)
   need(h.hexdigest()==e['sha256'],'member digest')
   padding=(-member.size)%512;need(stream.read(padding)==b'\0'*padding,'member padding')
   seen.add(name)
  need(seen==set(expected),'incomplete archive');need(archive_identity(os.fstat(raw.fileno()))==archive_identity(st),'archive changed during preflight');return archive_identity(st)

class StrictTarInfo(tarfile.TarInfo):
 def _proc_pax(self,*a,**k):raise ValueError('PAX refused')
 def _proc_gnulong(self,*a,**k):raise ValueError('GNU longname refused')
 def _proc_sparse(self,*a,**k):raise ValueError('sparse archive refused')

def _stage_authenticated(bootstrap,inventory,signature,archive,target,checked,before_rename,selected_archive_identity):
 # Signature, clock, rollback and complete resource bounds precede all writes.
 v=checked['inventory'];need(v['schema']=='dsmack-alpha-release/2','staging requires inventory/2')
 target=Path(target);need(target.is_absolute() and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,100}',target.name),'target path')
 protected(target.parent,True);need(not os.path.lexists(target),'existing stage refused')
 expected={x['path']:x for x in v['files']};need(len(expected)==len(v['files']) and sum(x['bytes'] for x in expected.values())<=34359738368,'closure bounds')
 lock=target.parent/(target.name+'.install-journal.json')
 fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:write(fd,canonical({'schema':'dsmack-alpha-install-journal/1','state':'installation-requested','inventory_sha256':checked['inventory_sha256'],'target':str(target)}));os.fsync(fd)
 finally:os.close(fd)
 syncdir(target.parent)
 incoming=Path(tempfile.mkdtemp(prefix='.'+target.name+'.incoming-',dir=target.parent));os.chmod(incoming,0o700)
 # Failure preserves this finite private tree + journal for explicit diagnosis;
 # never implicitly retry an ambiguous install or replace an existing version.
 afd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 seen=set();directories=set();members=0
 with os.fdopen(afd,'rb') as source:
  s=os.fstat(source.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==v['archive']['bytes'] and archive_identity(s)==selected_archive_identity,'selected archive identity changed')
  with tarfile.open(fileobj=source,mode='r|*',tarinfo=StrictTarInfo) as tar:
   for member in tar:
    members+=1;need(members<=8192,'archive member bound')
    name=member.name
    need(isinstance(name,str) and name and not name.startswith('/') and '\\' not in name and all(x and x not in ('.','..') for x in name.rstrip('/').split('/')),'archive path')
    need(not member.pax_headers and member.type not in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK),'archive extension refused')
    if member.isdir():
     name=name.rstrip('/');need(name not in directories and name not in expected and any(x.startswith(name+'/') for x in expected),'unknown or duplicate directory');directories.add(name);continue
    need(member.isreg() and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE),'nonregular archive member')
    need(name in expected and name not in seen,'unlisted or duplicate file');e=expected[name];need(member.size==e['bytes'],'member declared size')
    dest=incoming/name
    parent=incoming
    for part in Path(name).parts[:-1]:
     parent=parent/part
     if not parent.exists():parent.mkdir(mode=0o700)
     need(parent.is_dir() and not parent.is_symlink() and not parent.stat().st_mode&0o077,'private member parent')
    data=tar.extractfile(member);need(data is not None,'member reader')
    f=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,e['mode']);h=hashlib.sha256();total=0
    try:
     while True:
      b=data.read(min(1048576,e['bytes']-total+1))
      if not b:break
      total+=len(b);need(total<=e['bytes'],'member data bound');h.update(b);write(f,b)
     need(total==e['bytes'] and h.hexdigest()==e['sha256'],'member digest');os.fchmod(f,e['mode']);os.fsync(f)
    finally:os.close(f);data.close()
    seen.add(name)
  source.seek(0);h=hashlib.sha256();total=0
  while True:
   b=source.read(1048576)
   if not b:break
   h.update(b);total+=len(b)
  need(total==v['archive']['bytes'] and h.hexdigest()==v['archive']['sha256'] and archive_identity(os.fstat(source.fileno()))==selected_archive_identity,'actual extraction archive changed')
 need(seen==set(expected),'incomplete archive')
 # Independently authenticate again and check actual installed tree before rename.
 final_check=authenticate(bootstrap,inventory,signature,root=incoming)
 need(final_check['inventory_sha256']==checked['inventory_sha256'],'selected inventory changed during installation')
 for parent,dirs,files in os.walk(incoming,topdown=False):syncdir(parent)
 need(not os.path.lexists(target),'target appeared; preserve incoming')
 before_rename();os.rename(incoming,target);syncdir(target.parent)
 return {'schema':'dsmack-alpha-stage-result/1','inventory_sha256':checked['inventory_sha256'],'stage':str(target),'files':len(seen),'staged_files_checked':True,'launch_ready':False,'journal':str(lock),'journal_semantics':'installation-requested retained; existing journal refuses implicit retry'}

def stage(bootstrap,inventory,signature,archive,target):
 checked=authenticate(bootstrap,inventory,signature);need(checked['inventory']['schema']=='dsmack-alpha-release/2','staging requires inventory/2')
 selected_archive_identity=scan_archive(archive,{x['path']:x for x in checked['inventory']['files']},checked['inventory']['archive'])
 target=Path(target);need(target.is_absolute() and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,100}',target.name),'absolute fresh version stage');protected(target.parent,True)
 need(shutil.disk_usage(target.parent).free>=sum(f['bytes'] for f in checked['inventory']['files'])+67108864,'expanded release headroom required')
 need(not os.path.lexists(target),'existing stage refused')
 lock=target.parent/'.alpha-release-state.lock'
 fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o077,'private state lock')
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  statepath=target.parent/'alpha-release-state.json';state=None
  if os.path.lexists(statepath):
   st=os.lstat(statepath);need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o077,'private release state')
   state=json.loads(read_regular(statepath,65536))
   need(set(state)=={'schema','key_id','channel','root_sha256','minimum_sequence','inventory_sha256'} and state['schema']=='dsmack-alpha-release-state/1','state schema')
   need(state['key_id']==bootstrap['key_id'] and state['channel']==bootstrap['channel'] and state['root_sha256']==bootstrap['trust_key']['sha256'],'explicit release authority rotation required')
   need(type(state['minimum_sequence']) is int and state['minimum_sequence']>=0,'state sequence')
   seq=checked['inventory']['sequence'];need(seq>=state['minimum_sequence'],'persisted rollback floor')
   if seq==state['minimum_sequence']:need(checked['inventory_sha256']==state['inventory_sha256'],'same-sequence equivocation refused')
  def advance():
   value={'schema':'dsmack-alpha-release-state/1','key_id':bootstrap['key_id'],'channel':bootstrap['channel'],'root_sha256':bootstrap['trust_key']['sha256'],'minimum_sequence':checked['inventory']['sequence'],'inventory_sha256':checked['inventory_sha256']}
   tmpfd,name=tempfile.mkstemp(prefix='.release-state-',dir=target.parent)
   try:os.fchmod(tmpfd,0o600);write(tmpfd,canonical(value));os.fsync(tmpfd)
   finally:os.close(tmpfd)
   os.replace(name,statepath);syncdir(target.parent)
  return _stage_authenticated(bootstrap,inventory,signature,archive,target,checked,advance,selected_archive_identity)
 finally:os.close(fd)

def installation_plan(bootstrap,inventory,signature,target):
 checked=authenticate(bootstrap,inventory,signature);v=checked['inventory'];need(v['schema']=='dsmack-alpha-release/2','inventory/2 required')
 target=Path(target);protected(target.parent,True)
 expanded=sum(f['bytes'] for f in v['files']);free=shutil.disk_usage(target.parent).free
 return {'schema':'dsmack-alpha-install-plan/1','persisted_rollback_state_checked':False,'install_admissible':None,'inventory_sha256':checked['inventory_sha256'],'compressed_download_bytes':v['archive']['bytes'],'expanded_stage_bytes':expanded,'required_free_bytes_with_archive_present':expanded+67108864,'required_free_bytes_before_download':expanded+v['archive']['bytes']+67108864,'available_bytes':free,'sparse_extraction':False,'writes_performed':False,'launch_ready':False}

def main():
 p=argparse.ArgumentParser();p.add_argument('--bootstrap',required=True);p.add_argument('--inventory',required=True);p.add_argument('--signature',required=True);p.add_argument('--archive');p.add_argument('--target',required=True);p.add_argument('--plan',action='store_true');o=p.parse_args()
 bp=Path(o.bootstrap);protected(bp.parent);bs=os.lstat(bp);need(stat.S_ISREG(bs.st_mode) and bs.st_uid in (0,os.getuid()) and not bs.st_mode&0o022,'protected bootstrap config');b=json.loads(read_regular(bp,65536))
 if o.plan:r=installation_plan(b,o.inventory,o.signature,o.target)
 else:
  need(o.archive is not None,'archive required for staging');r=stage(b,o.inventory,o.signature,o.archive,o.target)
 print(json.dumps(r,sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
