#!/usr/bin/env python3
"""Selected Linux verifier launcher; source/environment preflight before imports.
This launcher itself must already be independently selected/inspected.
"""
import argparse,atexit,hashlib,importlib.util,importlib.metadata,json,os,platform,stat,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
class Refused(ValueError):pass
def need(v,message):
 if not v:raise Refused(message)
def read_file(path,cap=16777216):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid in (0,os.getuid()) and st.st_mode&0o022==0 and 0<=st.st_size<=cap,'regular bounded file required')
  b=b''
  while len(b)<=cap:
   x=os.read(fd,min(1048576,cap+1-len(b)))
   if not x:break
   b+=x
  need(len(b)<=cap,'file cap');return b
 finally:os.close(fd)
def digest(path,cap=16777216):return hashlib.sha256(read_file(path,cap)).hexdigest()
def load(path,expected):
 need(isinstance(expected,str) and len(expected)==64 and all(c in '0123456789abcdef' for c in expected),'independent manifest SHA-256 required')
 raw=read_file(path,1048576);need(hashlib.sha256(raw).hexdigest()==expected,'selected manifest changed')
 def pairs(a):
  d={}
  for k,v in a:
   need(k not in d,'duplicate manifest key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs)
def protected_root():
 for p in (ROOT,*ROOT.parents):
  st=os.lstat(p);need(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,os.getuid()) and st.st_mode&0o022==0,'stage runtime under protected user/root ancestors')
def source_check(expected):
 need(sys.flags.isolated==1,'run selected Python with -I')
 protected_root();m=load(ROOT/'SOURCE-PINS.json',expected)
 need(isinstance(m,dict) and set(m)=={'schema','files'} and m['schema']=='dsmack-full-verifier-source-pins/1','source inventory shape')
 files=m['files'];need(isinstance(files,dict),'source inventory files')
 entries=list(ROOT.rglob('*'))
 for p in entries:
  st=os.lstat(p);need(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,os.getuid()) and st.st_mode&0o022==0,'protected source descendant required')
 actual={str(p.relative_to(ROOT)) for p in entries if p.is_file()}
 # No caches, native extension alternatives, archives or unlisted import inputs.
 expected=set(files)|{'SOURCE-PINS.json','SOURCE-IMPORT.json','QUALIFIED-LINUX-ENVIRONMENT.json','README.md'}
 need(actual==expected,'complete runtime file membership changed')
 for name,pin in files.items():
  rel=Path(name);need(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'relative source path')
  need(set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and 0<=pin['bytes']<=16777216,'source pin shape')
  raw=read_file(ROOT/rel);need(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'selected source bytes changed')
 return len(files)
def prepare_source_imports():
 # -B alone still reads existing .pyc. A unique cache prefix makes installed
 # dependency caches unreachable; selected-tree caches are rejected separately.
 home=Path.home()
 for p in (home,*home.parents):
  st=os.lstat(p);need(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,os.getuid()) and st.st_mode&0o022==0,'protected home needed for fresh empty import cache')
 cache=tempfile.mkdtemp(prefix='.dsmack-source-import-',dir=home)
 os.chmod(cache,0o700);sys.pycache_prefix=cache;sys.dont_write_bytecode=True
 def cleanup():
  try:os.rmdir(cache) # Empty only; retain unexpected residue instead of deleting it.
  except OSError:pass
 atexit.register(cleanup)
 return cache

def environment_check(expected):
 m=load(ROOT/'QUALIFIED-LINUX-ENVIRONMENT.json',expected)
 need(m['schema']=='dsmack-linux-verifier-environment/1','environment schema')
 need(platform.system()==m['system']=='Linux' and platform.machine()==m['machine'] and platform.python_version()==m['python_version'],'qualified Linux/Python architecture required')
 # PATH-dependent OpenSSL in the original core has only these trusted roots.
 os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LANG='C')
 import ssl
 need(ssl.OPENSSL_VERSION==m['openssl_version'],'qualified OpenSSL runtime required')
 for path,pin in m['files'].items():
  p=Path(path).resolve();raw=read_file(p,67108864);need(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'qualified tool bytes changed')
 need(Path(sys.executable).resolve()==Path('/usr/bin/python3').resolve(),'qualified Python executable required')
 for name,version in m['distribution_versions'].items():need(importlib.metadata.version(name)==version,'qualified dependency version required')
 for name,package in m['packages'].items():
  spec=importlib.util.find_spec(name);need(spec is not None and spec.origin==package['origin'],'qualified dependency origin required')
  origin=Path(spec.origin)
  paths={str(p.relative_to(origin.parent)):p for p in origin.parent.rglob('*') if p.is_file() and p.suffix in ('.py','.so')} if spec.submodule_search_locations else {origin.name:origin}
  need(set(paths)==set(package['files']),'dependency source membership changed')
  for rel,pin in package['files'].items():
   raw=read_file(paths[rel],67108864);need(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'qualified dependency bytes changed')
 return m

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--source-manifest-sha256',required=True)
 parser.add_argument('--environment-sha256',required=True)
 parser.add_argument('command',choices=('doctor','operator','prepare','transfer'))
 parser.add_argument('args',nargs=argparse.REMAINDER)
 a=parser.parse_args(argv)
 try:
  count=source_check(a.source_manifest_sha256);prepare_source_imports();env=environment_check(a.environment_sha256)
  # No selected implementation imported before all source/environment checks.
  sys.path.insert(0,str(ROOT))
  from runresult_ref.extraction import sandbox_available
  sandbox=sandbox_available()
  if a.command=='doctor':
   need(not a.args,'doctor has no extra options')
   print(json.dumps({'schema':'dsmack-full-verifier-doctor/1','source_files_checked':count,'qualified_environment_matches':True,'namespace_sandbox_available':sandbox,'platform':env['system'],'architecture':env['machine'],'runtime_ready':sandbox,'authority_ready':False,'enrollment_checked':False,'replay_opened':False,'private_inputs_read':False,'execution_verified':False,'task_accepted':False,'payment_received':False},sort_keys=True));return 0 if sandbox else 2
  need(sandbox,'Linux namespace sandbox unavailable; no extraction fallback')
  if a.command=='operator':
   from runresult_ref.operator_cli import main as entry
  elif a.command=='prepare':
   from tools.prepare_app_evidence import main as entry
  else:
   from tools.evidence_transfer import main as entry
  return entry(a.args)
 except (Refused,OSError,ValueError,ImportError,KeyError) as e:
  # Avoid printing candidate data or private paths on a failed operation.
  print('Verifier package preflight refused; preserve original evidence and inspect protected local configuration.',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
