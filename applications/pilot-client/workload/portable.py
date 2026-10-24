#!/usr/bin/env python3
"""Private VDE encoder with an explicitly unsealed portable backing backend.

No wire/guest/app changes. Same-UID host integrity is trusted; unlinked regular
files are NOT Linux kernel write seals. No private bytes/digests in diagnostics.
"""
import argparse,ast,hashlib,io,contextlib,os,stat,tempfile,sys,types
from pathlib import Path

def need(ok,message):
 if not ok:raise ValueError(message)
def protected(path):
 p=Path(path);need(p.is_absolute(),'absolute private temporary parent required')
 for ancestor in (p,*p.parents):
  s=ancestor.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'protected temporary ancestry required')
 s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'owned0700 temporary parent required')
def selected_loader():
 p=Path(__file__).with_name('transport_loader.py');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=65536,'loader source type/size');raw=os.read(fd,65537)
 finally:os.close(fd)
 ns={'__name__':'dsmack_portable_loader','__file__':str(p)};exec(compile(raw,str(p),'exec'),ns);return ns

def identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
class Backing:
 def __init__(self,parent):protected(parent);self.parent=str(parent);self.sealed={};self.opened=[]
 def metadata(self,fd):
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==0 and stat.S_IMODE(s.st_mode)==0o600,'anonymous owned0600 regular descriptor required');return s
 def anonymous(self,label,owned):
  protected(self.parent);f=tempfile.TemporaryFile(mode='w+b',dir=self.parent,prefix='.dsmack-vde-');owned.enter_context(f);fd=f.fileno();self.metadata(fd);self.sealed.pop(fd,None);self.opened.append(fd);return fd
 def digest(self,fd,expected):
  h=hashlib.sha256();offset=0
  while offset<expected:
   chunk=os.pread(fd,min(1048576,expected-offset),offset);need(chunk,'portable staged read truncated');offset+=len(chunk);h.update(chunk)
  need(not os.pread(fd,1,expected),'portable staged read grew');return h.digest()
 def seal(self,fd,expected):
  # Writer quiescence and metadata checks, explicitly NOT F_ADD_SEALS.
  os.fsync(fd);s=self.metadata(fd);need(s.st_size==expected,'portable staged size changed');need(fd not in self.sealed,'descriptor already closed for writes');self.sealed[fd]=(identity(s),self.digest(fd,expected));need(identity(self.metadata(fd))==identity(s),'portable staged descriptor changed while hashing');return s
 def consume(self,fd,expected):
  s=self.metadata(fd);need(s.st_size==expected and self.sealed.get(fd)==(identity(s),self.digest(fd,expected)) and identity(self.metadata(fd))==identity(s),'portable descriptor changed after staging');os.lseek(fd,0,os.SEEK_SET);return os.fdopen(os.dup(fd),'rb')

REPLACEMENTS='''
def anonymous(label):
 return _portable.anonymous(label,owned)
def seal(fd,expected):
 return _portable.seal(fd,expected)
def consume(fd,expected):
 return _portable.consume(fd,expected)
'''
def derive(original,source,backing):
 """Exactly three inner functions and one Linux-seal assignment may change."""
 tree=ast.parse(source);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_build_transport'];need(len(functions)==1,'original transport function shape');function=functions[0]
 replacements={n.name:n for n in ast.parse(REPLACEMENTS).body};counts={k:0 for k in (*replacements,'seals')}
 class Seam(ast.NodeTransformer):
  def visit_FunctionDef(self,n):
   if n.name in replacements:counts[n.name]+=1;return replacements[n.name]
   return self.generic_visit(n)
  def visit_Assign(self,n):
   if len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='seals':
    counts['seals']+=1;return ast.Assign(targets=n.targets,value=ast.Constant(0))
   return self.generic_visit(n)
 function=Seam().visit(function);need(counts=={'anonymous':1,'seal':1,'consume':1,'seals':1},'original descriptor seam shape changed')
 tree=ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]));namespace=dict(original.__dict__);namespace['_portable']=backing;exec(compile(tree,'<pinned-transport-portable-backend>','exec'),namespace)
 return namespace['_build_transport']

def load_portable(transport_module,temporary_parent):
 """Initialize once per isolated process, before any credential is read."""
 loader=selected_loader();path=Path(transport_module);source=loader['raw'](path);original=loader['load'](path);backing=Backing(temporary_parent);builder=derive(original,source,backing)
 def private(rt,workload_dir,out_img,max_bytes,require_residue_free=False):
  need(type(max_bytes)is int and 0<max_bytes<=1<<30,'private image cap')
  return builder(rt,str(workload_dir),str(out_img),max_bytes,True,require_residue_free)
 return types.SimpleNamespace(start_overall_deadline=original.start_overall_deadline,build_private_disk=private)

def build_private(transport_module,workload_dir,out_img,max_bytes,temporary_parent):
 transport=load_portable(transport_module,temporary_parent);transport.start_overall_deadline(300)
 # Preserve bounded original lifecycle and deferred output-residue policy. Its
 # path-only diagnostics are withheld here rather than becoming public logs.
 with contextlib.redirect_stderr(io.StringIO()):return transport.build_private_disk({},workload_dir,out_img,max_bytes)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('transport-module','input-root','out','temporary-parent'):p.add_argument('--'+n,required=True)
 p.add_argument('--max-bytes',type=int,default=64<<20);a=p.parse_args()
 result=build_private(a.transport_module,a.input_root,a.out,a.max_bytes,a.temporary_parent)
 print('Private VDE packed; original guest grammar checked; kernel write seals unavailable.' if result else 'No private input entries; no image created.')
if __name__=='__main__':
 try:main()
 except (Exception,SystemExit) as exc:
  if isinstance(exc,SystemExit) and exc.code==0:raise
  print('Private packing refused; preserve owned output residue and inspect locally. Private contents withheld.',file=sys.stderr);raise SystemExit(2)
