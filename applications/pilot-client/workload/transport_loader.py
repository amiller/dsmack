"""Load exact previously qualified transport source bytes, never bytecode caches.

Original source remains operator-selected external dependency. Raw pins below
are from browser-guest-build-3 and its original private reader; this is not a
new transport grammar. The caller must run isolated Python in an owned stable
namespace and must not import another dsmack_guest_io package first.
"""
import os,stat,sys,types
from pathlib import Path
SOURCES=('launch_vm_dstack_arm64.py','__init__.py','pt_limits.py','private_transport.py')
def raw(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or s.st_size>1048576:raise ValueError('selected source type/size')
  b=os.read(fd,1048577)
 finally:os.close(fd)
 return b
def execute(name,path,body,package=False):
 m=types.ModuleType(name);m.__file__=str(path);m.__package__=name if package else name.rpartition('.')[0]
 if package:m.__path__=[]
 sys.modules[name]=m
 exec(compile(body,str(path),'exec'),m.__dict__)
 return m
def load(path):
 path=Path(path);root=path.parent.parent/'runner-content/dsmack_guest_io'
 sources={n:raw(path if n=='launch_vm_dstack_arm64.py' else root/n)for n in SOURCES}
 if any(n=='dsmack_guest_io'or n.startswith('dsmack_guest_io.')for n in sys.modules):raise ValueError('transport package already imported')
 package=execute('dsmack_guest_io',root/'__init__.py',sources['__init__.py'],True)
 for n in ('pt_limits','private_transport'):
  m=execute('dsmack_guest_io.'+n,root/(n+'.py'),sources[n+'.py']);setattr(package,n,m)
 return execute('dsmack_selected_original_transport',path,sources[path.name])
