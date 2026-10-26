"""Bounded public USTAR task preparation/inspection; no signing, credentials or VM."""
import argparse,copy,datetime,hashlib,io,json,os,re,stat,tarfile
from pathlib import Path
CAP=4<<30
CONTEXT='closure-context/context.json'
def need(v,m):
 if not v:raise ValueError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def closure(raw,selector):
 v=json.loads(raw);need(set(v)=={'schema','attempt_id','selectors'} and v['schema']=='dsmack-result-closure-context/1' and isinstance(v['attempt_id'],str) and re.fullmatch('[a-f0-9]{32}',v['attempt_id']) and v['selectors']==[selector] and canonical(v)==raw,'canonical selected closure required');return v
def protected(path):
 p=Path(path);need(p.is_absolute(),'absolute public input')
 for x in (p,*p.parents):
  s=os.lstat(x);need(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'protected public input ancestry')
def scan_payload(descriptor,selector,manifest_sha256,expected_closure=None,cap=CAP):
 need(set(descriptor)=={'path','bytes','sha256'} and type(descriptor['bytes']) is int and 0<descriptor['bytes']<=cap<=CAP and re.fullmatch('[a-f0-9]{64}',descriptor['sha256'] or ''),'public disk descriptor/cap')
 need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',selector) and re.fullmatch('[a-f0-9]{64}',manifest_sha256),'selected public manifest')
 protected(descriptor['path']);fd=os.open(descriptor['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and st.st_size==descriptor['bytes'],'owned regular exact public disk')
  h=hashlib.sha256();total=0;files={};dirs=set();aliases={};selected={};count=0
  wanted={CONTEXT:65536,'manifests/'+selector+'.app-compose.json':1<<20,'WORKLOAD':256,'SHA256SUMS':1<<20}
  def read(n):
   nonlocal total
   b=f.read(n);total+=len(b);need(total<=descriptor['bytes'],'public disk size exceeded');h.update(b);return b
  while True:
   block=read(512);need(len(block)==512,'truncated USTAR header')
   if block==b'\0'*512:
    need(read(512)==b'\0'*512,'two USTAR terminators required')
    expected_size=(((total+10239)//10240*10240+1048575)//1048576)*1048576
    need(descriptor['bytes']==expected_size,'canonical public disk alignment')
    trailing=0
    while True:
     tail=read(65536)
     if not tail:break
     trailing+=len(tail);need(trailing<=1048576+10240 and not tail.strip(b'\0'),'trailing USTAR payload')
    break
   count+=1;need(count<=8192,'public member cap');m=tarfile.TarInfo.frombuf(block,'utf-8','strict')
   need(block[257:265]==b'ustar\00000' and m.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),'only USTAR regular files/directories')
   need(not block[124]&128 and not block[136]&128 and m.tobuf(tarfile.USTAR_FORMAT,'utf-8','strict')==block,'noncanonical USTAR header')
   def field(b):
    parts=b.split(b'\0',1);need(len(parts)==1 or not parts[1].strip(b'\0'),'noncanonical pathname field');return parts[0].decode('ascii')
   rawname=field(block[:100]);prefix=field(block[345:500]);name=(prefix+'/' if prefix else '')+rawname
   if m.isdir() and name.endswith('/'):name=name[:-1]
   expected_name=m.name[:-1] if m.isdir() and m.name.endswith('/') else m.name
   need(re.fullmatch('[A-Za-z0-9._/-]+',name) and not name.startswith('/') and all(p and p not in ('.','..') for p in name.split('/')) and name==expected_name,'canonical public member path')
   if selector in ('bounty-board-search-develop-v1','bounty-board-search-generate-v1','agent-turns-edit-v1'):need(name not in ('public-inputs','envelopes','broker') and not name.startswith(('public-inputs/','envelopes/','broker/')),'Private develop forbids public runtime channel')
   need(not name.startswith('manifests/') or name=='manifests/'+selector+'.app-compose.json','unexpected public manifest member')
   need(not name.startswith('closure-context/') or name==CONTEXT,'unexpected public closure member')
   need(name not in files and name not in dirs,'duplicate public member')
   parts=name.split('/')
   for i in range(1,len(parts)+1):
    p='/'.join(parts[:i]);a=p.lower();need(a not in aliases or aliases[a]==p,'public path case alias');aliases[a]=p
    if i<len(parts):need(p not in files,'public ancestor file')
   need(not any(p.startswith(name+'/') for p in set(files)|dirs) or m.isdir(),'public file/ancestor collision')
   if m.isdir():need(m.size==0,'nonempty public directory');dirs.add(name);continue
   need(0<=m.size<=cap and sum(x['bytes'] for x in files.values())+m.size<=cap,'public member/aggregate size');left=m.size;fh=hashlib.sha256();pieces=[]
   if name in wanted:need(m.size<=wanted[name],'selected public member size')
   while left:
    b=read(min(1048576,left));need(b,'truncated public member');left-=len(b);fh.update(b)
    if name in wanted:pieces.append(b)
   need(read((-m.size)%512)==b'\0'*((-m.size)%512),'nonzero public member padding');files[name]={'bytes':m.size,'sha256':fh.hexdigest()}
   if name in wanted:selected[name]=b''.join(pieces)
  need(total==descriptor['bytes'] and h.hexdigest()==descriptor['sha256'] and identity(os.fstat(f.fileno()))==identity(st),'public disk bytes/identity changed')
 need(set(selected)==set(wanted),'missing selected public member');c=closure(selected[CONTEXT],selector)
 need(expected_closure is None or selected[CONTEXT]==expected_closure,'packaged closure differs from task/checker context')
 need(selected['WORKLOAD']==(selector+'\n').encode(),'public WORKLOAD selector');need(hashlib.sha256(selected['manifests/'+selector+'.app-compose.json']).hexdigest()==manifest_sha256,'packaged manifest differs')
 sums={}
 for line in selected['SHA256SUMS'].decode('ascii').splitlines():
  match=re.fullmatch('([a-f0-9]{64})  ([A-Za-z0-9._/-]+)',line);need(match is not None and match[2] not in sums,'public SHA256SUMS grammar/duplicate');sums[match[2]]=match[1]
 need(sums=={p:v['sha256'] for p,v in files.items() if p!='SHA256SUMS'},'public SHA256SUMS membership/digests')
 return {'descriptor':descriptor,'identity':identity(st),'files':files,'directories':sorted(dirs),'closure_context':c,'closure_context_sha256':hashlib.sha256(selected[CONTEXT]).hexdigest(),'closure_raw':selected[CONTEXT]}

def prepare_payload(seed,context,selector,manifest_sha256,out):
 checked=scan_payload(seed,selector,manifest_sha256);closure(context,selector);out=Path(out);protected(out.parent);need(not os.path.lexists(out),'fresh public task output required')
 hashes={p:v['sha256'] for p,v in checked['files'].items() if p!='SHA256SUMS'};hashes[CONTEXT]=hashlib.sha256(context).hexdigest();sums=None;fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 sourcefd=os.open(seed['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(sourcefd,'rb') as src,os.fdopen(fd,'wb') as dest:
  need(identity(os.fstat(src.fileno()))==checked['identity'],'seed identity changed')
  with tarfile.open(fileobj=src,mode='r:') as old,tarfile.open(fileobj=dest,mode='w|',format=tarfile.USTAR_FORMAT) as new:
   for member in old:
    name=member.name.rstrip('/');ti=copy.copy(member)
    if member.isdir():new.addfile(ti);continue
    if name=='SHA256SUMS':
     table=old.extractfile(member).read(1048577);need(len(table)==member.size<=1048576,'seed checksum bound')
     sums=b''.join(hashes[line.decode('ascii').splitlines()[0].split('  ',1)[1]].encode()+line[64:] for line in table.splitlines(keepends=True))
    replacement=context if name==CONTEXT else sums if name=='SHA256SUMS' else None;ti.size=len(replacement) if replacement is not None else member.size
    new.addfile(ti,io.BytesIO(replacement) if replacement is not None else old.extractfile(member))
  padding=(-dest.tell())%1048576;dest.write(b'\0'*padding);dest.flush();os.fsync(dest.fileno());need(identity(os.fstat(src.fileno()))==checked['identity'],'seed changed during preparation')
 h=hashlib.sha256()
 with out.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 descriptor={'path':str(out),'bytes':out.stat().st_size,'sha256':h.hexdigest()};actual=scan_payload(descriptor,selector,manifest_sha256,context)
 need({p:v['sha256'] for p,v in actual['files'].items() if p!='SHA256SUMS'}==hashes,'prepared public members changed');return actual

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seed',required=True,help='public path/bytes/sha256 JSON descriptor');p.add_argument('--context',required=True);p.add_argument('--selector',required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--out',required=True);a=p.parse_args();need(Path(a.seed).stat().st_size<=65536 and Path(a.context).stat().st_size<=65536,'input JSON cap');seed=json.loads(Path(a.seed).read_bytes());raw=Path(a.context).read_bytes();need(len(raw)<=65536,'context cap');v=prepare_payload(seed,raw,a.selector,a.manifest_sha256,a.out);print(json.dumps({k:value for k,value in v.items() if k not in ('closure_raw','files','directories')},sort_keys=True))
if __name__=='__main__':main()
