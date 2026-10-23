"""Application-only full-source development. No provider credential import.

This module executes only inside the pinned workload container. Its output is
an observation and candidate delivery; independent review decides acceptance.
"""
import ctypes,io,json,os,signal,stat,tarfile,time
from pathlib import Path
import source_bundle as source
from audit_stage import regular,SLOTS
p=source.protocol
need=p.require
sha=source.sha
MODEL='claude-opus-4-8'
SECONDS=480
TURNS=30
TOOLS='Read,Write,Edit,Glob,Grep,Bash'
MAX_SOURCE=8*1024*1024


def audit(paths,request_sha,profile_sha,driver_sha,plan_sha):
    p.keys(paths,SLOTS,'semantic paths');need(paths['suite'] is None,'develop has no suite')
    raw={k:regular(v,MAX_SOURCE if k=='source_bundle' else 4*1024*1024)for k,v in paths.items()if v is not None}
    r=p.parse_json(raw['request']);p.validate_request(r)
    need(r['run_role']=='develop' and r['candidate'] is None,'typed develop request')
    need(raw['request']==p.canonical_json(r),'canonical request')
    digest=sha(r['schema'].encode()+b'\0'+raw['request']);need(digest==request_sha,'fixed request')
    for n,h in [('stage_profile',profile_sha),('driver',driver_sha),('plan',plan_sha)]:need(sha(raw[n])==h,'fixed '+n)
    need(sha(raw['task_terms'])==r['task_terms_sha256']and sha(raw['acceptance_profile'])==r['acceptance_profile_sha256'],'task/profile binding')
    profile=p.parse_json(raw['stage_profile']);p.keys(profile,('schema','model','seconds','turns','tools','specification'),'develop profile')
    need(profile['schema']=='dsmack-bounty-develop-profile/1'and profile['model']==MODEL and type(profile['seconds'])is int and profile['seconds']==SECONDS and type(profile['turns'])is int and profile['turns']==TURNS and profile['tools']==TOOLS,'fixed develop policy')
    spec=profile['specification'];p.keys(spec,('text','sha256'),'specification');need(isinstance(spec['text'],str)and 0<len(spec['text'].encode())<=65536 and sha(spec['text'].encode())==spec['sha256'],'specification digest')
    manifest,files=source.decode_source(raw['source_bundle'],raw['source_manifest'],r['base']['tree_manifest_sha256'])
    for name in files:need(not any(x in('.git','.claude','.mcp.json','.claude.json')for x in Path(name).parts),'repository configuration/history refused')
    return {'role':'develop','request':r,'request_sha256':digest,'source_tree_sha256':r['base']['tree_manifest_sha256'],'input_bytes':raw,'manifest':manifest,'files':files,'specification':spec['text']}


def materialize(result,root):
    root=Path(root);root.mkdir(mode=0o755,exist_ok=False)
    for row in result['manifest']:
        target=root/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb')as f:f.write(result['files'][row['path']])
        target.chmod(row['mode'])
    need(p.scan_tree(root,MAX_SOURCE)==result['manifest'],'full base projection')
    return {row['path']:{'mode':row['mode'],'bytes':row['bytes'],'sha256':row['sha256']}for row in result['manifest']}


def command(cli,prompt):
    need(len(prompt.encode())<=98304,'prompt byte bound')
    return [str(cli),'--print',prompt,'--verbose','--output-format','stream-json','--model',MODEL,'--max-turns',str(TURNS),'--tools',TOOLS,'--allowedTools',TOOLS,'--strict-mcp-config','--mcp-config','{"mcpServers":{}}','--setting-sources','user','--settings','{"disableAllHooks":true}','--disable-slash-commands','--no-session-persistence']


def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'duplicate stream member');result[k]=v
    return result

def observe(raw):
    events=[]
    for line in raw.splitlines():
        need(len(line)<=1048576,'event byte bound');v=json.loads(line,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite stream JSON')));need(isinstance(v,dict),'event object');events.append(v)
    need(0<len(events)<=4096,'event count')
    init=[e.get('model')for e in events if e.get('type')=='system'and e.get('subtype')=='init'];need(init==[MODEL],'exact init model')
    models=[];tools=[]
    for e in events:
        if e.get('type')=='assistant':
            msg=e.get('message',{});need(msg.get('model')==MODEL,'exact assistant model');models.append(msg['model'])
            content=msg.get('content');need(isinstance(content,list),'assistant content')
            for block in content:
                need(isinstance(block,dict),'assistant block')
                if block.get('type')=='tool_use':need(block.get('name')in TOOLS.split(','),'tool outside fixed policy');tools.append(block['name'])
    results=[e for e in events if e.get('type')=='result'];need(models and len(results)==1 and events[-1]is results[0],'final result')
    r=results[0];need(r.get('subtype')=='success'and r.get('is_error')is False,'CLI outcome not completed')
    need(type(r.get('num_turns'))is int and 1<=r['num_turns']<=TURNS,'turn budget')
    usage=r.get('modelUsage');need(isinstance(usage,dict)and set(usage)=={MODEL},'exact result model usage')
    return {'schema':'dsmack-bounty-develop-model-observation/1','requested_model':MODEL,'init_model':MODEL,'assistant_models':sorted(set(models)),'result_models':sorted(usage),'turns':r['num_turns'],'tools':sorted(set(tools))}


def protect_parent():
    need(os.getpid()==1 and os.getuid()==1000,'parent protection requires private UID1000 PID1')
    libc=ctypes.CDLL(None,use_errno=True);prctl=libc.prctl
    prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    prctl.restype=ctypes.c_int
    need(prctl(4,0,0,0,0)==0 and prctl(3,0,0,0,0)==0,'trusted parent must be nondumpable')


def namespace_members(proc=Path('/proc'),self_pid=None,uid=None):
    """Linux private workload PID namespace only; unknown live identity refuses."""
    self_pid=os.getpid()if self_pid is None else self_pid;uid=os.getuid()if uid is None else uid
    result=[]
    for path in proc.iterdir():
        if not path.name.isdecimal()or int(path.name)==self_pid:continue
        try:
            text=(path/'status').read_text();fields={x.split(':',1)[0]:x.split(':',1)[1].strip()for x in text.splitlines()if':'in x}
            owner=int(fields['Uid'].split()[0]);state=fields['State'].split()[0]
        except FileNotFoundError:continue
        need(owner==uid,'foreign UID in private workload PID namespace')
        if state not in('Z','X'):result.append(int(path.name))
    return result


def quiesce(seconds=5):
    need(os.getpid()==1 and os.getuid()==1000,'capture owner must be UID1000 PID1 in private container')
    end=time.monotonic()+seconds
    while True:
        members=namespace_members()
        if not members:break
        for pid in members:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        if time.monotonic()>=end:raise ValueError('private namespace writers remain; no capture')
        time.sleep(.02)
    while True:
        try:
            pid,_=os.waitpid(-1,os.WNOHANG)
            if pid==0:break
        except ChildProcessError:break
    need(not namespace_members(),'namespace changed before capture')


def capture(root,baseline):
    """Called only after private namespace quiescence; rescan guards mutations."""
    root=Path(root);manifest=p.scan_tree(root,MAX_SOURCE);files={row['path']:regular(root/row['path'],MAX_SOURCE)for row in manifest}
    relation=source.admission_relation(baseline['manifest'],baseline['files'],manifest,files)
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT)as tar:
        for row in manifest:
            entry=tarfile.TarInfo(row['path']);entry.mode=row['mode'];entry.size=row['bytes'];entry.mtime=0;entry.uid=entry.gid=0;tar.addfile(entry,io.BytesIO(files[row['path']]))
    encoded=buf.getvalue();length=1024+sum(512+((row['bytes']+511)//512)*512 for row in manifest)
    need(encoded[length:]==bytes(len(encoded)-length),'unexpected USTAR extension')
    raw=encoded[:length];need(len(raw)<=MAX_SOURCE,'candidate archive cap')
    need(source.decode_source(raw,p.canonical_json(manifest),p.tree_digest(manifest))==(manifest,files),'captured tree/bundle agreement')
    need(p.scan_tree(root,MAX_SOURCE)==manifest,'candidate changed across capture')
    return raw,p.canonical_json(manifest),relation
