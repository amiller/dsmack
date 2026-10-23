"""Local coordinator policy input, not signed evidence or new cryptography.
The coordinator supplies this file from a final independently approved join.
Every public pin is checked before launch; private input is never inventoried.
"""
import hashlib,json,os,re,stat,plistlib
from pathlib import Path
PUBLIC = ('policy_path','image_manifest_path','checksum_manifest_path','metadata_path','admission_path','compose_manifest_path','workload_disk_path','scratch_template_path','result_template_path')
class Refused(ValueError): pass
def need(ok,msg):
    if not ok: raise Refused(msg)
def exact(obj,keys): need(isinstance(obj,dict) and set(obj)==set(keys),'exact keys: '+','.join(keys))
def load(path):
    def pairs(items):
        obj={}
        for k,v in items:
            need(k not in obj,'duplicate JSON key');obj[k]=v
        return obj
    with open(path,'rb') as f: raw=f.read(2**20+1)
    need(len(raw)<=2**20,'policy JSON too large')
    return json.loads(raw,object_pairs_hook=pairs)
def pin(p):
    exact(p,('path','bytes','sha256'))
    need(isinstance(p['path'],str) and os.path.isabs(p['path']),'absolute public path required')
    need(type(p['bytes']) is int and p['bytes']>=0,'public size')
    need(isinstance(p['sha256'],str) and re.fullmatch('[0-9a-f]{64}',p['sha256']),'public digest')
    fd=os.open(p['path'],os.O_RDONLY|os.O_NOFOLLOW)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode),'regular public file required')
        h=hashlib.sha256();n=0
        while True:
            b=os.read(fd,1<<20)
            if not b: break
            h.update(b);n+=len(b)
        need(n==p['bytes'] and h.hexdigest()==p['sha256'],'changed public pin: '+p['path'])
    finally: os.close(fd)
    return p['path']
def inventory(rec):
    exact(rec,('gate','files'))
    need(isinstance(rec['files'],list) and rec['files'],'empty source inventory')
    # Validate all record shapes before opening any listed source.
    for p in rec['files']: exact(p,('path','bytes','sha256'))
    need(len({p['path'] for p in rec['files']})==len(rec['files']),'duplicate source path')
    gate=load(pin(rec['gate']))
    exact(gate,('schema','approved','inventory_sha256'))
    need(type(gate['approved']) is bool and gate['approved'], 'source approval must be boolean true')
    wire=json.dumps(rec['files'],sort_keys=True,separators=(',',':')).encode()
    need(gate=={'schema':'dsmack-source-gate/1','approved':True,'inventory_sha256':hashlib.sha256(wire).hexdigest()},'source gate pending/rejected/mismatched')
    for p in rec['files']: pin(p)
def validate(h,spec=None):
    exact(h,('schema','status','final_gate','spec','inputs','resources','sources','app','helper','closure_context','checker_context','cross'))
    need(h['schema']=='dsmack-coordinator-approved-run/1' and h['status']=='approved','coordinator handoff pending')
    need(isinstance(h['inputs'],dict) and set(h['inputs'])==set(PUBLIC),'complete public inputs only; private keys forbidden')
    s=h['spec'];need(isinstance(s,dict),'spec required')
    need(set(s)==set(PUBLIC)|{'profile','workload_id','runtime_seconds','private_input_path','net_socket_path'},'exact spec keys')
    if spec is not None: need(spec==s,'spec differs from admitted handoff')
    for key,p in h['inputs'].items():
        exact(p,('path','bytes','sha256'));need(p['path']==s[key],'input path mismatch')
    exact(h['resources'],('profile','mem_mib','vcpus','scratch_bytes','result_bytes','network'))
    r=h['resources'];need(r['profile']==s['profile'] and r['mem_mib']==4096 and type(r['mem_mib']) is int and type(r['vcpus']) is int and r['vcpus']==1,'measured resource profile mismatch')
    need(r['network'] in ('mini-gvproxy-192.168.127','offline'),'Mini network profile required')
    need(bool(s['net_socket_path'])==(r['network']!='offline'),'network socket/profile mismatch')
    for k in ('scratch','result'):
        n=r[k+'_bytes'];need(type(n) is int and 0<n<=1<<30 and n%512==0 and n==h['inputs'][k+'_template_path']['bytes'],'template resource mismatch')
    need(isinstance(h['sources'],dict) and set(h['sources'])=={'native','swift','guest','image','operator','cross','auxiliary'},'complete source gates required')
    gate=load(pin(h['final_gate']))
    exact(gate,('schema','approved','handoff_sha256'))
    need(type(gate['approved']) is bool and gate['approved'], 'final approval must be boolean true')
    source_wire=json.dumps({k:v for k,v in h.items() if k!='final_gate'},sort_keys=True,separators=(',',':')).encode()
    need(gate=={'schema':'dsmack-final-join-gate/1','approved':True,'handoff_sha256':hashlib.sha256(source_wire).hexdigest()},'final independent join gate pending/rejected/mismatched')
    for rec in h['sources'].values(): inventory(rec)
    for p in h['inputs'].values(): pin(p)
    manifest=load(s['image_manifest_path'])
    declared=manifest.get('resource_profiles',{}).get(s['profile'],{})
    need(type(declared.get('mem_mib')) is int and type(declared.get('vcpus')) is int and declared.get('mem_mib')==r['mem_mib'] and declared.get('vcpus')==r['vcpus'] and manifest.get('arch')=='aarch64','actual image resource profile mismatch')
    for role in ('kernel','initrd','system_disk'):
        item=manifest.get(role,{})
        pin({k:item[k] for k in ('path','bytes','sha256')})
    policy=load(s['policy_path']);limits=policy.get('resource_limits',{})
    need(type(limits.get('max_mem_mib')) is int and limits['max_mem_mib']>=r['mem_mib'] and type(limits.get('max_vcpus')) is int and limits['max_vcpus']>=r['vcpus'] and type(limits.get('max_runtime_seconds')) is int and type(s['runtime_seconds']) is int and 1<=s['runtime_seconds']<=limits['max_runtime_seconds'],'actual admission resource budget mismatch')
    # Actual Swift still enforces complete policy/admission/manifest semantics.
    exact(h['app'],('bundle_path','executable','full_cdhash','team_id','bundle_id'))
    need(os.path.isabs(h['app']['bundle_path']),'absolute app bundle')
    need(h['app']['bundle_id']=='dev.dsmack.provider' and h['app']['team_id']=='DC9JH5DRMY','app identity')
    need(re.fullmatch('[0-9a-f]{64}',h['app']['full_cdhash'] or '') is not None,'full CDHash required')
    info_path=str(Path(h['app']['bundle_path'])/'Contents/Info.plist')
    infos=[p for p in h['sources']['swift']['files'] if p['path']==info_path]
    need(len(infos)==1,'Info.plist absent from approved Swift inventory')
    # Selection metadata is approved public input, just like executable bytes.
    pin(infos[0])
    with open(info_path,'rb') as f: raw=f.read(2**20+1)
    need(len(raw)<=2**20,'Info.plist too large')
    try: info=plistlib.loads(raw)
    except Exception as exc: raise Refused('invalid Info.plist') from exc
    need(isinstance(info,dict),'Info.plist dictionary required')
    name=info.get('CFBundleExecutable')
    need(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}',name) is not None,'invalid CFBundleExecutable')
    need(info.get('CFBundleIdentifier')==h['app']['bundle_id'],'Info.plist bundle identity mismatch')
    need(h['app']['executable']['path']==str(Path(h['app']['bundle_path'])/'Contents/MacOS'/name),'app executable path')
    pin(h['app']['executable'])
    from closure_context import validate_context_bytes
    raw=Path(pin(h['closure_context'])).read_bytes();validate_context_bytes(raw)
    ctx=load(pin(h['checker_context']))
    expected=ctx.get('expected',{}).get('closure_context',{})
    need(expected==json.loads(raw),'independent closure context mismatch')
    exact(h['cross'],('root','transfer'))
    need(os.path.isabs(h['cross']['root']),'absolute cross root')
    need(h['cross']['transfer']['path']==str(Path(h['cross']['root'])/'tools/evidence_transfer.py'),'cross transfer path mismatch')
    pin(h['cross']['transfer'])
    for role,artifact in [('cross',h['cross']['transfer']),('swift',h['app']['executable'])]:
        need(artifact in h['sources'][role]['files'],'artifact absent from approved source inventory')
    if h['helper'] is not None:
        exact(h['helper'],('interface','launcher','gvproxy','run_dir'))
        need(h['helper']['interface']=='gvproxy-launcher/external-client-stdin-stop/1','native helper interface')
        for artifact in (h['helper']['launcher'],h['helper']['gvproxy']):
            pin(artifact)
            need(artifact in h['sources']['native']['files'],'helper absent from approved inventory')
        need(s['net_socket_path']==str(Path(h['helper']['run_dir'])/'net.sock'),'helper socket mismatch')
    need(bool(h['helper'])==bool(s['net_socket_path']),'helper/profile mismatch')
    return h
