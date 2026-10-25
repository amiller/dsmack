#!/usr/bin/env python3
"""Read-only preflight for setup.py. Reads GET /api/task and authenticates the small signed
inventory+signature in a temporary directory; never fetches the archive or keeps install state."""
import argparse,hashlib,json,platform,shlex,sys,tempfile
from pathlib import Path
if sys.version_info<(3,9):raise SystemExit('Python 3.9 or later required (pathlib is_relative_to); found '+sys.version.split()[0])
s=Path(__file__).with_name('setup.py');S={'__name__':'arcade_setup','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),S)
p=S['p'];ROOT_SHA=S['ROOT_SHA']

def check(rows,name,fn,fix=None):
    try:status,detail,fix=fn()
    except Exception as e:status,detail='fail',f'{type(e).__name__}: {e}'
    rows.append({'check':name,'status':status,'detail':detail,'fix':fix})

def version(v):return tuple(int(x)for x in v.split('.'))

def host(minimum='27.0'):
    mac=platform.mac_ver()[0];ok=platform.system()=='Darwin'and platform.machine()=='arm64'and bool(mac)and version(mac)>=version(minimum)
    return('ok'if ok else'fail',f'{platform.system()} {platform.machine()} macOS {mac or "n/a"}; release requires darwin arm64 macOS {minimum}+',f'use an Apple silicon Mac on macOS {minimum} or later')

def node(path):
    n,v=S['node_version'](path)
    return('ok'if v.startswith('v24.')else'fail',f"{n} {v.split(chr(10))[0][:40]}",'install Node 24 and pass its absolute path to --node')

def paths(home,state):
    root=Path(home).expanduser();p['need'](root.is_absolute()and not root.exists(),f'{root} must not exist yet; choose a fresh --home')
    p['protected'](root.parent,True);d=S['state_directory'](root,state)
    return('ok',f'home {root}, state {d}',None)

def key(path):
    h=hashlib.sha256(p['read'](path,4096)).hexdigest()
    return('ok'if h==ROOT_SHA else'fail',f'sha256 {h}',f"curl -fLo release-public.pem {S['KEY_URL']} && chmod 600 release-public.pem && shasum -a 256 release-public.pem  # must print {ROOT_SHA}")

def release(node,key,runtime,home,fetch=None):
    with tempfile.TemporaryDirectory(dir=Path(home).expanduser().parent)as t:v=S['release_metadata'](node,p['protected'](key),runtime,Path(t),fetch)
    return v,('ok',f"{v['release_id']} sequence {v['sequence']} signed by {v['key_id']}, expires {v['expires_at']}, Developer ID category {v['app']['attestation_category']}, {len(v['files'])} files",None)

def disk(home,state,inventory):
    root=Path(home).expanduser();rows=S['disk_need'](root,S['state_directory'](root,state),inventory);short=[r for r in rows if r[1]<r[2]]
    what='expanded runtime + archive + 12 GiB working reserve'if len(rows)==1 else'expanded runtime + archive on the --home volume, 12 GiB working reserve on the --state-dir volume'
    return('fail'if short else'ok','; '.join(f'{free>>20} MiB free at {v}, need {need>>20} MiB'for v,free,need in rows)+f' ({what})','free disk space on the volume that is short, or choose a --home/--state-dir on a larger volume')

def next_commands(x):
    home=Path(x.home).expanduser();cmd=['python3','-I','setup.py','--api',x.api,'--home',x.home,'--node',x.node,'--public-key',x.public_key]+(['--state-dir',x.state_dir]if x.state_dir else[])+(['--allow-loopback']if x.allow_loopback else[])
    return[shlex.join(cmd),shlex.join(['python3','-I','client.py','--config',str(home/'client.json'),'authorization','--purpose','registration','--payee','0xYOURADDRESS','--out',str(home/'REG-AUTH.json')])]

def main():
    a=argparse.ArgumentParser();a.add_argument('--api',required=True);a.add_argument('--home',required=True);a.add_argument('--state-dir');a.add_argument('--node',required=True);a.add_argument('--public-key',required=True);a.add_argument('--allow-loopback',action='store_true');a.add_argument('--json',action='store_true');x=a.parse_args()
    rows=[];task=inventory=None
    check(rows,'python',lambda:('ok',sys.executable+' '+sys.version.split()[0]+' (3.9+ required)',None))
    check(rows,'node',lambda:node(x.node),"pass the resolved absolute path of an executable Node 24 (not a symlink), owned by you or root in directories that are not group/world writable; print it with: python3 -c 'import os,shutil;print(os.path.realpath(shutil.which(\"node\")))'")
    check(rows,'paths',lambda:paths(x.home,x.state_dir),'pick a --home that does not exist, inside a directory owned by you and not group/world writable; if the socket path is too long add --state-dir /SHORT/FRESH/PATH')
    check(rows,'public_key',lambda:key(x.public_key),'save the maintainer public key as a private regular file (chmod 600)')
    def fetch():
        nonlocal task;task=S['c']['API'](x.api,x.allow_loopback).request('GET','/api/task');r=task['runtime']
        p['need'](r['trust_key_sha256']==ROOT_SHA,'service publishes a runtime from a different release key')
        p['need']({d['name']for d in r['assets']}=={'inventory','signature','archive'}and len(r['assets'])==3,'unexpected runtime asset set')
        return('ok',f"status {r.get('status')!r}, sequence {r['sequence']}, inventory {r['release_inventory_sha256']}",None)
    check(rows,'task_runtime',fetch,'check the --api origin; setup will refuse this runtime')
    if task and all(r['status']=='ok'for r in rows if r['check']in('node','public_key','paths','task_runtime')):
        def signed():
            nonlocal inventory;inventory,row=release(x.node,x.public_key,task['runtime'],x.home);return row
        check(rows,'release',signed,'setup will refuse this release; report the error to the maintainer')
    else:rows.append({'check':'release','status':'fail','detail':'not checked: node, public_key, paths and task_runtime must pass first','fix':None})
    check(rows,'host',lambda:host(inventory['platform']['minimum_version']if inventory else'27.0'))
    if inventory:check(rows,'disk',lambda:disk(x.home,x.state_dir,inventory))
    ok=all(r['status']=='ok'for r in rows)
    nxt=next_commands(x)
    summary={k:task[k]for k in ('slug','repository','payout_wei','chain_id','contract','task_id')if k in task}if task else None
    if x.json:print(json.dumps({'ready':ok,'checks':rows,'task':summary,'next':nxt if ok else[]},indent=1))
    else:
        for r in rows:print(f"{r['status']:4} {r['check']}: {r['detail']}"+(f"\n     fix: {r['fix']}"if r['fix']and r['status']!='ok'else''))
        if summary:print('task: '+json.dumps(summary)+'\npayee: the 0x address you pass to authorization receives the testETH; it is fixed in the signed attempt and cannot be changed by the node that runs it')
        print('\nnext:\n  '+'\n  '.join(nxt)if ok else'\nfix the failed checks, then rerun doctor.py')
    raise SystemExit(0 if ok else 1)
if __name__=='__main__':main()
