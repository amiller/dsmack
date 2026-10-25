#!/usr/bin/env python3
"""Read-only preflight for setup.py. Reads GET /api/task only; downloads, installs, enrolls and signs nothing."""
import argparse,hashlib,json,platform,sys
from pathlib import Path
s=Path(__file__).with_name('setup.py');S={'__name__':'arcade_setup','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),S)
p=S['p'];ROOT_SHA=S['ROOT_SHA']

def check(rows,name,fn,fix=None):
    try:status,detail,fix=fn()
    except Exception as e:status,detail='fail',f'{type(e).__name__}: {e}'
    rows.append({'check':name,'status':status,'detail':detail,'fix':fix})

def host():
    mac=platform.mac_ver()[0];ok=platform.system()=='Darwin'and platform.machine()=='arm64'and mac and int(mac.split('.')[0])>=27
    return('ok'if ok else'fail',f'{platform.system()} {platform.machine()} macOS {mac or "n/a"}','use an Apple silicon Mac on macOS 27 or later')

def node(path):
    n,v=S['node_version'](path)
    return('ok'if v.startswith('v24.')else'fail',f'{n} {v[:40]}','install Node 24 in a directory owned by you or root and not group/world writable, then pass its absolute path to --node')

def paths(home,state):
    root=Path(home).expanduser();p['need'](root.is_absolute()and not root.exists(),f'{root} must not exist yet; choose a fresh --home')
    p['protected'](root.parent,True);d=S['state_directory'](root,state)
    return('ok',f'home {root}, state {d}',None)

def key(path):
    h=hashlib.sha256(p['read'](path,4096)).hexdigest()
    return('ok'if h==ROOT_SHA else'fail',f'sha256 {h}',f'obtain the maintainer public key with sha256 {ROOT_SHA} from a source other than the service')

def disk(home,assets):
    root=Path(home).expanduser();free,need=S['disk_need'](root,assets)
    return('ok'if free>=need else'fail',f'{free>>20} MiB free at {root.parent}; downloads plus 12 GiB reserve need {need>>20} MiB; expanded runtime and task disks need more (size not published before install)','free disk space on that volume')

def main():
    a=argparse.ArgumentParser();a.add_argument('--api');a.add_argument('--home',required=True);a.add_argument('--state-dir');a.add_argument('--node',required=True);a.add_argument('--public-key',required=True);a.add_argument('--allow-loopback',action='store_true');a.add_argument('--json',action='store_true');x=a.parse_args()
    rows=[];task=None
    check(rows,'host',host);check(rows,'python',lambda:('ok',sys.executable+' '+sys.version.split()[0],None))
    check(rows,'node',lambda:node(x.node),'pass the absolute path of an executable Node 24 owned by you or root, not group/world writable');check(rows,'paths',lambda:paths(x.home,x.state_dir),'pick a --home that does not exist, inside a directory owned by you and not group/world writable; if the socket path is too long add --state-dir /SHORT/FRESH/PATH');check(rows,'public_key',lambda:key(x.public_key),'save the maintainer public key as a private regular file (chmod 600)')
    if x.api:
        def fetch():
            nonlocal task;task=S['c']['API'](x.api,x.allow_loopback).request('GET','/api/task');r=task['runtime']
            p['need'](r['trust_key_sha256']==ROOT_SHA,'service publishes a runtime from a different release key')
            p['need']({d['name']for d in r['assets']}=={'inventory','signature','archive'}and len(r['assets'])==3,'unexpected runtime asset set')
            return('ok',f"key {r['key_id']} sequence {r['sequence']} profile {r['profile_id']} inventory {r['release_inventory_sha256']}",None)
        check(rows,'task_runtime',fetch,'check the --api origin; setup will refuse this runtime')
        if task:
            check(rows,'disk',lambda:disk(x.home,task['runtime']['assets']))
            rows.append({'check':'release_approval','status':'unknown','detail':'the service publishes the signed runtime identity but no approval status; ask the maintainer whether this sequence is approved','fix':None})
    else:rows.append({'check':'task_runtime','status':'unknown','detail':'no --api given; release, disk and task were not checked','fix':'rerun with --api https://PUBLISHED-PILOT-ORIGIN'})
    ok=all(r['status']!='fail'for r in rows)
    cmd=['python3','-I','setup.py','--api',x.api or'https://PUBLISHED-PILOT-ORIGIN','--home',x.home,'--node',x.node,'--public-key',x.public_key]+(['--state-dir',x.state_dir]if x.state_dir else[])+(['--allow-loopback']if x.allow_loopback else[])
    config=str(Path(x.home).expanduser()/'client.json')
    nxt=[' '.join(cmd),f'python3 -I client.py --config {config} authorization --purpose registration --payee 0xYOURADDRESS --out REG-AUTH.json']
    summary={k:task[k]for k in ('slug','repository','payout_wei','chain_id','contract','task_id')if k in task}if task else None
    if x.json:print(json.dumps({'ready':ok,'checks':rows,'task':summary,'next':nxt if ok else[]},indent=1))
    else:
        for r in rows:print(f"{r['status']:7} {r['check']}: {r['detail']}"+(f"\n        fix: {r['fix']}"if r['fix']and r['status']!='ok'else''))
        if summary:print('task: '+json.dumps(summary)+'\npayee: the 0x address you pass to authorization receives the testETH; it is fixed in the signed attempt and cannot be changed by the node that runs it')
        print('\nnext:\n  '+'\n  '.join(nxt)if ok else'\nfix the failed checks, then rerun doctor.py')
    raise SystemExit(0 if ok else 1)
if __name__=='__main__':main()
