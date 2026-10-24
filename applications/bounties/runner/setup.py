#!/usr/bin/env python3
"""Install a selected signed pilot runtime with local paths; never creates a VM/key."""
import argparse,hashlib,http.client,json,os,subprocess,sys,urllib.parse
from pathlib import Path
s=Path(__file__).with_name('client.py');c={'__name__':'arcade_client','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),c)
p=c['_scope'];need=p['need'];read=p['read'];pin=p['pin'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive'];protected=p['protected']
ROOT_SHA='4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df'

def download(d,path):
    need(type(d['bytes'])is int and 0<d['bytes']<=1<<30,'runtime download cap');url=d['url'];f=None
    try:
        for turn in range(4):
            u=urllib.parse.urlsplit(url);need(u.scheme=='https'and u.hostname in ('github.com','release-assets.githubusercontent.com')and not u.username and not u.password and not u.fragment and u.port in (None,443),'fixed HTTPS release hosts only')
            conn=http.client.HTTPSConnection(u.hostname,timeout=120)
            conn.request('GET',u.path+('?' +u.query if u.query else''),headers={'Accept-Encoding':'identity'});response=conn.getresponse()
            if response.status in (301,302,303,307,308):
                url=urllib.parse.urljoin(url,response.getheader('Location')or'');response.close();conn.close();continue
            need(response.status==200 and response.getheader('Content-Encoding')in(None,'identity'),'release download refused')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();n=0
            with os.fdopen(fd,'wb')as f:
                while True:
                    b=response.read(min(4<<20,d['bytes']+1-n))
                    if not b:break
                    n+=len(b);need(n<=d['bytes'],'release bytes cap');h.update(b);f.write(b)
                f.flush();os.fsync(f.fileno())
            response.close();conn.close();need(n==d['bytes']and h.hexdigest()==d['sha256'],'release digest mismatch');return
        raise ValueError('too many release redirects')
    finally:
        if f is not None and not f.closed:f.close()

def state_directory(root,override=None):
    state=Path(override).expanduser()if override else root/'s'
    need(state.is_absolute()and '..'not in state.parts and state!=root and not state.exists(),'fresh absolute state directory required')
    # Use the SAME helper/socket suffix as actual task materialization. This
    # must run before any request, download or installer creates partial state.
    p['task_directory'](state,'0'*32)
    if state.parent!=root:protected(state.parent,True)
    return state

def main():
    a=argparse.ArgumentParser();a.add_argument('--api',required=True);a.add_argument('--home',required=True);a.add_argument('--state-dir');a.add_argument('--node',required=True);a.add_argument('--public-key',required=True);a.add_argument('--allow-loopback',action='store_true');x=a.parse_args();need(sys.flags.isolated,'isolated Python required')
    root=Path(x.home).expanduser();need(root.is_absolute()and not root.exists(),'fresh local installation destination; never overwrite partial state');protected(root.parent,True)
    state=state_directory(root,x.state_dir)
    public=read(x.public_key,4096);need(hashlib.sha256(public).hexdigest()==ROOT_SHA,'independently selected maintainer key fingerprint required')
    api=c['API'](x.api,x.allow_loopback);task=api.request('GET','/api/task');runtime=task['runtime'];need(runtime['trust_key_sha256']==ROOT_SHA,'unexpected release authority')
    rows=runtime['assets'];need(type(rows)is list and len(rows)==3 and {d['name']for d in rows}=={'inventory','signature','archive'},'closed signed runtime asset set')
    root.mkdir(mode=0o700);exclusive(root/'root-public.pem',public);exclusive(root/'public-task.json',canonical(task));downloads=root/'downloads';downloads.mkdir(mode=0o700)
    for d in rows:download(d,downloads/d['name'])
    need(pin(downloads/'inventory')['sha256']==runtime['release_inventory_sha256'],'selected task/runtime identity')
    bootstrap_source=Path(__file__).parents[2]/'pilot-client/alpha-bootstrap.mjs';node=protected(x.node);need(os.access(node,os.X_OK),'trusted Node24 prerequisite')
    # Existing bootstrap inspects the actual Node/runtime dependencies and refuses
    # injection. It downloads or installs no Node interpreter.
    subprocess.run([str(node),str(bootstrap_source),'--trust-key',str(root/'root-public.pem'),'--key-id',runtime['key_id'],'--channel','alpha','--min-sequence',str(runtime['sequence']),'--out',str(root/'bootstrap')],check=True,timeout=120,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    installer=root/'bootstrap/alpha_stage.py';need(pin(installer)['sha256']==p['INSTALLER'],'selected installer source')
    subprocess.run([sys.executable,'-I','-B',str(installer),'--bootstrap',str(root/'bootstrap/bootstrap.json'),'--inventory',str(downloads/'inventory'),'--signature',str(downloads/'signature'),'--archive',str(downloads/'archive'),'--target',str(root/'runtime')],check=True,timeout=600,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    state.mkdir(mode=0o700)
    config={'api_url':x.api,'state_dir':str(state),'install_root':str(root/'runtime'),'profile_id':runtime['profile_id'],'bootstrap':str(root/'bootstrap/bootstrap.json'),'inventory':str(downloads/'inventory'),'signature':str(downloads/'signature'),'app_policy_sha256':task['app_policy_sha256']}
    exclusive(root/'client.json',canonical(config));print(json.dumps({'installed':True,'client_config':str(root/'client.json'),'vm_launched':False,'credentials_imported':False,'key_created':False}))
if __name__=='__main__':main()
