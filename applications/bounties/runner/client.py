#!/usr/bin/env python3
"""Public arcade client. Wallet signatures are supplied by a wallet, never private keys."""
import argparse,base64,hashlib,http.client,importlib.util,json,os,re,secrets,socket,sys,time,urllib.parse
from pathlib import Path
# Load reviewed sibling source directly; -I does not add the script directory.
_source=Path(__file__).with_name('portable.py');_scope={'__file__':str(_source),'__name__':'arcade_portable'}
exec(compile(_source.read_bytes(),str(_source),'exec'),_scope)
need=_scope['need'];read=_scope['read'];doc=_scope['document'];canonical=_scope['canonical'];exclusive=_scope['exclusive'];protected=_scope['protected']

def request_connection(url,method,path,body=None,headers=None):
    """Retry only DNS resolution failure from request, before socket writes.

    Responses, TLS failures and disconnects are never replayed here. Every
    attempt gets a fresh connection with the exact already-selected payload.
    """
    for turn in range(6):
        c=(http.client.HTTPSConnection if url.scheme=='https' else http.client.HTTPConnection)(url.hostname,url.port,timeout=120)
        try:c.request(method,path,body,headers=headers)
        except socket.gaierror:
            c.close()
            if turn==5:raise
            time.sleep(5)
        except BaseException:
            c.close();raise
        else:return c

class API:
    def __init__(self,url,allow_loopback=False):
        self.url=urllib.parse.urlsplit(url);u=self.url
        need(not u.username and not u.password and not u.query and not u.fragment and re.fullmatch(r'(?:/[A-Za-z0-9_-]+)*/?',u.path)is not None,'API must be a protected origin with a simple optional prefix')
        need(u.scheme=='https' or (allow_loopback and u.scheme=='http' and u.hostname in ('127.0.0.1','::1')),'HTTPS required; explicit loopback development only')
        self.prefix=u.path.rstrip('/');self.resume_download=False
    def request(self,method,path,body=None,capability=None,headers=None,raw=False):
        need(path.startswith('/api/') and not any(x in path for x in ('?','#','..')),'closed API path')
        h=dict(headers or {});h['Accept']='application/json'
        if capability is not None:
            need(re.fullmatch('[A-Za-z0-9_-]{43}',capability),'invalid capability');h['Authorization']='Bearer '+capability
        if body is not None and not raw:body=canonical(body);h['Content-Type']='application/json'
        if body is not None:h['Content-Length']=str(len(body))
        c=request_connection(self.url,method,self.prefix+path,body,h)
        try:
            r=c.getresponse();b=r.read((1<<20)+1)
            need(len(b)<=1<<20 and 200<=r.status<300,'API refused request; retained state permits explicit reconciliation')
            return doc(b) if b else {}
        finally:c.close()
    def fetch(self,d,path,capability=None):
        u=urllib.parse.urlsplit(d['url']);need((u.scheme,u.netloc)==(self.url.scheme,self.url.netloc) and not u.query and not u.fragment and not u.username and '..' not in u.path and u.path.startswith(self.prefix+'/api/'),'same-origin artifact URL required')
        existing=Path(path).exists()
        if existing:
            need(self.resume_download,'existing download requires explicit reconciliation');p=protected(path);st=p.stat()
            need(st.st_uid==os.getuid() and not st.st_mode&0o077 and st.st_size<=d['bytes'],'unprotected partial download')
        fd=os.open(path,(os.O_RDWR if existing else os.O_WRONLY|os.O_CREAT|os.O_EXCL)|os.O_NOFOLLOW,0o600)
        try:
            if existing:
                held=os.fstat(fd);need((held.st_dev,held.st_ino,held.st_size,held.st_mtime_ns,held.st_ctime_ns)==(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns),'partial changed before open')
            n=0;digest=hashlib.sha256()
            with os.fdopen(fd,'r+b' if existing else 'wb',closefd=False) as f:
                if existing:
                    while True:
                        prefix=f.read(4<<20)
                        if not prefix:break
                        digest.update(prefix);n+=len(prefix)
                    after=os.fstat(fd);need(n==held.st_size and (after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(held.st_size,held.st_mtime_ns,held.st_ctime_ns),'partial changed while hashing')
                while n<d['bytes']:
                    end=min(n+(4<<20),d['bytes'])-1
                    headers={'Range':f'bytes={n}-{end}'}
                    if capability is not None:headers['Authorization']='Bearer '+capability
                    c=request_connection(u,'GET',u.path,headers=headers)
                    try:
                        r=c.getresponse()
                        need(r.status==206 and r.getheader('Content-Encoding') in (None,'identity'),'bounded artifact response refused')
                        need(r.getheader('Content-Length')==str(end-n+1),'bounded artifact length refused')
                        content_range=r.getheader('Content-Range')
                        need(content_range in (None,f'bytes {n}-{end}/{d["bytes"]}'),'artifact range mismatch')
                        chunk=r.read(end-n+2);need(len(chunk)==end-n+1,'artifact range truncated or exceeded')
                        f.write(chunk);digest.update(chunk);n+=len(chunk)
                    finally:c.close()
                f.flush();os.fsync(fd)
            need(n==d['bytes'] and digest.hexdigest()==d['sha256'],'artifact digest mismatch')
        finally:os.close(fd)

def state(path):
    p=protected(path);need(p.stat().st_uid==os.getuid() and not p.stat().st_mode&0o077,'private client state required');return doc(read(p))

def upload(api,attempt,capability,out,request_id):
    observed=api.request('GET',f'/api/attempts/{attempt}')
    if observed.get('submission_id') and observed.get('state')in ('verifying','verified','failed','verification_error'):
        return {'evidence_submitted':True,'state':observed['state'],'attempt_id':attempt}
    rows=_scope['evidence_manifest'](out)
    start=api.request('POST',f'/api/attempts/{attempt}/evidence',{'request_id':request_id,'files':rows},capability)
    sid=start['submission_id'];chunk=start['chunk_bytes'];need(re.fullmatch('[a-f0-9]{32}',sid) and chunk==4194304,'unsupported submission protocol')
    offsets={d['name']:d['received'] for d in start['files']};need(set(offsets)=={d['name']for d in rows},'submission offset membership')
    for d in rows:
        path=Path(out)/d['name'];before=_scope['pin'](path,_scope['ORIGINALS'][d['name']]);offset=offsets[d['name']];need(type(offset)is int and 0<=offset<=d['bytes'],'invalid stored upload offset')
        with path.open('rb') as f:
            f.seek(offset)
            while offset<d['bytes']:
                b=f.read(min(chunk,d['bytes']-offset));need(b,'truncated evidence')
                api.request('PUT',f'/api/attempts/{attempt}/evidence/{sid}/{d["name"]}',b,capability,{'Content-Type':'application/octet-stream','Content-Range':f'bytes {offset}-{offset+len(b)-1}/{d["bytes"]}'},True);offset+=len(b)
        need(_scope['pin'](path,_scope['ORIGINALS'][d['name']])==before,'original evidence changed')
    return api.request('POST',f'/api/attempts/{attempt}/evidence/{sid}/complete',{'request_id':request_id},capability)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--allow-loopback',action='store_true')
    sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('authorization');a.add_argument('--purpose',choices=('attempt','registration'),required=True);a.add_argument('--payee',required=True);a.add_argument('--candidate-commit');a.add_argument('--out',required=True)
    for name in ('attempt','register'):
        a=sub.add_parser(name);a.add_argument('--authorization',required=True);a.add_argument('--wallet-signature',required=True);a.add_argument('--out',required=True)
    for name in ('prepare','check','run','resume','submit','status','cleanup'):
        a=sub.add_parser(name);a.add_argument('--attempt',required=True)
        if name=='prepare':a.add_argument('--registration');a.add_argument('--mode',choices=('self','best_effort'),default='self');a.add_argument('--resume-download',action='store_true')
    x=p.parse_args();need(sys.flags.isolated,'invoke Python with -I');cfg=state(x.config);api=API(cfg['api_url'],x.allow_loopback);parent=protected(cfg['state_dir'],True)
    if x.command=='authorization':
        request_id=secrets.token_hex(32);payload={'purpose':x.purpose,'payee':x.payee.lower(),'request_id':request_id,'candidate_commit':None}
        if x.candidate_commit:need(re.fullmatch('[0-9a-f]{40}',x.candidate_commit),'full candidate commit required');payload['candidate_commit']=x.candidate_commit
        result=api.request('POST','/api/authorization-challenges',payload);exclusive(Path(x.out),canonical({'request':payload,'challenge':result}));print(json.dumps(result));return
    if x.command in ('attempt','register'):
        authorization=state(x.authorization);a=authorization['request'];challenge=authorization['challenge'];need(a['purpose']==('attempt' if x.command=='attempt' else 'registration'),'authorization purpose mismatch')
        signature=read(x.wallet_signature,4096).decode().strip();need(re.fullmatch('0x[0-9a-fA-F]{130}',signature),'wallet signature only; never private keys')
        intent=Path(x.out+'.intent.json')
        if intent.exists():v=state(intent);need(v['authorization']==authorization and v['signature']==signature,'conflicting explicit retry')
        else:
            v={'authorization':authorization,'signature':signature,'capability':secrets.token_urlsafe(32)};exclusive(intent,canonical(v))
        common={'request_id':a['request_id'],'payee':a['payee'],'authorization_id':challenge['authorization_id'],'wallet_authorization':{'signature':signature}}
        if x.command=='attempt':
            response=api.request('POST','/api/attempts',{**common,'candidate_commit':a['candidate_commit'],'capability':v['capability']});exclusive(Path(x.out),canonical({'response':response,'capability':v['capability']}));print(json.dumps({'registered':True,'state_file':x.out}));return
        regpath=Path(x.out+'.registration.json');evpath=Path(x.out+'.attestation.json')
        if regpath.exists():reg=state(regpath)
        else:
            reg=api.request('POST','/api/registrations/challenge',{**common,'node_capability':v['capability']});exclusive(regpath,canonical(reg))
        need(reg['app_policy_sha256']==cfg['app_policy_sha256'] and re.fullmatch('[a-f0-9]{32}',reg['registration_id']),'unexpected app policy/registration')
        directory=parent/('registration-'+reg['registration_id'])
        if evpath.exists():evidence=state(evpath)
        else:
            directory.mkdir(mode=0o700)
            evidence=_scope['enroll'](cfg,reg['challenge_b64'],directory);exclusive(evpath,canonical(evidence))
        response=api.request('POST','/api/registrations',{'registration_id':reg['registration_id'],**evidence,'payee':a['payee']})
        exclusive(Path(x.out),canonical({'response':response,'key_id':evidence['key_id'],'registration_id':reg['registration_id'],'node_capability':v['capability']}));print(json.dumps({'registration_submitted':True,'server_verified':response.get('registered_key_id')==evidence['key_id'],'registration_id':reg['registration_id'],'state_file':x.out}));return
    record=state(x.attempt);response=record['response'];attempt=response.get('attempt_id',response.get('id',response.get('attempt',{}).get('id')));need(re.fullmatch('[a-f0-9]{32}',attempt or ''),'attempt identity');cap=record['capability'];local=_scope['task_directory'](parent,attempt)
    if x.command=='status':print(json.dumps(api.request('GET',f'/api/attempts/{attempt}')));return
    if x.command=='prepare':
        registration=state(x.registration) if x.registration else None
        need(x.mode=='best_effort' or registration is not None,'self route requires local registered key')
        intent=parent/(attempt+'.execution-request.json')
        expected={'mode':x.mode,'key_id':registration['key_id'] if x.mode=='self' else None}
        if intent.exists():
            request=state(intent);need(all(request[k]==v for k,v in expected.items()),'execution request already selected')
        else:
            request={'request_id':secrets.token_hex(32),**expected};exclusive(intent,canonical(request))
        packet=api.request('POST',f'/api/attempts/{attempt}/execution',request,cap)
        if x.mode=='best_effort':print(json.dumps({'queued':True,'attempt_id':attempt}));return
        if 'artifacts' not in packet:
            observed=api.request('GET',f'/api/attempts/{attempt}');packet=observed.get('execution')
            if not packet:print(json.dumps({'preparation_pending':True,'attempt_id':attempt,'retry_same_prepare_after_status':True}));return
        need(packet['attempt_id']==attempt,'wrong task packet')
        if local.exists() and not x.resume_download:
            need(doc(read(local/'execution-packet.json'))==packet and (local/'task.json').exists(),'partial or conflicting preparation; preserve state');print(json.dumps({'prepared':True,'existing_task':True,'use_check_or_resume':True}));return
        api.resume_download=x.resume_download
        task=_scope['materialize'](cfg,packet,registration['key_id'],parent,api.fetch,resume_download=x.resume_download)
        raise SystemExit(_scope['coordinator'](cfg,'prepare',task,local,packet['native_execution_id']))
    task=local/'task.json';packet=doc(read(local/'execution-packet.json'));native=packet['native_execution_id']
    if x.command=='submit':
        saved=local/'EVIDENCE-SUBMITTED.json'
        if saved.exists():print(read(saved).decode());return
        result=upload(api,attempt,cap,local/('attempt-'+native),hashlib.sha256((attempt+'evidence').encode()).hexdigest());exclusive(saved,canonical(result));print(json.dumps(result));return
    if x.command=='cleanup':
        status=api.request('GET',f'/api/attempts/{attempt}');need(status.get('verdict'),'full proof still pending; preserve files')
        script=Path(__file__).with_name('cleanup.py');ns={'__name__':'arcade_cleanup','__file__':str(script)};exec(compile(script.read_bytes(),str(script),'exec'),ns);print(json.dumps(ns['retire'](cfg,packet,local,status['verdict'])));return
    raise SystemExit(_scope['coordinator'](cfg,x.command,task,local,native))

if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,OSError,http.client.HTTPException) as e:
        print('Arcade request refused: '+type(e).__name__+'; preserve local state and inspect status before retry',file=sys.stderr);raise SystemExit(2)
