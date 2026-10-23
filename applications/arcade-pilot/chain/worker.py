"""Fixed-task WorkEscrow v2 bridge. Authority keys stay in protected Zed files.

No caller-supplied RPC, role, terms, executable or trust root is accepted.
The selected validation adapter MUST recheck genuine retained runtime/functional
and delivery correspondence; an HTTP 'accepted' flag is never sufficient.
"""
import argparse, hashlib, json, os, pathlib, re, stat, subprocess, sys, time, urllib.request, fcntl, tempfile
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_abi import encode, decode
from eth_utils import keccak

CHAIN=84532
CONTRACT='0x62fedc157f275abb8f8b4543696e6f0c717d391b'
RUNTIME='dd3596a61b94402a0161b950319d726fed7ffd0fd384774fa562d07b06aa6daa'
FIELDS=[('assignmentId','uint256'),('taskId','uint256'),('packageHash','bytes32'),('policyHash','bytes32'),('worker','address'),('candidate','bytes32'),('evidence','bytes32'),('delivery','bytes32'),('outcome','uint8'),('payout','uint256')]
TASK_TYPES=['address','bool','uint256','uint256','bytes32','bytes32',*(['address']*5),'uint96','uint96','uint32','uint32','uint32']
ASSIGN_TYPES=['uint256','address','uint8','uint256','uint256','uint256','bytes32','bytes32','bytes32']
ZERO=b'\0'*32
class Refusal(Exception):pass
def need(v,m):
 if not v:raise Refusal(m)
def unique(pairs):
 d={}
 for k,v in pairs:need(k not in d,'duplicate JSON key');d[k]=v
 return d
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'nonfinite JSON'))
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def addr(v):return isinstance(v,str)and re.fullmatch(r'0x[0-9a-f]{40}',v)and v!='0x'+'0'*40
def hash64(v):return isinstance(v,str)and re.fullmatch(r'[0-9a-f]{64}',v)
def uint(v):return isinstance(v,str)and re.fullmatch(r'[1-9][0-9]*',v)and int(v)<2**256
def secure_read(path,cap,private=False):
 p=pathlib.Path(path);need(p.is_absolute()and str(p)==str(p.resolve()),'normalized protected path')
 for a in p.parents:
  st=a.lstat();need(stat.S_ISDIR(st.st_mode)and st.st_uid in (0,os.getuid())and not(st.st_mode&0o022),'unsafe path ancestry')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid in (0,os.getuid())and not(st.st_mode&0o022)and 0<st.st_size<=cap,'bounded protected regular file')
  if private:need(stat.S_IMODE(st.st_mode)==0o600 and stat.S_IMODE(p.parent.stat().st_mode)==0o700,'private mode required')
  raw=os.read(fd,cap+1);need(len(raw)==st.st_size and (lambda q:(q.st_dev,q.st_ino,q.st_mode,q.st_uid,q.st_nlink,q.st_size,q.st_mtime_ns,q.st_ctime_ns))(os.fstat(fd))==(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns),'file changed');return raw
 finally:os.close(fd)
def durable(path,value):
 raw=canon(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False)as f:f.write(raw);f.flush();os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(pathlib.Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def data(sig,types=(),values=()):return '0x'+keccak(text=sig)[:4].hex()+encode(list(types),list(values)).hex()
def decode_hex(types,raw):need(isinstance(raw,str)and raw.startswith('0x'),'RPC ABI response');return decode(types,bytes.fromhex(raw[2:]))
class RPC:
 def __init__(self,url):need(isinstance(url,str)and url.startswith('https://'),'HTTPS RPC required');self.url=url
 def __call__(self,method,args):
  need(method in ['eth_chainId','eth_getBlockByNumber','eth_getBlockByHash','eth_getCode','eth_call','eth_getBalance','eth_getTransactionCount','eth_estimateGas','eth_gasPrice','eth_getTransactionReceipt','eth_sendRawTransaction','eth_getLogs'],'RPC method refused')
  request=urllib.request.Request(self.url,data=canon({'jsonrpc':'2.0','id':1,'method':method,'params':args}),headers={'Content-Type':'application/json','User-Agent':'dsmack-arcade-pilot/1'})
  with urllib.request.urlopen(request,timeout=20)as r:raw=r.read(2097153)
  need(len(raw)<=2097152,'RPC body bound');v=parse(raw);need(v.get('id')==1 and 'error'not in v and 'result'in v,'RPC refused');return v['result']

def config_check(c):
 need(c['schema']=='dsmack-arcade-claim-worker/1'and c['chain_id']==CHAIN and c['contract']==CONTRACT and c['runtime_sha256']==RUNTIME,'fixed deployment')
 need(uint(c['task_id'])and int(c['task_id'])>=10,'new funded task only')
 need(hash64(c['package_hash'])and hash64(c['policy_hash'])and uint(c['payout_wei'])and addr(c['requester']),'fixed task terms')
 need(c['terms']['effort_pay']=='0'and c['terms']['completion_pay']==c['payout_wei'],'completion only')
 for n in ['allocator','execution','review','delivery']:need(addr(c['roles'][n]['address']),'fixed public role')
 need(addr(c['terms']['adjudicator']),'adjudicator required')
 need(re.fullmatch(r'0x[0-9a-f]+',c['task_created_block']),'actual task creation block required')
 need(int(c['max_allocator_fee_wei'])>0 and int(c['max_allocator_fee_wei'])<=10**15,'bounded allocator fee')
 return c
class Bridge:
 def __init__(self,c,rpc,validator,key_loader=None):
  self.c=config_check(c);self.rpc=rpc;self.validate=validator;self.key_loader=key_loader or self.private_key
  self.root=pathlib.Path(c['journal_root']);self.root.mkdir(mode=0o700,parents=True,exist_ok=True);need(stat.S_IMODE(self.root.stat().st_mode)==0o700,'private journal root')
 def private_key(self,role):
  selected=self.c['roles'][role];v=parse(secure_read(selected['key_file'],4096,True));need(set(v)=={'address','private_key'}and v['address'].lower()==selected['address'],'role document identity');need(re.fullmatch(r'0x[0-9a-fA-F]{64}',v['private_key']),'role scalar');secret=bytes.fromhex(v['private_key'][2:]);need(Account.from_key(secret).address.lower()==selected['address'],'role recovery');return secret
 def call(self,sig,types=(),values=(),height='latest'):
  return self.rpc('eth_call',[{'to':CONTRACT,'data':data(sig,types,values)},height])
 def snapshot(self,assignment_id=None):
  c=self.c;need(int(self.rpc('eth_chainId',[]),16)==CHAIN,'wrong chain');h=self.rpc('eth_getBlockByNumber',['latest',False]);need(h and h.get('hash')and h.get('number')and h.get('timestamp'),'block required');height=h['number'];code=self.rpc('eth_getCode',[CONTRACT,height]);need(sha(bytes.fromhex(code[2:]))==RUNTIME,'wrong runtime')
  t=decode_hex(TASK_TYPES,self.call('task(uint256)',['uint256'],[int(c['task_id'])],height));roles=c['roles'];terms=c['terms']
  need(t[0]==c['requester']and t[4].hex()==c['package_hash']and t[5].hex()==c['policy_hash'],'task hashes/requester')
  need(list(t[6:11])==[roles['allocator']['address'],roles['execution']['address'],roles['review']['address'],roles['delivery']['address'],terms['adjudicator']],'task authority roles')
  need(t[11:]==(0,int(c['payout_wei']),terms['submit_seconds'],terms['review_seconds'],terms['adjudication_seconds']),'task amounts/windows')
  a=None
  if assignment_id is not None:a=decode_hex(ASSIGN_TYPES,self.call('assignment(uint256)',['uint256'],[int(assignment_id)],height));need(a[0]==int(c['task_id']),'assignment task mismatch')
  return h,t,a
 def binding(self,input):
  need(set(input)=={'task','attempt','request_id'},'claim input fields');task=input['task'];a=input['attempt'];c=self.c
  need(task['task_id']==c['task_id']and task['policy_sha256']==c['policy_hash']and task['chain_id']==CHAIN and task['contract']==CONTRACT,'public task binding')
  need(re.fullmatch(r'[a-f0-9]{32}',a['id'])and addr(a['payee'])and re.fullmatch(r'[a-f0-9]{40}',a['candidate_commit']),'immutable attempt identity')
  need(a['state']=='verified'and a['verdict']['accepted']is True,'genuine verified attempt required')
  b=self.validate(input)
  for k,v in {'schema':'dsmack-arcade-settlement-binding/1','attempt_id':a['id'],'payee':a['payee'],'candidate_commit':a['candidate_commit'],'policy_sha256':c['policy_hash'],'report_sha256':a['verdict']['report_sha256']}.items():need(b.get(k)==v,'validated report binding '+k)
  for k in ['candidate_sha256','evidence_sha256','delivery_sha256','report_sha256']:need(hash64(b.get(k)),'validated commitment '+k)
  need(b.get('original_report_authenticated')is True and b.get('original_outputs_verified')is True and b.get('checker_recomputed')is True and b.get('delivery_rehashed')is True,'common verifier and delivery checks required')
  return a,b
 def packet(self,a,b,aid,stage,txs=None,**extra):return {'schema':'dsmack-arcade-claim/1','chain_id':CHAIN,'contract':CONTRACT,'task_id':self.c['task_id'],'assignment_id':str(aid)if aid else None,'payee':a['payee'],'candidate_commit':a['candidate_commit'],'report_sha256':b['report_sha256'],'candidate_sha256':b['candidate_sha256'],'evidence_sha256':b['evidence_sha256'],'delivery_sha256':b['delivery_sha256'],'stage':stage,'transactions':txs or {},'payment_received':False,**extra}
 def tx(self,payee,calldata):return {'chainId':hex(CHAIN),'to':CONTRACT,'from':payee,'value':'0x0','data':calldata}
 def journal(self,attempt):
  p=self.root/attempt;p.mkdir(mode=0o700,exist_ok=True);need(stat.S_IMODE(p.stat().st_mode)==0o700,'private attempt journal');return p
 def assign(self,a,b,h,t):
  """One durable signed allocation per attempt. Never choose a fresh nonce on retry."""
  c=self.c;j=self.journal(a['id']);intent=j/'allocation-intent.json';receipt=j/'allocation-receipt.json'
  if receipt.exists():return parse(secure_read(receipt,65536))['assignment_id']
  if intent.exists():v=parse(secure_read(intent,131072,True));need(v['payee']==a['payee']and v['binding_sha256']==sha(canon(b)),'allocation journal binding')
  else:
   need(t[1]and t[2]>=int(c['payout_wei'])and t[3]==0,'task unfunded/closed/already assigned')
   sender=c['roles']['allocator']['address'];nonce=self.rpc('eth_getTransactionCount',[sender,'pending']);need(nonce==self.rpc('eth_getTransactionCount',[sender,'latest']),'allocator pending nonce')
   call={'from':sender,'to':CONTRACT,'value':'0x0','data':data('assign(uint256,address)',['uint256','address'],[int(c['task_id']),a['payee']])};gas=int(self.rpc('eth_estimateGas',[call]),16)*125//100;price=int(self.rpc('eth_gasPrice',[]),16)*125//100;need(gas<=300000 and gas*price<=int(c['max_allocator_fee_wei']),'allocator fee bound');need(int(self.rpc('eth_getBalance',[sender,'latest']),16)>=gas*price,'allocator balance')
   tx={**call,'chainId':CHAIN,'nonce':int(nonce,16),'gas':gas,'gasPrice':price};tx['value']=0;tx['to']=bytes.fromhex(CONTRACT[2:]);tx.pop('from');secret=self.key_loader('allocator');signed=Account.sign_transaction(tx,secret);need(Account.recover_transaction(signed.raw_transaction).lower()==sender,'allocator recovered signer');oracle='0x420000000000000000000000000000000000000F';l1=int(self.rpc('eth_call',[{'to':oracle,'data':data('getL1Fee(bytes)',['bytes'],[signed.raw_transaction])},h['number']]),16);operator=int(self.rpc('eth_call',[{'to':oracle,'data':data('getOperatorFee(uint256)',['uint256'],[gas])},h['number']]),16);need(gas*price+l1+operator<=int(c['max_allocator_fee_wei']),'actual signed rollup fee bound');need(int(self.rpc('eth_getBalance',[sender,'latest']),16)>=gas*price+l1+operator,'allocator rollup balance');need(self.rpc('eth_getBlockByNumber',[h['number'],False])['hash']==h['hash'],'snapshot changed');need(self.rpc('eth_getTransactionCount',[sender,'pending'])==nonce==self.rpc('eth_getTransactionCount',[sender,'latest']),'late nonce changed');v={'payee':a['payee'],'binding_sha256':sha(canon(b)),'transaction_hash':'0x'+signed.hash.hex(),'raw_transaction':'0x'+signed.raw_transaction.hex(),'snapshot_block':h['number']};durable(intent,v)
  sent=j/'broadcast-intent.json'
  if not sent.exists():
   durable(sent,{'transaction_hash':v['transaction_hash'],'same_hash_only':True})
   try:returned=self.rpc('eth_sendRawTransaction',[v['raw_transaction']]);need(returned.lower()==v['transaction_hash'],'broadcast hash mismatch')
   except Exception:return None # outcome unknown: later calls observe SAME hash only
  r=self.rpc('eth_getTransactionReceipt',[v['transaction_hash']])
  if r is None:return None
  need(r['transactionHash'].lower()==v['transaction_hash']and int(r['status'],16)==1,'allocation receipt failure');block=self.rpc('eth_getBlockByNumber',[r['blockNumber'],False]);need(block['hash'].lower()==r['blockHash'].lower(),'noncanonical allocation receipt')
  topic='0x'+keccak(text='Assigned(uint256,uint256,address,uint256,uint256)').hex();logs=[x for x in r['logs']if x['address'].lower()==CONTRACT and x['topics'][0].lower()==topic]
  need(len(logs)==1,'one Assigned event required');log=logs[0];need(len(log['topics'])==4 and int(log['topics'][2],16)==int(c['task_id'])and '0x'+log['topics'][3][-40:].lower()==a['payee'],'Assigned event binding');aid=int(log['topics'][1],16);reserved,deadline=decode_hex(['uint256','uint256'],log['data']);need(reserved==int(c['payout_wei']),'Assigned reserve');_,t,assignment=self.snapshot(aid);need(assignment[1]==a['payee']and assignment[2]==1 and t[3]==aid,'actual assignment state');durable(receipt,{'assignment_id':str(aid),'transaction_hash':v['transaction_hash'],'block_hash':r['blockHash'],'submit_by':deadline,'inclusion_not_finality':True});return str(aid)
 def typed(self,aid,a,b):
  c=self.c;return {'types':{'Decision':[{'name':n,'type':t}for n,t in FIELDS]},'primaryType':'Decision','domain':{'name':'DsmackWorkEscrow','version':'2','chainId':CHAIN,'verifyingContract':CONTRACT},'message':{'assignmentId':str(aid),'taskId':c['task_id'],'packageHash':'0x'+c['package_hash'],'policyHash':'0x'+c['policy_hash'],'worker':a['payee'],'candidate':'0x'+b['candidate_sha256'],'evidence':'0x'+b['evidence_sha256'],'delivery':'0x'+b['delivery_sha256'],'outcome':2,'payout':c['payout_wei']}}
 def process(self,input):
  fd=os.open(self.root/'.bridge.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  try:
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise Refusal('claim bridge busy; no action started')
   return self._process_locked(input)
  finally:os.close(fd)
 def _process_locked(self,input):
  a,b=self.binding(input);h,t,_=self.snapshot();j=self.journal(a['id']);rec=j/'allocation-receipt.json'
  if rec.exists():aid=parse(secure_read(rec,65536))['assignment_id']
  elif t[3]:
   # Never adopt an unrelated assignment because its payee happens to match.
   need((j/'allocation-intent.json').exists(),'unowned existing assignment');aid=self.assign(a,b,h,t)
  else:aid=self.assign(a,b,h,t)
  if aid is None:return self.packet(a,b,None,'allocation_pending',same_hash_only=True)
  h,t,s=self.snapshot(aid);now=int(h['timestamp'],16);need(s[1]==a['payee'],'assignment wallet mismatch');commitments=[bytes.fromhex(b[k])for k in ['candidate_sha256','evidence_sha256','delivery_sha256']]
  if s[2]==1:
   need(t[3]==int(aid)and s[3]==int(self.c['payout_wei'])and now<=s[4]and all(v==ZERO for v in s[6:]),'reserved submission state/deadline');return self.packet(a,b,aid,'submit',{'submit':self.tx(a['payee'],data('submit(uint256,bytes32,bytes32,bytes32)',['uint256','bytes32','bytes32','bytes32'],[int(aid),*commitments]))})
  need(list(s[6:])==commitments,'onchain candidate/evidence/delivery mismatch')
  if s[2]==2:
   need(t[3]==int(aid)and s[3]==int(self.c['payout_wei'])and now<=s[5],'reviewer window/reservation')
   # Repeat the common report/delivery validation immediately before role signing.
   need(self.binding(input)[1]==b,'verification/delivery changed before signing');typed=self.typed(aid,a,b);message=encode_typed_data(full_message=typed);digest=keccak(b'\x19'+message.version+message.header+message.body);need(self.call('decisionDigest(uint256,uint8)',['uint256','uint8'],[int(aid),2],h['number']).lower()=='0x'+digest.hex(),'onchain decisionDigest mismatch');sigpath=j/('signatures-'+digest.hex()+'.json')
   if sigpath.exists():
    cached=parse(secure_read(sigpath,131072));need(cached['decision_digest']=='0x'+digest.hex(),'cached decision digest');signatures=cached['signatures'];need(isinstance(signatures,list)and len(signatures)==3,'cached signature membership')
    for role,sig in zip(['execution','review','delivery'],signatures):need(re.fullmatch(r'0x[0-9a-f]{130}',sig)and Account.recover_message(message,signature=sig).lower()==self.c['roles'][role]['address'],'cached role signature recovery')
   else:
    signatures=[]
    for role in ['execution','review','delivery']:
     sig=Account.sign_message(message,self.key_loader(role));need(Account.recover_message(message,signature=sig.signature).lower()==self.c['roles'][role]['address'],'verifier role recovery');signatures.append('0x'+sig.signature.hex())
    durable(sigpath,{'decision_digest':'0x'+digest.hex(),'signatures':signatures,'checked_block':h['number']})
   return self.packet(a,b,aid,'resolve',{'resolve':self.tx(a['payee'],data('resolve(uint256,uint8,bytes,bytes,bytes)',['uint256','uint8','bytes','bytes','bytes'],[int(aid),2,*[bytes.fromhex(x[2:])for x in signatures]]))},typed_data=typed,signatures=signatures,checked_block=h['number'])
  need(s[2]==3 and s[3]==0,'assignment not completion-settled');resolved=self.event('Resolved(uint256,uint8,uint256)',[hex(int(aid))],['uint8','uint256'],[2,int(self.c['payout_wei'])],self.c['task_created_block'],h['number']);need(resolved,'actual completion resolution event required');credit=int(self.call('withdrawable(address)',['address'],[a['payee']],h['number']),16)
  if credit>0:return self.packet(a,b,aid,'withdraw',{'withdraw':self.tx(a['payee'],data('withdraw()'))},withdrawable_wei=str(credit),received=False)
  # Zero credit is not receipt. Require a canonical successful event-bearing
  # withdrawal after THIS assignment's actual Completion resolution.
  withdrawn=self.event('Withdrawn(address,uint256)',['0x'+a['payee'][2:].rjust(64,'0')],['uint256'],None,resolved['blockNumber'],h['number'],minimum=int(self.c['payout_wei']),sender=a['payee'],after=resolved)
  if withdrawn is None:return self.packet(a,b,aid,'withdrawal_unobserved',received=False)
  return self.packet(a,b,aid,'received',received=True,payment_received=True,transaction_hash=withdrawn['transactionHash'],inclusion_not_finality=True)
 def event(self,signature,indexed,types,expected,start,end,minimum=None,sender=None,after=None):
  topic='0x'+keccak(text=signature).hex();topics=[topic,*['0x'+x[2:].rjust(64,'0')for x in indexed]];logs=self.rpc('eth_getLogs',[{'address':CONTRACT,'fromBlock':start,'toBlock':end,'topics':topics}]);need(isinstance(logs,list)and len(logs)<=128,'event lookup bound')
  for log in logs:
   need(log['address'].lower()==CONTRACT and [x.lower()for x in log['topics']]==topics and not log.get('removed',False),'event identity');values=list(decode_hex(types,log['data']))
   if expected is not None and values!=expected:continue
   if minimum is not None and values[0]<minimum:continue
   if after is not None and tuple(int(log[k],16)for k in ['blockNumber','transactionIndex','logIndex'])<=tuple(int(after[k],16)for k in ['blockNumber','transactionIndex','logIndex']):continue
   r=self.rpc('eth_getTransactionReceipt',[log['transactionHash']]);need(r and int(r['status'],16)==1 and r['to'].lower()==CONTRACT and r['blockHash'].lower()==log['blockHash'].lower()and r['transactionHash'].lower()==log['transactionHash'].lower(),'successful event transaction')
   if sender:need(r['from'].lower()==sender,'withdrawal signer')
   block=self.rpc('eth_getBlockByNumber',[r['blockNumber'],False]);need(block['hash'].lower()==r['blockHash'].lower()and log in r['logs'],'canonical event receipt');return log
  return None

def validation_envelope(raw):
 result=parse(raw);need(isinstance(result,dict)and set(result)=={'public_result','artifacts'}and result['artifacts']==[]and isinstance(result['public_result'],dict),'settlement validation envelope');return result['public_result']
def selected_validator(c):
 v=c['validator'];script=secure_read(v['script'],1048576);need(sha(script)==v['script_sha256'],'validator source pin');cfg=secure_read(v['config'],1048576);need(sha(cfg)==v['config_sha256'],'validator config pin');job_root=pathlib.Path(v['job_root']);job_root.mkdir(mode=0o700,parents=True,exist_ok=True);need(stat.S_IMODE(job_root.stat().st_mode)==0o700,'private validation job root')
 def run(input):
  # The adapter writes bounded public validation records under a fresh owned
  # job directory. Preserve those records for audit; never reuse its mutation
  # namespace, and never let an HTTP caller select the path or config.
  job=tempfile.mkdtemp(prefix='settlement-',dir=job_root);request={'action':'settlementBinding','input':input,'job_dir':job,'input_sha256':sha(canon(input))}
  p=subprocess.run([v['python'],'-I',v['script'],'--config',v['config'],'--config-sha256',v['config_sha256']],input=canon(request),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=120,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'});need(p.returncode==0 and 0<len(p.stdout)<=262144,'genuine settlement validation refused');return validation_envelope(p.stdout)
 return run

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--config-sha256',required=True);args=ap.parse_args();raw=secure_read(args.config,1048576,True);need(sha(raw)==args.config_sha256,'root selected config pin');c=parse(raw);input=parse(sys.stdin.buffer.read(1048577));need(len(canon(input))<=1048576,'input bound');bridge=Bridge(c,RPC(c['rpc_url']),selected_validator(c));print(canon(bridge.process(input)).decode())
if __name__=='__main__':
 try:main()
 except Exception as e:
  # Never emit signing scalar, RPC body, environment or subprocess diagnostics.
  print(json.dumps({'error':str(e)if isinstance(e,Refusal)else'claim bridge refused; inspect private journal'}),file=sys.stderr);raise SystemExit(2)
