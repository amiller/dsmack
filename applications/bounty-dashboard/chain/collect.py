#!/usr/bin/env python3
"""Read-only WorkEscrow snapshot. No signing, secrets, transaction send or dependencies."""
import argparse,datetime,hashlib,json,os,pathlib,re,time,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
ABI=json.loads((HERE/'abi.json').read_text())
STATES=['none','reserved','submitted','settled','rejected','expired']
def need(x,message):
 if not x:raise ValueError(message)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def atomic(p,x):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.tmp-'+str(os.getpid()))
 with tmp.open('x') as f:json.dump(x,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.replace(tmp,p)
class RPC:
 def __init__(self,url):need(url.startswith('https://'),'HTTPS RPC required');self.url=url
 def __call__(self,method,params):
  need(method in ['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call','eth_getLogs','eth_getTransactionReceipt','eth_getTransactionByHash'],'read method required')
  b=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
  with urllib.request.urlopen(urllib.request.Request(self.url,data=b,headers={'Content-Type':'application/json','User-Agent':'dsmack-arcade-pilot/1'}),timeout=30) as r:
   raw=r.read(8*1024*1024+1);need(len(raw)<=8*1024*1024,'RPC response too large');x=json.loads(raw)
  need(isinstance(x,dict) and x.get('id')==1 and 'error' not in x and 'result' in x,'RPC returned error/invalid response');return x['result']
def rawbytes(s):
 need(isinstance(s,str) and re.fullmatch('0x(?:[0-9a-fA-F]{2})*',s),'invalid hex');return bytes.fromhex(s[2:])
def words(s):
 b=rawbytes(s);need(len(b)%32==0,'invalid ABI word length');return [b[i:i+32] for i in range(0,len(b),32)]
def val(w,t):
 n=int.from_bytes(w,'big')
 if t=='address':need(n<2**160,'invalid address padding');return '0x'+w[-20:].hex()
 if t=='bytes32':return '0x'+w.hex()
 if t=='bool':need(n in [0,1],'invalid bool');return bool(n)
 need(t.startswith('uint') and n<2**int(t[4:] or '256'),'invalid uint');return str(n)
def flatfields(fields):
 out=[]
 for f in fields:out.extend(flatfields(f['components']) if f['type']=='tuple' else [f])
 return out
def decode(fields,data):
 fields=flatfields(fields);w=words(data);need(len(w)==len(fields),'ABI field count mismatch');return {f['name']:val(x,f['type']) for f,x in zip(fields,w)}
def call(r,c,name,i=None,block='latest'):
 sig=name+('(address)' if name=='withdrawable' else '(uint256)' if i is not None else '()');data='0x'+ABI['selectors'][sig]+('' if i is None else format(i,'064x'))
 return r('eth_call',[{'to':c['address'],'data':data},block])
def event(log,c,abi=ABI):
 need(log.get('address','').lower()==c['address'] and not log.get('removed',False),'foreign/removed event')
 es=[e for e in abi['events'] if log['topics'][0]==e['topic']];need(len(es)==1,'unknown event')
 e=es[0];indexed=[f for f in e['inputs'] if f['indexed']];plain=[f for f in e['inputs'] if not f['indexed']]
 need(len(log['topics'])==len(indexed)+1,'event topic count');d=decode(plain,log['data'])
 for f,t in zip(indexed,log['topics'][1:]):w=words(t);need(len(w)==1,'topic word count');d[f['name']]=val(w[0],f['type'])
 return {'event':e['name'],'fields':d,'block_number':int(log['blockNumber'],16),'block_hash':log['blockHash'],'transaction_hash':log['transactionHash'],'log_index':int(log['logIndex'],16)}
def scan(r,c,head,state,max_pages,abi=ABI):
 start=c['deployment_block'];reorg=False
 if state:
  need(state.get('contract_id')==str(c['chain_id'])+':'+c['address'],'checkpoint contract mismatch')
  anchor=r('eth_getBlockByNumber',[hex(state['through_block']),False])
  if anchor and anchor['hash']==state['through_hash']:start=state['through_block']+1
  else:state=None;reorg=True
 events=[] if not state else state['events'];through=start-1;throughhash=None if not state else state['through_hash'];pages=0
 while start<=head and pages<max_pages:
  end=min(start+199,head);logs=r('eth_getLogs',[{'address':c['address'],'fromBlock':hex(start),'toBlock':hex(end)}]);need(isinstance(logs,list) and len(logs)<=10000,'invalid/oversize logs')
  batch=[]
  for log in logs:
   e=event(log,c,abi);need(start<=e['block_number']<=end,'event outside requested range')
   block=r('eth_getBlockByNumber',[hex(e['block_number']),False]);need(block and block['hash']==e['block_hash'],'noncanonical log')
   receipt=r('eth_getTransactionReceipt',[e['transaction_hash']]);need(receipt and receipt['status']=='0x1' and receipt['blockHash']==e['block_hash'] and receipt['transactionHash']==e['transaction_hash'],'event receipt mismatch')
   need(any(x==log for x in receipt['logs']),'event missing from receipt');e['timestamp']=int(block['timestamp'],16);batch.append(e)
  anchor=r('eth_getBlockByNumber',[hex(end),False]);need(anchor,'missing event anchor');events.extend(batch);through=end;throughhash=anchor['hash'];start=end+1;pages+=1
 return {'contract_id':str(c['chain_id'])+':'+c['address'],'through_block':through,'through_hash':throughhash,'events':events,'reorg_reset':reorg},pages

def collect_contract(c,r,state,max_pages):
 cid=str(c['chain_id'])+':'+c['address'];meta={k:c[k] for k in ['network','testnet','address','explorer_url']};meta.update(id=cid,chain_id=c['chain_id'],observed_at=now(),status='unknown',coverage={},error=None)
 result={'contracts':[meta],'tasks':[],'assignments':[],'payments':[],'activity':[],'sources':[],'credits':[]};newstate=None
 try:
  need(c.get('codec')==ABI['schema'],'unsupported contract codec')
  need(int(r('eth_chainId',[]),16)==c['chain_id'],'wrong RPC chain')
  head=r('eth_getBlockByNumber',['latest',False]);number=int(head['number'],16);tag=hex(number);meta.update(block_number=number,block_hash=head['hash'])
  code=rawbytes(r('eth_getCode',[c['address'],tag]));need(code and hashlib.sha256(code).hexdigest()==c['runtime_sha256'],'runtime mismatch')
  nt=int(decode([{'name':'n','type':'uint256'}],call(r,c,'nextTask',block=tag))['n']);na=int(decode([{'name':'n','type':'uint256'}],call(r,c,'nextAssignment',block=tag))['n']);need(1<=nt<=10000 and 1<=na<=10000,'getter ID budget exceeded')
  tasks=[];assignments=[]
  for i in range(1,nt):
   d=decode(ABI['functions']['task'],call(r,c,'task',i,tag));tasks.append({'key':cid+':'+str(i),'id':str(i),'contract_id':cid,'chain_id':c['chain_id'],'package_hash':d['packageHash'],'policy_hash':d['policyHash'],'requester':d['requester'],'reward_wei':d['completionPay'],'effort_wei':d['effortPay'],'roles':{'allocator':d['allocator'],'execution_verifier':d['executionVerifier'],'reviewer':d['reviewer'],'delivery_verifier':d['deliveryVerifier'],'adjudicator':d['adjudicator']},'windows':{'submit_seconds':d['submitSeconds'],'review_seconds':d['reviewSeconds'],'adjudication_seconds':d['adjudicationSeconds']},'available_wei':d['available'],'reserved_wei':'0','deposited_wei':None,'state':'open' if d['open'] else 'closed','created_tx':None,'created_at':None,'active_assignment_id':d['activeAssignment'],'block_number':number,'block_hash':head['hash']})
  for i in range(1,na):
   d=decode(ABI['functions']['assignment'],call(r,c,'assignment',i,tag));s=int(d['state']);need(s<len(STATES),'unknown assignment state');assignments.append({'key':cid+':assignment:'+str(i),'id':str(i),'task_key':cid+':'+d['taskId'],'contract_id':cid,'worker':d['worker'],'state':STATES[s],'candidate_hash':d['candidate'],'evidence_hash':d['evidence'],'delivery_hash':d['delivery'],'reserved_wei':d['reserved'],'payout_wei':None,'deadlines':{'submit_by':d['submitBy'],'review_by':d['reviewBy']},'txlinks':[]})
  for t in tasks:t['reserved_wei']=str(sum(int(a['reserved_wei']) for a in assignments if a['task_key']==t['key'] and a['state'] in ['reserved','submitted']))
  accounts=sorted({t['requester'] for t in tasks}|{a['worker'] for a in assignments})
  credits=[{'contract_id':cid,'chain_id':c['chain_id'],'account':account,'withdrawable_wei':decode([{'name':'value','type':'uint256'}],call(r,c,'withdrawable',int(account,16),tag))['value'],'block_number':number,'block_hash':head['hash']} for account in accounts]
  # All reads at one height; detect a reorg that happened during the getter pass.
  need(r('eth_getBlockByNumber',[tag,False])['hash']==head['hash'],'snapshot block reorged')
  result.update(tasks=tasks,assignments=assignments,credits=credits);meta['status']='observed';meta['coverage']['getters']='all IDs at pinned block'
  try:
   newstate,pages=scan(r,c,number,state,max_pages);events=newstate['events'];meta['coverage'].update(events_from=c['deployment_block'],events_through=newstate['through_block'],events_complete=newstate['through_block']==number,pages_this_run=pages,reorg_reset=newstate['reorg_reset'])
   for e in events:
    d=e['fields'];tx=c['explorer_url'].split('/address/')[0]+'/tx/'+e['transaction_hash'];entry={'contract_id':cid,**e,'explorer_url':tx};result['activity'].append(entry)
    if e['event']=='TaskCreated':
     t=next((t for t in tasks if t['id']==d['taskId']),None)
     if t:t.update(deposited_wei=d['funding'],created_tx=e['transaction_hash'],created_at=e['timestamp'])
    if 'assignmentId' in d:
     a=next((a for a in assignments if a['id']==d['assignmentId']),None)
     if a:
      a['txlinks'].append({'event':e['event'],'url':tx,'transaction_hash':e['transaction_hash']})
      if e['event']=='Resolved':
       outcome=int(d['outcome']);need(outcome<3,'unknown resolved outcome');a.update(payout_wei=d['payout'],outcome=['Reject','Effort','Completion'][outcome])
    if e['event']=='Withdrawn':result['payments'].append({'key':cid+':'+e['transaction_hash']+':'+str(e['log_index']),'contract_id':cid,'account':d['account'],'recipient':d['account'],'amount_wei':d['amount'],'kind':'withdrawal','task_key':None,'assignment_key':None,'transaction_hash':e['transaction_hash'],'explorer_url':tx,'block_number':e['block_number'],'created_at':e['timestamp'],'attribution':'Account-level pull payment; task allocation unproven'})
  except Exception as ex:meta['coverage'].update(events_complete=False);meta['error']='event scan incomplete: '+str(ex)[:180]
  meta['coverage']['reward_classification_complete']=classify_withdrawals(newstate['events'] if newstate else [],tasks,assignments,result['payments'],meta['coverage'].get('events_complete')is True) and meta['coverage'].get('events_complete')is True
  need(r('eth_getBlockByNumber',[tag,False])['hash']==head['hash'],'snapshot block reorged during scan')
  result['sources'].append({'contract_id':cid,'rpc':c['rpc'],'runtime_sha256':c['runtime_sha256'],'deployment_tx':c['deployment_tx'],'deployment_block':c['deployment_block'],'provenance':c['provenance']})
 except Exception as ex:
  meta['status']='unknown';meta['error']=str(ex)[:180]
  for k in ['tasks','assignments','payments','activity','credits']:result[k]=[]
  newstate=None
 return result,newstate

def classify_withdrawals(events,tasks,assignments,payments,complete):
 """Classify each pull-payment pool from its observed credit origins."""
 pools={};bytask={t['id']:t for t in tasks};byassignment={a['id']:a for a in assignments}
 bytx={}
 for p in payments:bytx.setdefault((p['transaction_hash'],p['block_number']),[]).append(p)
 for e in sorted(events,key=lambda e:(e['block_number'],e['log_index'])):
  d=e['fields'];account=None;kind=None;amount=0
  if e['event']=='Resolved':
   a=byassignment.get(d['assignmentId']);account=a['worker'] if a else None;kind='reward';amount=int(d['payout'])
  elif e['event']=='TaskClosed':
   t=bytask.get(d['taskId']);account=t['requester'] if t else None;kind='refund';amount=int(d['reclaimed'])
  elif e['event']=='Withdrawn':
   account=d['account'];pool=pools.pop(account,{});p=bytx[(e['transaction_hash'],e['block_number'])].pop(0)
   known=complete and sum(pool.values())==int(d['amount']) and len(pool)==1
   economic=next(iter(pool)) if known else 'unclassified'
   p.update(economic_kind=economic,reward_eligible=True if economic=='reward' else False if economic=='refund' else None,
    attribution='Complete credit-event history: '+economic+' pool; task allocation unproven' if known else 'Withdrawal credit origins incomplete, mixed or unmatched')
  if account and amount>0:pools.setdefault(account,{})[kind]=pools.get(account,{}).get(kind,0)+amount
 return all(p.get('reward_eligible')is not None for p in payments)

def main():
 import importlib.util
 spec=importlib.util.spec_from_file_location('dashboard_direct_payments',HERE/'direct_payments.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);collect_direct=module.collect_direct
 p=argparse.ArgumentParser();p.add_argument('--registry',type=pathlib.Path,default=HERE/'registry.json');p.add_argument('--state-dir',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--event-pages',type=int,default=20);a=p.parse_args();need(0<=a.event_pages<=10000,'event page budget invalid');registry=json.loads(a.registry.read_text());out={'schema':'bounty-dashboard-chain/1','built_at':now(),**{k:[] for k in ['contracts','tasks','assignments','payments','activity','sources','credits']}}
 for c in registry['contracts']:
  need(re.fullmatch('0x[0-9a-f]{40}',c['address']) and isinstance(c['chain_id'],int),'invalid registry identity');path=a.state_dir/(str(c['chain_id'])+'-'+c['address']+'.json');state=json.loads(path.read_text()) if path.exists() else None;r,new=collect_contract(c,RPC(c['rpc']),state,a.event_pages)
  for k in ['contracts','tasks','assignments','payments','activity','sources','credits']:out[k].extend(r[k])
  if new:atomic(path,new)
 direct,source=collect_direct(json.loads((HERE/'direct-payments.json').read_text())['payments'],registry['contracts'],RPC,out['built_at'],out['payments']);out['payments'].extend(direct);out['direct_payment_sources']=[source]
 spec=importlib.util.spec_from_file_location('dashboard_canary',HERE/'canary.py');canary=importlib.util.module_from_spec(spec);spec.loader.exec_module(canary);out['canaries']=canary.collect_canaries(registry['canaries'],RPC,a.state_dir,a.event_pages)
 atomic(a.out,out)
if __name__=='__main__':main()
