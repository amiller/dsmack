#!/usr/bin/env python3
"""Publish only public read models to the separate dashboard. Never signs or sends funds."""
import argparse,datetime,json,pathlib,stat,os,urllib.request
ENDPOINT='https://pod.dstack.soc1024.com/bounties/api/snapshot'
def normalize(chain,feeds):
 out={k:chain.get(k,[]) for k in ['contracts','tasks','assignments','payments','activity','credits','canaries']}
 out['contracts']=[{k:v for k,v in c.items()if k in ['id','name','chain_id','network','testnet','address','explorer_url','asset_symbol','block_number','block_hash','observed_at','status','coverage','error']}for c in out['contracts']]
 for c in out['contracts']:
  if 'credits'in chain and c.get('status')=='observed':c.setdefault('coverage',{})['credit_balances']='all observed recipients at pinned block'
  c.setdefault('name','WorkEscrow v2');c.setdefault('asset_symbol','ETH'if c['chain_id']in[1,8453,84532,11155111]else'native units')
 ids={c['id']:c for c in out['contracts']};assignments={a['key']:a for a in out['assignments']}
 for row in out['payments']:row.setdefault('chain_id',ids[row['contract_id']]['chain_id']);row.setdefault('timestamp',row.get('created_at'))
 for row in out['assignments']:row.setdefault('chain_id',ids[row['contract_id']]['chain_id'])
 activity=[]
 labels={'TaskCreated':'Task funded','Assigned':'Assignment created','Submitted':'Result submitted','Resolved':'Assignment resolved','Expired':'Assignment expired','ReviewExpired':'Review window expired','TaskClosed':'Task closed / refund credited','Withdrawn':'Withdrawal'}
 for e in out['activity']:
  cid=e['contract_id'];fields=e.get('fields',{});task=fields.get('taskId');a=assignments.get(cid+':assignment:'+str(fields.get('assignmentId')))
  activity.append({**e,'id':cid+':'+e['transaction_hash']+':'+str(e['log_index']),'kind':labels.get(e['event'],e['event']),'task_key':cid+':'+str(task)if task is not None else a['task_key']if a else None,'tx':e['transaction_hash']})
 out['activity']=sorted(activity,key=lambda e:(e.get('timestamp',0),e.get('log_index',0)),reverse=True)
 out['sources']=[{'id':'chain:'+c['id'],'kind':'chain','name':c['name']+' · '+c['network'],'status':'unavailable'if c['status']=='unknown'else'partial'if c.get('error')else'ok'if c.get('coverage',{}).get('events_complete')else'indexing','observed_at':c.get('observed_at'),'block_number':c.get('block_number'),'block_hash':c.get('block_hash'),'scope':'All task and assignment IDs at the observed block','coverage':c.get('coverage',{}),'error':c.get('error')}for c in out['contracts']]
 out['sources'].extend(chain.get('direct_payment_sources',[]))
 return {'schema':'dsmack-bounty-dashboard-snapshot/1','observed_at':chain['built_at'],'chain':out,'feeds':feeds}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('dashboard redirect refused')
def send(payload,tokenfile):
 p=pathlib.Path(tokenfile);s=p.lstat()
 if not stat.S_ISREG(s.st_mode)or s.st_uid!=os.getuid()or s.st_mode&0o077:raise ValueError('private ingest token required')
 token=p.read_text().strip()
 if len(token)!=43:raise ValueError('invalid ingest token')
 req=urllib.request.Request(ENDPOINT,data=json.dumps(payload,separators=(',',':')).encode(),method='PUT',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','User-Agent':'dsmack-bounty-dashboard/1'})
 with urllib.request.build_opener(NoRedirect).open(req,timeout=30)as r:
  d=json.loads(r.read(65536));assert r.status==200 and d.get('accepted')is True
 return {'accepted':True,'tasks':len(payload['chain']['tasks']),'historical_attempts':sum(len(x['attempts'])for x in payload['feeds']),'payments':len(payload['chain']['payments']),'observed_at':payload['observed_at']}
def main():
 p=argparse.ArgumentParser();p.add_argument('--chain',required=True,type=pathlib.Path);p.add_argument('--feed',action='append',default=[],type=pathlib.Path);p.add_argument('--token-file',required=True,type=pathlib.Path);a=p.parse_args();print(json.dumps(send(normalize(json.loads(a.chain.read_text()),[json.loads(f.read_text())for f in a.feed]),a.token_file)))
if __name__=='__main__':main()
