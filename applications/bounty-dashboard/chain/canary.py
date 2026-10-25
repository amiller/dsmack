"""Read-only Canary entries with their Armed and Burned events."""
import hashlib,json,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))  # collect.py runs under python -I, which omits the script directory
import collect as m
CODECS=json.loads((HERE/'canary-abi.json').read_text())
KINDS=['Forgery','Guest','Runner','Owner']
def kind(d):
 k=int(d['kind']);m.need(k<len(KINDS),'unknown canary kind');return KINDS[k]
def collect_canary(c,r,state,max_pages):
 cid=str(c['chain_id'])+':'+c['address'];tx=c['explorer_url'].split('/address/')[0]+'/tx/'
 meta={k:c[k] for k in ['name','network','testnet','address','explorer_url','void','note','runtime_sha256','deployment_block','deployment_tx']}
 meta.update(id=cid,chain_id=c['chain_id'],observed_at=m.now(),status='unknown',coverage={},error=None,entries=[],events=[])
 try:
  m.need(c['codec'] in CODECS,'unsupported canary codec');codec=CODECS[c['codec']]
  m.need(int(r('eth_chainId',[]),16)==c['chain_id'],'wrong RPC chain')
  head=r('eth_getBlockByNumber',['latest',False]);number=int(head['number'],16);tag=hex(number)
  code=m.rawbytes(r('eth_getCode',[c['address'],tag]));m.need(code and hashlib.sha256(code).hexdigest()==c['runtime_sha256'],'runtime mismatch')
  state,pages=m.scan(r,c,number,state,max_pages,codec)
  events=[{'event':e['event'],'id':e['fields']['id'],'kind':kind(e['fields']),'amount_wei':e['fields']['amount'],'claimant':e['fields'].get('claimant'),'transaction_hash':e['transaction_hash'],'explorer_url':tx+e['transaction_hash'],'block_number':e['block_number'],'log_index':e['log_index'],'timestamp':e['timestamp']} for e in state['events']]
  entries=[]
  for i in sorted({int(e['id']) for e in events if e['event']=='Armed'}):
   d=m.decode(codec['entry'],r('eth_call',[{'to':c['address'],'data':'0x'+codec['selectors']['entries(uint256)']+format(i,'064x')},tag]))
   entries.append({'id':str(i),'kind':kind(d),'cdhash':d.get('cdhash'),'image':d['image'],'manifest':d['manifest'],'funder':d['funder'],'pot_wei':d['amount'],'until':d['until'],'burned':d['burned']})
  m.need(r('eth_getBlockByNumber',[tag,False])['hash']==head['hash'],'snapshot block reorged')
  meta.update(status='observed',block_number=number,block_hash=head['hash'],entries=entries,events=events,coverage={'entries':'every Armed id indexed, read at pinned block','events_from':c['deployment_block'],'events_through':state['through_block'],'events_complete':state['through_block']==number,'pages_this_run':pages,'reorg_reset':state['reorg_reset']})
  return meta,state
 except Exception as ex:
  meta.update(status='unknown',error=str(ex)[:180]);return meta,None
def collect_canaries(registry,rpc_factory,state_dir,max_pages):
 out=[]
 for c in registry:
  path=state_dir/(str(c['chain_id'])+'-'+c['address']+'.json');meta,new=collect_canary(c,rpc_factory(c['rpc']),json.loads(path.read_text()) if path.exists() else None,max_pages);out.append(meta)
  if new:m.atomic(path,new)
 return out
