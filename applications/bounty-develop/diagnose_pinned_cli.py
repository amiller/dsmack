#!/usr/bin/python3
"""Measured non-bounty diagnostic driver for the EXISTING pinned d912 image.

Root must separately admit fresh manifest/public driver/challenge/private broker.
No source/task/candidate supplied, no suite, no acceptance authority. The only
model instruction is fixed here. Original streams remain transient memory and
are NEVER exported; allowlisted structural observations only.
"""
import json,os,sys,time,tempfile
from pathlib import Path
sys.path.insert(0,'/opt/bounty-judges')
MODEL='claude-opus-4-8';PROMPT=b'Reply with the single word OK.'

def summarize(raw):
 result={'events':0,'init_events':0,'init_model_matches':False,'assistant_events':0,'assistant_model_matches':True,'result_events':0,'retry_events':0,'retry_statuses':[],'parse_refused':False}
 try:
  for line in raw.splitlines():
   if len(line)>262144:raise ValueError()
   e=json.loads(line)
   if type(e)is not dict:raise ValueError()
   result['events']+=1
   if result['events']>1024:raise ValueError()
   if e.get('type')=='system'and e.get('subtype')=='init':result['init_events']+=1;result['init_model_matches']=e.get('model')==MODEL
   if e.get('type')=='assistant':result['assistant_events']+=1;result['assistant_model_matches']&=type(e.get('message'))is dict and e['message'].get('model')==MODEL
   if e.get('type')=='result':result['result_events']+=1
   if e.get('type')=='system'and e.get('subtype')=='api_retry':
    result['retry_events']+=1;s=e.get('error_status');
    if len(result['retry_statuses'])<16:result['retry_statuses'].append(s if type(s)is int and 100<=s<=599 else None)
 except Exception:result['parse_refused']=True
 return result

def main():
 import generate as q
 q.require(os.getuid()==1000 and os.getgid()==1000,'UID1000 required')
 q.require(q.file_sha(Path('/usr/local/bin/claude'))==q.CLI_SHA256,'pinned CLI')
 state=Path('/workspace/state');out=Path('/workspace/artifacts');q.require(not any(state.iterdir())and not any(out.iterdir()),'fresh diagnostic workspace')
 with tempfile.TemporaryDirectory(prefix='diagnostic-',dir=state)as tmp:
  cwd,env=q.runtime_environment(Path(tmp),os.environ.get('DSMACK_SENTINEL_ENDPOINT'))
  start=time.monotonic();raw,err,code,failure=q.bounded_process(q.cli_command(Path('/usr/local/bin/claude'),MODEL,PROMPT),b'',cwd,env,30,1048576,65536)
  observed=summarize(raw);observed.update(schema='dsmack-pinned-cli-diagnostic/1',elapsed_ms=int((time.monotonic()-start)*1000),cli_exit=code,process_failure=failure if failure in(None,'deadline','output bound')else'other',stderr_bytes=len(err),requested_model=MODEL,stdout_bytes=len(raw),raw_output_exported=False,bounty_acceptance=False)
 with(out/'cli-diagnostic.json').open('xb')as f:f.write(json.dumps(observed,sort_keys=True,separators=(',',':')).encode())
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception:raise SystemExit('Pinned CLI diagnostic refused')from None
