#!/usr/bin/env python3
"""Explicit local credential-only export for a pipe into the reviewed importer.

No implicit source, provider calls, refresh, persistence, settings or metadata
export. Run locally on the subscription owner's computer. Never tee/log stdout.
"""
import argparse,json,os,stat,sys,time,types
from pathlib import Path
import hashlib
VALIDATOR_SHA='11f4e0fa320c741c2324bf21c0892a133c608d56b7e2b0e76e47c72556d12487'

def need(ok):
 if not ok:raise ValueError('credential export refused')
def unique(rows):
 result={}
 for k,v in rows:need(k not in result);result[k]=v
 return result

def validator():
 path=Path(__file__).resolve().parent/'reference/claude_subscription_document.py'
 with path.open('rb')as f:raw=f.read(65537)
 need(hashlib.sha256(raw).hexdigest()==VALIDATOR_SHA)
 m=types.ModuleType('selected_export_subscription_validator');exec(compile(raw,str(path),'exec'),m.__dict__);return m

def project(raw,v,now):
 need(isinstance(raw,bytes)and 0<len(raw)<=1048576)
 document=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite')))
 need(isinstance(document,dict)and isinstance(document.get('claudeAiOauth'),dict));oauth=document['claudeAiOauth']
 selected={'claudeAiOauth':{k:oauth[k]for k in v.ACCEPTED_OAUTH_FIELDS if k in oauth}}
 encoded=json.dumps(selected,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
 parsed=v.parse_subscription_document(encoded);need(parsed['expiresAt']/1000-now>=1200)
 return encoded

class Arguments(argparse.ArgumentParser):
 def error(self,message):raise ValueError('argument contract refused')
def main():
 ap=Arguments(description=__doc__);ap.add_argument('--source',required=True);ap.add_argument('--emit-credential-stdout',action='store_true');a=ap.parse_args()
 need(sys.flags.isolated==1 and a.emit_credential_stdout and stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode))
 # Validate public parser source and destination before opening any credential.
 v=validator();fd=os.open(a.source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_uid==os.getuid()and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=1048576)
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(1048577)
  after=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(identity(before)==identity(after)and len(raw)==before.st_size)
 finally:os.close(fd)
 selected=project(raw,v,time.time());sys.stdout.buffer.write(selected);sys.stdout.buffer.flush()
if __name__=='__main__':
 try:main()
 except SystemExit:raise
 except BaseException:
  print('DSMACK_CREDENTIAL_EXPORT_REFUSED',file=sys.stderr);raise SystemExit(2)
