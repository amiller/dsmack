#!/usr/bin/env python3
"""Exercise the browser P-256/HKDF/GCM wire format against secret_box.py."""
import base64
import json
from pathlib import Path
import subprocess
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'dstack-compat'))
import secret_box
sys.path.insert(0,str(ROOT/'applications/compute-node'))
from client import seal
import os
canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
node=ec.generate_private_key(ec.SECP256R1());broker=ed25519.Ed25519PrivateKey.generate()
pub=lambda key:key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
proc=subprocess.Popen(['node',str(Path(__file__).with_name('interop.mjs'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def send(v):proc.stdin.write(json.dumps(v)+'\n');proc.stdin.flush()
def receive():return json.loads(proc.stdout.readline())
job='0123456789abcdef0123456789abcdef';peer='12D3KooWPdcePFHp8pmoxdwpNC2ADNivvsCFYH8KPSfqutt7GWzA'
send(dict(peer=peer,secret=pub(node).hex(),broker=broker.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),jobId=job))
client=receive()['peer']
import time
grant=dict(client_peer=client,expires_at=int(time.time())+60,grant_id='abcdef0123456789abcdef0123456789',relay_peer=peer,seconds=30,unit='seconds',v=1)
send(dict(**grant,sig=broker.sign(canonical(grant)).hex()))
sealed=receive()
raw=secret_box.open_secret(node.private_numbers().private_value,job,*(bytes.fromhex(sealed['sealed'][k]) for k in ('epk','iv','ct')))
expected=dict(job_id=job,grant_id=grant['grant_id'],credential={'test':'cross-language'},repo_tar=base64.b64encode(b'toy archive bytes').decode(),prompt='edit π <tag> & UTF-8',output_pub=sealed['output_pub'])
assert raw==canonical(expected),'browser sealing differs from Python'
go_binary=os.environ.get('DSMACK_GO_BOX')
def go(request):return json.loads(subprocess.check_output([go_binary],input=canonical(request)))
if go_binary:
    opened=go(dict(Mode='open',Key=node.private_numbers().private_value.to_bytes(32,'big').hex(),Task=job,Box=sealed['sealed']))
    assert base64.b64decode(opened['plain'])==raw,'browser sealing differs from Go'
outputs={name:seal(bytes.fromhex(sealed['output_pub']),job+'/'+name,text.encode()) for name,text in dict(patch='diff π\n',transcript='{"text":"done"}\n',verdict='{"ok":true}').items()}
if go_binary:
    outputs['patch']=go(dict(Mode='seal',Key=sealed['output_pub'],Task=job+'/patch',Plain=base64.b64encode('diff π\n'.encode()).decode()))
send(outputs)
assert receive()==dict(patch='diff π\n',transcript='{"text":"done"}\n',verdict='{"ok":true}')
proc.stdin.close();assert proc.wait()==0
print(json.dumps({'browser_to_python':'passed','python_to_browser':'passed','unicode_canonical':'passed','output_key':'per-job nonextractable CryptoKey',**({'browser_to_go':'passed','go_to_browser':'passed'} if go_binary else {})}))
