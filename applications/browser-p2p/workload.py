#!/usr/bin/env python3
"""Pack the hostname-gated browser peer. Build on a Linux host with the repository tooling."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'applications/libp2p-attest'),str(ROOT/'dstack-compat')]
import importlib.util
_spec=importlib.util.spec_from_file_location("peer_workload",ROOT/"applications/libp2p-attest/workload.py")
peer_workload=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(peer_workload)
import canary_workload
p=argparse.ArgumentParser(description=__doc__)
for arg in ('base','reference','peer','gateway','ca','out'):p.add_argument('--'+arg,type=Path,required=True)
p.add_argument('--seconds',type=int,default=420);p.add_argument('--mac-public-pack',action='store_true');p.add_argument('--hostname',required=True);p.add_argument('--relay-peer',required=True)
p.add_argument('--proxy-ip',default='192.168.127.254');p.add_argument('--proxy-port',type=int,default=18290)
a=p.parse_args()
if not 1<=a.seconds<=420:p.error('guest lifetime must be 1..420 seconds')
a.out.mkdir()
policy={'rules':[{'name':'*.trycloudflare.com','port':443,'methods':['GET'],'paths':['/'],'websocket_seconds':540,'max_request_bytes':1<<20,'max_response_bytes':4<<20,'upload_bytes':1<<20,'download_bytes':4<<20,'requests':8,'requests_per_minute':60}]}
policy_path=a.out/'policy.json';policy_path.write_bytes(peer_workload.canon(policy))
digest=peer_workload.oci_layout(a.peer,a.out/'image',ca_cert=a.ca,files={'/usr/local/bin/egress-policy':(a.gateway,0o755),'/policy.json':(policy_path,0o644)})
m=json.loads(peer_workload.manifest(a.reference,a.peer,digest,''))
services=json.loads(m['docker_compose_file'])['services'];service=services['peer']
service['command']=[a.hostname,a.relay_peer,str(a.seconds)];service['environment']={'BROWSER_GATEWAY_PROXY':f'http://{a.proxy_ip}:{a.proxy_port}'}
m['docker_compose_file']=peer_workload.canon({'services':services}).decode()
m['network']={'mode':'nat','listen_ports':[],'egress':[{'destination':a.proxy_ip+'/32','protocol':'tcp','port':a.proxy_port}]}
meta=json.loads((a.base/'metadata.json').read_bytes());sha=canary_workload.fsha
m['base_vm'].update(cmdline=meta['cmdline'],initrd_sha256=sha(a.base/'initramfs.cpio.gz'),kernel_sha256=sha(a.base/'Image'),metadata_sha256=sha(a.base/'metadata.json'),os_image_hash=sha(a.base/'sha256sum.txt'),rootfs_sha256=sha(a.base/'rootfs.squashfs.verity'),verity_root_hash=next(t.split('=',1)[1] for t in meta['cmdline'].split() if t.startswith('dstack.rootfs_hash=')))
m['outputs']['artifacts'] += [{'name':n,'path':'/workspace/artifacts/'+n} for n in ('gateway-log','egress-checks')]
raw=peer_workload.canon(m);(a.out/'compose-manifest.json').write_bytes(raw)
from public_pack import pack_public
canary_workload.pack(ROOT,a.base,a.out/'image',a.out/'disk',peer_workload.NAME,raw,build_disk=pack_public if a.mac_public_pack else None)
