#!/usr/bin/env python3
"""Pack a compute OCI layout into a v0.2 workload with three fixed egress endpoints.

workload.py REPO BASE STARTER OCI_DIR DIGEST BINARY RELAY BROKER BROKER_KEY CDHASH OUT [SECONDS]
"""
import hashlib
import ipaddress
import json
import socket
from pathlib import Path
import sys
from urllib.parse import urlsplit

NAME = 'compute-node-v1'
PROXY = 'http://192.168.100.3:18443'

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def manifest(starter, digest, binary, relay, broker, key, cdhash, seconds):
    family, host, transport, port, peer, peer_id = relay.strip('/').split('/')
    if family not in ('ip4','ip6') or transport != 'tcp' or peer != 'p2p' or not peer_id:
        raise ValueError('IP TCP relay required')
    url = urlsplit(broker)
    if url.scheme not in ('http','https') or not url.hostname:
        raise ValueError('broker HTTP origin required')
    def endpoint(host, port):
        return {'destination': str(ipaddress.ip_network(ipaddress.ip_address(host))), 'protocol':'tcp', 'port':int(port)}
    broker_ip = socket.gethostbyname(url.hostname)
    m = json.loads(starter.read_bytes())
    service = {'image':'127.0.0.1:5005/compute-node@'+digest, 'entrypoint':['/usr/local/bin/dsmack-compute'],
               'command':['serve',relay,str(seconds),broker,key,cdhash,'/opt/compute-node/worker.py'],
               'environment':{'HTTPS_PROXY':PROXY,'BROKER_IP':broker_ip}, 'read_only':True,
               'volumes':['artifacts:/workspace/artifacts:rw','/var/run/dstack.sock:/var/run/dstack.sock:ro']}
    m.update(name=NAME, allowed_files=[],
             network={'mode':'nat','listen_ports':[], 'egress':[endpoint('192.168.100.3',18443),endpoint(host,port),
                       endpoint(broker_ip,url.port or (443 if url.scheme=='https' else 80))]},
             harness={'name':'compute-node','path':'/usr/local/bin/dsmack-compute',
                      'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'version':'compute-node-1'},
             docker_compose_file=canonical({'services':{'node':service}}).decode(),
             outputs={'capture':[], 'artifacts':[{'name':'registration','path':'/workspace/artifacts/registration'}]})
    m['limits'] = dict(m.get('limits',{}), workspace_max_bytes=256<<20)
    return canonical(m)

if __name__ == '__main__':
    repo,base,starter,oci = map(Path,sys.argv[1:5])
    digest,binary,relay,broker,key,cdhash,out = sys.argv[5:12]
    seconds = int(sys.argv[12]) if len(sys.argv)>12 else 1800
    sys.path.insert(0,str(repo/'dstack-compat'))
    import canary_workload
    output=Path(out);output.mkdir()
    raw=manifest(starter,digest,Path(binary),relay,broker,key,cdhash,seconds)
    (output/'compose-manifest.json').write_bytes(raw)
    canary_workload.pack(repo,base,oci,output/'disk',NAME,raw)
