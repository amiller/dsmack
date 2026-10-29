#!/usr/bin/env python3
"""Pack a compute OCI layout into a v0.2 workload with three fixed egress endpoints.

workload.py REPO BASE STARTER OCI_DIR DIGEST BINARY RELAY BROKER BROKER_KEY CDHASH PROXY OUT [SECONDS [PAYMENTS_JSON]]
"""
import hashlib
import ipaddress
import json
import socket
from pathlib import Path
import sys
from urllib.parse import urlsplit

NAME = 'compute-node-v1'

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def manifest(starter, digest, binary, relay, broker, key, cdhash, seconds, proxy, payments=None):
    family, host, transport, port, peer, peer_id = relay.strip('/').split('/')
    if family not in ('ip4','ip6') or transport != 'tcp' or peer != 'p2p' or not peer_id:
        raise ValueError('IP TCP relay required')
    url = urlsplit(broker)
    if url.scheme not in ('http','https') or not url.hostname:
        raise ValueError('broker HTTP origin required')
    def endpoint(host, port):
        return {'destination': str(ipaddress.ip_network(ipaddress.ip_address(host))), 'protocol':'tcp', 'port':int(port)}
    proxy_url = urlsplit(proxy)
    if proxy_url.scheme != 'http' or not proxy_url.hostname or not proxy_url.port:
        raise ValueError('HTTP proxy with an IP address required')
    proxy_endpoint = endpoint(proxy_url.hostname, proxy_url.port)
    broker_ip = socket.gethostbyname(url.hostname)
    m = json.loads(starter.read_bytes())
    service = {'image':'127.0.0.1:5005/compute-node@'+digest, 'entrypoint':['/usr/local/bin/dsmack-compute'],
               'command':['serve',relay,str(seconds),broker,key,cdhash,'/opt/compute-node/worker.py'],
               'environment':{'HTTPS_PROXY':proxy,'BROKER_IP':broker_ip,'MODEL':'claude-opus-4-8'}, 'read_only':True,
               'volumes':['artifacts:/workspace/artifacts:rw','/var/run/dstack.sock:/var/run/dstack.sock:ro']}
    artifacts = ['registration', 'last-result', 'egress']
    if payments is not None:
        service['environment']['PAYMENTS_CONFIG'] = canonical(payments).decode()
        artifacts.append('payment-receipts')
    m.update(name=NAME, allowed_files=[],
             network={'mode':'nat','listen_ports':[], 'egress':[proxy_endpoint,endpoint(host,port),
                       endpoint(broker_ip,url.port or (443 if url.scheme=='https' else 80))]},
             harness={'name':'compute-node','path':'/usr/local/bin/dsmack-compute',
                      'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'version':'compute-node-1'},
             docker_compose_file=canonical({'services':{'node':service}}).decode(),
             outputs={'capture':[], 'artifacts':[{'name':n,'path':'/workspace/artifacts/'+n} for n in artifacts]})
    m['limits'] = dict(m.get('limits',{}), timeout_s=seconds, workspace_max_bytes=256<<20)
    return canonical(m)

if __name__ == '__main__':
    repo,base,starter,oci = map(Path,sys.argv[1:5])
    digest,binary,relay,broker,key,cdhash,proxy,out = sys.argv[5:13]
    seconds = int(sys.argv[13]) if len(sys.argv)>13 else 1800
    payments = json.loads(Path(sys.argv[14]).read_bytes()) if len(sys.argv)>14 else None
    sys.path.insert(0,str(repo/'dstack-compat'))
    import canary_workload
    output=Path(out);output.mkdir()
    raw=manifest(starter,digest,Path(binary),relay,broker,key,cdhash,seconds,proxy,payments)
    (output/'compose-manifest.json').write_bytes(raw)
    canary_workload.pack(repo,base,oci,output/'disk',NAME,raw)
