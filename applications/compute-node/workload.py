#!/usr/bin/env python3
"""Pack a compute OCI layout into a v0.2 workload with an explicit direct-IP or Mac hostname-gateway route.

workload.py REPO BASE STARTER OCI_DIR DIGEST BINARY RELAY BROKER BROKER_KEY CDHASH PROXY OUT [SECONDS [PAYMENTS_JSON [PROVIDER_JSON [TUNNEL_INDEX [OPERATOR_JSON]]]]]
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

def manifest(starter, digest, binary, relay, broker, key, cdhash, seconds, proxy, payments=None, provider=None, admit_seconds=None, *, tunnel_index=None, guest=None):
    parts = relay.strip('/').split('/')
    mac = len(parts) == 7 and parts[:6] == ['ip4','127.0.0.1','tcp','18082','ws','p2p'] and bool(parts[6])
    if not mac:
        if len(parts) != 6:
            raise ValueError('IP TCP relay or Mac loopback WebSocket relay required')
        family, host, transport, port, peer, peer_id = parts
        if family not in ('ip4','ip6') or transport != 'tcp' or peer != 'p2p' or not peer_id:
            raise ValueError('IP TCP relay required')
        if tunnel_index is not None:
            raise ValueError('tunnel index requires the Mac WebSocket relay')
    url = urlsplit(broker)
    if url.scheme not in ('http','https') or not url.hostname:
        raise ValueError('broker HTTP origin required')
    def endpoint(host, port):
        return {'destination': str(ipaddress.ip_network(ipaddress.ip_address(host))), 'protocol':'tcp', 'port':int(port)}
    proxy_url = urlsplit(proxy)
    if proxy_url.scheme != 'http' or not proxy_url.hostname or not proxy_url.port:
        raise ValueError('HTTP proxy with an IP address required')
    proxy_endpoint = endpoint(proxy_url.hostname, proxy_url.port)
    if mac:
        index = urlsplit(tunnel_index or '')
        if (url.scheme != 'https' or url.port not in (None,443) or url.username or url.password or url.query or url.fragment
                or index.scheme != 'https' or index.hostname != url.hostname or index.port not in (None,443)
                or index.username or index.password or not index.path.startswith('/') or index.query or index.fragment):
            raise ValueError('Mac mode requires a same-host HTTPS broker and tunnel index')
        if proxy != 'http://192.168.127.254:18484':
            raise ValueError('Mac mode requires the host-loopback CONNECT proxy')
        environment = {'HTTPS_PROXY':proxy,'BROKER_GATEWAY':'http://127.0.0.1:18080','TUNNEL_INDEX':tunnel_index}
        egress = [proxy_endpoint]
    else:
        broker_ip = socket.gethostbyname(url.hostname)
        environment = {'HTTPS_PROXY':proxy,'BROKER_IP':broker_ip}
        egress = [proxy_endpoint,endpoint(host,port),endpoint(broker_ip,url.port or (443 if url.scheme=='https' else 80))]
    guest = guest or {'mem_mib': 4096, 'vcpus': 1}
    if any(type(guest.get(k)) is not int or guest[k] < 1 for k in ('mem_mib', 'vcpus')):
        raise ValueError('guest mem_mib and vcpus must be positive integers')
    m = json.loads(starter.read_bytes())
    m['base_vm'].update(memory_mb=guest['mem_mib'], vcpus=guest['vcpus'])
    service = {'image':'127.0.0.1:5005/compute-node@'+digest, 'entrypoint':['/usr/local/bin/dsmack-compute'],
               'command':['serve',relay,str(seconds),broker,key,cdhash,'/opt/compute-node/agent-mcp.mjs'],
               'environment':environment | {'AGENT_MCP_SOCKET':'/run/dsmack/agent-mcp.sock',
                   'AGENT_COMMAND_TIMEOUT_SECONDS':'120','AGENT_OUTPUT_CAP_BYTES':'51200',
                   'AGENT_RAW_OUTPUT_CAP_BYTES':'1048576','AGENT_IDLE_TIMEOUT_SECONDS':'300',
                   'AGENT_PI_VERSION':'1.4.0','AGENT_MCP_VERSION':'2026-07-28',
                   'DSTACK_SOCKET':'/root/dstack.sock','AGENT_CONFINEMENT':'readonly-rootfs-uid1000-workspace-tmpfs',
                   'AGENT_NETWORK_ALLOWLIST':canonical([url.hostname, 'attested relay hostname from '+tunnel_index] if mac else [url.hostname]).decode()},
               'read_only':True, 'security_profile':'agent-sandbox-v1',
               'volumes':['artifacts:/workspace/artifacts:rw','/var/run/dstack.sock:/var/run/dstack.sock:ro']}
    if not 1 <= seconds <= 840:
        raise ValueError('compute lifetime must be 1..840 seconds')
    admit_seconds = max(1, seconds - 270) if admit_seconds is None else admit_seconds
    if not 1 <= admit_seconds < seconds:
        raise ValueError('admission cutoff must precede compute lifetime')
    service['environment']['ADMIT_SECONDS'] = str(admit_seconds)
    if provider is not None:
        from inference_provider import validate_config
        provider = validate_config(provider)
        if provider['base_url'].rstrip('/') != broker.rstrip('/') or provider['broker_key'] != key:
            raise ValueError('inference capability must use the measured node broker and key')
        # Model inference stays in the browser. Keep validating an existing
        # pool packer's provider input while it migrates to the MCP workload.
    artifacts = ['registration', 'last-result', 'egress', 'agent-receipts']
    if mac:
        artifacts += ['egress-checks','gateway-log']
    if payments is not None:
        service['environment']['PAYMENTS_CONFIG'] = canonical(payments).decode()
        artifacts.append('payment-receipts')
    m.update(name=NAME, allowed_files=[],
             network={'mode':'nat','listen_ports':[], 'egress':egress},
             harness={'name':'compute-node','path':'/usr/local/bin/dsmack-compute',
                      'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'version':'compute-node-1'},
             docker_compose_file=canonical({'services':{'node':service}}).decode(),
             outputs={'capture':['stderr'], 'artifacts':[
                 *[{'name':n,'path':'/workspace/artifacts/'+n} for n in artifacts],
                 {'name':'tool-server-log','path':'/workspace/artifacts/tool-server.log'}]})
    m['limits'] = dict(m.get('limits',{}), timeout_s=seconds, workspace_max_bytes=256<<20)
    return canonical(m)

if __name__ == '__main__':
    repo,base,starter,oci = map(Path,sys.argv[1:5])
    digest,binary,relay,broker,key,cdhash,proxy,out = sys.argv[5:13]
    seconds = int(sys.argv[13]) if len(sys.argv)>13 else 840
    payments = json.loads(Path(sys.argv[14]).read_bytes()) if len(sys.argv)>14 else None
    provider = json.loads(Path(sys.argv[15]).read_bytes()) if len(sys.argv)>15 else None
    tunnel_index = sys.argv[16] if len(sys.argv)>16 else None
    guest = json.loads(Path(sys.argv[17]).read_bytes())['guest'] if len(sys.argv)>17 else None
    sys.path.insert(0,str(repo/'dstack-compat'))
    import canary_workload
    output=Path(out);output.mkdir()
    raw=manifest(starter,digest,Path(binary),relay,broker,key,cdhash,seconds,proxy,payments,provider,tunnel_index=tunnel_index,guest=guest)
    (output/'compose-manifest.json').write_bytes(raw)
    canary_workload.pack(repo,base,oci,output/'disk',NAME,raw)
