#!/usr/bin/env python3
"""Run on a Linux Docker builder; owns only this Compose project's resources."""
import ipaddress
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent
EVIDENCE = ROOT / 'evidence'
PROJECT = 'dsmack-egress-policy-20261027'
IMAGE = PROJECT + ':prototype'


def run(*args, input=None, check=True):
    p = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
    if check and p.returncode:
        raise RuntimeError(' '.join(args) + '\n' + p.stdout)
    return p


def docker(*args, **kw):
    return run('docker', *args, **kw)


def compose(*args):
    return docker('compose', '-p', PROJECT, '-f', str(ROOT / 'demo-compose.json'), *args)


def firewall(container, rules, image):
    # Helper shares only the target network namespace, never the host's.
    docker('run', '--rm', '--network', 'container:' + container, '--cap-drop', 'ALL',
           '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges', '--read-only',
           '--user', '0', '--entrypoint', 'nft', '-i', image, '-f', '-', input=rules)


def listing(container, image):
    return docker('run', '--rm', '--network', 'container:' + container, '--cap-drop', 'ALL',
                  '--cap-add', 'NET_ADMIN', '--read-only', '--user', '0', '--entrypoint', 'nft',
                  image, '-a', 'list', 'table', 'inet', 'dsmack_egress').stdout


def main():
    EVIDENCE.mkdir(exist_ok=True)
    before = docker('image', 'inspect', IMAGE, '--format', '{{.Size}}').stdout
    ids = docker('network', 'ls', '-q').stdout.split()
    networks = json.loads(docker('network', 'inspect', *ids).stdout) if ids else []
    used = [ipaddress.ip_network(c['Subnet']) for n in networks for c in (n.get('IPAM', {}).get('Config') or []) if c.get('Subnet')]
    subnet = next(ipaddress.ip_network('172.30.%d.0/24' % n) for n in range(227, 255)
                  if not any(ipaddress.ip_network('172.30.%d.0/24' % n).overlaps(x) for x in used if x.version == 4))
    gateway, client = str(subnet[2]), str(subnet[3])
    image = docker('image', 'inspect', IMAGE, '--format', '{{.Id}}').stdout.strip()
    policy = (ROOT / 'policy.json').read_text()
    for name, contents in [('workload-resolver.conf', f'nameserver {gateway}\noptions timeout:1 attempts:1\n'), ('gateway-resolver.conf', 'nameserver 1.1.1.1\noptions timeout:1 attempts:2\n')]:
        resolver = ROOT / name
        resolver.unlink(missing_ok=True)
        resolver.write_text(contents)
        resolver.chmod(0o444)
    doc = {
        'services': {
            'gateway': {'image': image, 'command': ['-policy', '/policy.json', '-answer-ip', gateway],
                        'user': '65532:65532', 'cap_drop': ['ALL'],
                        'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'pids_limit': 64,
                        'configs': [{'source': 'policy', 'target': '/policy.json'}],
                        'volumes': [f'{ROOT}/gateway-resolver.conf:/etc/resolv.conf:ro'],
                        'networks': {'private': {'ipv4_address': gateway}, 'uplink': {}}},
            'workload': {'image': image, 'entrypoint': ['python3', '-c', 'import time; time.sleep(600)'],
                         'user': '65532:65532', 'cap_drop': ['ALL'],
                         'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'pids_limit': 32,
                         'dns': [gateway], 'read_only': True, 'volumes': [f'{ROOT}/workload-resolver.conf:/etc/resolv.conf:ro'], 'networks': {'private': {'ipv4_address': client}}}},
        'configs': {'policy': {'content': policy}},
        'networks': {'private': {'internal': True, 'ipam': {'config': [{'subnet': str(subnet)}]}}, 'uplink': {}}}
    (ROOT / 'demo-compose.json').write_text(json.dumps(doc, indent=2) + '\n')
    (EVIDENCE / 'compose.json').write_text(json.dumps(doc, indent=2) + '\n')
    gateway_id = workload_id = None
    try:
        compose('up', '-d', '--pull', 'never')
        gateway_id = compose('ps', '-q', 'gateway').stdout.strip()
        workload_id = compose('ps', '-q', 'workload').stdout.strip()
        # Priority -300 precedes Docker's embedded-DNS output DNAT (-100).
        # No loopback exception: 127.0.0.11 would otherwise bypass the stub.
        workload_rules = f'''table inet dsmack_egress {{
 chain output {{ type filter hook output priority -300; policy drop;
  ip daddr {gateway} tcp dport {{ 53, 8080 }} counter accept
  ip daddr {gateway} udp dport 53 counter accept
  udp dport 443 counter drop comment "quic denied"
  counter drop
 }}
 chain input {{ type filter hook input priority -300; policy drop;
  ip saddr {gateway} ct state established counter accept
 }}
 chain forward {{ type filter hook forward priority -300; policy drop; }}
}}'''
        gateway_rules = f'''table inet dsmack_egress {{
 chain output {{ type filter hook output priority -150; policy drop;
  ct direction reply ct state established counter accept
  ip daddr 1.1.1.1 udp dport 53 counter accept
  ip daddr 1.1.1.1 tcp dport 53 counter accept
  tcp dport 443 counter accept
  counter drop
 }}
 chain input {{ type filter hook input priority -300; policy drop;
  ct direction reply ct state established counter accept
  ip saddr {client} tcp dport {{ 53, 8080 }} counter accept
  ip saddr {client} udp dport 53 counter accept
  counter drop
 }}
 chain forward {{ type filter hook forward priority -300; policy drop; }}
}}'''
        firewall(workload_id, workload_rules, image)
        firewall(gateway_id, gateway_rules, image)
        # Observer has no workload data; records two valid names on one edge IP.
        observed = docker('run', '--rm', '--network', PROJECT + '_uplink', '--cap-drop', 'ALL',
                          '--read-only', '--memory', '128m', '--pids-limit', '32',
                          '--entrypoint', 'python3', image, '/probe.py', 'observer').stdout
        (EVIDENCE / 'shared-ip.jsonl').write_text(observed)
        shared_ip = json.loads(observed.splitlines()[0])['ip']
        result = docker('exec', workload_id, 'python3', '/probe.py', gateway, shared_ip, 'www.cloudflare.com', check=False)
        (EVIDENCE / 'docker-checks.jsonl').write_text(result.stdout)
        print(result.stdout, end='')
        if result.returncode:
            raise RuntimeError('workload checks failed')
        rules = listing(workload_id, image)
        (EVIDENCE / 'workload-nft.txt').write_text(rules)
        # Confirm a real UDP packet hit the deny rule, beyond client timeout.
        import re
        assert re.search(r'udp dport 443 counter packets [1-9]\d* bytes \d+ drop', rules), rules
        (EVIDENCE / 'gateway-nft.txt').write_text(listing(gateway_id, image))
    finally:
        if gateway_id:
            (EVIDENCE / 'gateway.log').write_text(docker('logs', gateway_id, check=False).stdout)
        result = compose('down', '--volumes', '--remove-orphans')
        (EVIDENCE / 'cleanup.txt').write_text(result.stdout + '\n' + docker('ps', '-a', '--filter', 'label=com.docker.compose.project=' + PROJECT).stdout + '\nBefore:\n' + before + '\nAfter:\n' + docker('image', 'inspect', IMAGE, '--format', '{{.Size}}').stdout)
    print('Docker checks PASS; project containers and networks removed')


if __name__ == '__main__':
    main()
