"""Basescan verification from a full forge compilation unit. via-IR output depends on which sources
share the unit, so `forge verify-contract` (minimal source set) does not reproduce the adapters' bytecode.
Usage (in contracts/, ETHERSCAN_API_KEY in env): verify_standard_json.py <build-info id> <address> <path:Name> <ctor args hex>"""
import json, os, subprocess, sys, time, urllib.parse, urllib.request
bi, address, name, ctor = sys.argv[1:5]
paths = json.load(open(f'out/build-info/{bi}.json'))['source_id_to_path'].values()
settings = json.loads(subprocess.run(['forge', 'verify-contract', address, name, '--chain', 'base-sepolia', '--show-standard-json-input'],
                                     capture_output=True, text=True, check=True).stdout)['settings']
source = json.dumps({'language': 'Solidity', 'sources': {p: {'content': open(p).read()} for p in paths}, 'settings': settings})
url = 'https://api.etherscan.io/v2/api?chainid=84532'
def api(fields):
    fields['apikey'] = os.environ['ETHERSCAN_API_KEY']
    return json.loads(urllib.request.urlopen(url, urllib.parse.urlencode(fields).encode()).read())
r = api({'module': 'contract', 'action': 'verifysourcecode', 'codeformat': 'solidity-standard-json-input', 'sourceCode': source,
         'contractaddress': address, 'contractname': name, 'compilerversion': 'v0.8.21+commit.d9974bed', 'constructorArguements': ctor})
assert r['status'] == '1', r
for _ in range(20):
    time.sleep(10); s = api({'module': 'contract', 'action': 'checkverifystatus', 'guid': r['result']})
    print(s['result'], flush=True)
    if 'Pending' not in s['result']: break
