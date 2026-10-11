#!/usr/bin/env python3
"""Register an already-signed Mac app with the selected testnet relay.

No Apple credentials or gas key are sent. Registration is only code admission;
live App Attest and recipient consent are still required for NFT claims.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from cd_args import args as code_directory_args


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', type=Path, required=True)
    p.add_argument('--relay', required=True)
    a = p.parse_args()
    app = a.app.resolve()
    subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
    payload = code_directory_args(str(app / 'Contents/MacOS/node'))
    body = json.dumps({k: payload[k] for k in ('cd', 'page0', 'ent')}).encode()
    if len(body) > 65536:
        raise SystemExit('Build evidence exceeds the relay request limit')
    request = urllib.request.Request(a.relay.rstrip('/') + '/register-build', data=body,
                                     headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=150) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Registration rejected: {error.read(4096).decode(errors="replace")}') from None
    print(json.dumps({'cdhash': payload['cdhash'], 'transaction': result['tx'],
                      'next': 'Open this exact app to verify its live attestation and join.'}, indent=2))


if __name__ == '__main__':
    main()
