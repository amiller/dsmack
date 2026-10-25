"""Run the guest sentinel unchanged, appending every request and response it handles to the chain.

usage: sentinel_rec.py --dashcam DIR --sentinel-source DIR <sentinel arguments>
"""
import argparse
import sys

from dashcam import Chain

parser = argparse.ArgumentParser()
parser.add_argument('--dashcam', required=True)
parser.add_argument('--sentinel-source', required=True)
args, rest = parser.parse_known_args()
sys.path.insert(0, args.sentinel_source)
from harness.sentinel import sentinel  # noqa: E402

chain = Chain(args.dashcam)
handle = sentinel.RunSentinel.handle


def recorded(self, method, raw_path, headers, body):
    path = sentinel._redact_path(raw_path, self.token.decode())
    kept = {k: v for k, v in headers.items() if k.lower() not in sentinel.CREDENTIAL_HEADERS}
    chain.append('sentinel', 'request', body or b'', {'method': method, 'path': path, 'headers': kept})
    status, hdrs, payload = handle(self, method, raw_path, headers, body)
    chain.append('sentinel', 'response', payload, {'path': path, 'status': status, 'headers': dict(hdrs)})
    return status, hdrs, payload


sentinel.RunSentinel.handle = recorded
sys.exit(sentinel.main(rest))
