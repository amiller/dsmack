#!/usr/bin/env python3
"""One edit turn. Inputs/outputs use pipes; all working files and credentials use tmpfs."""
import base64
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace

sys.path[:0] = ['/opt/agent-turns', '/opt/sentinel']
import find
from harness.sentinel.sentinel import SentinelServer
from harness.sentinel.sentinel_oauth import SubscriptionSentinel, load_subscription_credential

PIN = {'cli_version': '2.1.187', 'cli_sha256': 'b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2',
       'model': 'claude-opus-4-8', 'tools': ['Read','Grep','Glob','Edit','Write'], 'max_turns': 8,
       'wall_seconds': 240, 'settings': {'disableAllHooks': True}}
ROOT = Path('/run/dsmack')

def main():
    os.umask(0o077)
    def interrupted(*_):
        raise TimeoutError()
    signal.signal(signal.SIGTERM, interrupted)
    # Refuse a misconfigured writable disk mount before handling any secret.
    if not any(line.split()[1:3] == [str(ROOT.resolve()), 'tmpfs'] for line in Path('/proc/mounts').read_text().splitlines()):
        raise ValueError('compute work root must be tmpfs')
    job = json.load(sys.stdin)
    workroot = ROOT/('job-' + job['job_id'])
    workroot.mkdir()
    os.environ['TMPDIR'] = str(workroot)
    tempfile.tempdir = str(workroot)
    credential = ROOT/'credential'
    server = None
    try:
        credential.write_bytes(find.canonical(job['credential']))
        args = SimpleNamespace(credential_fd=None, credential_file=str(credential), allow_group_readable_credential_file=False,
                               provider_route='https://api.anthropic.com', ca_bundle='/etc/ssl/certs/ca-certificates.crt')
        subscription = load_subscription_credential(args, lambda _: None)
        token = secrets.token_hex(32)
        sentinel = SubscriptionSentinel(job['job_id'], token, args.provider_route, args.ca_bundle, subscription)
        sentinel.log = lambda _: None
        server = SentinelServer(('127.0.0.1', 0), sentinel)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        os.environ['DSMACK_SENTINEL_ENDPOINT'] = f'http://127.0.0.1:{server.server_port}/{token}'
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); inputs = tmp/'inputs'; inputs.mkdir()
            raw = base64.b64decode(job['repo_tar'], validate=True)
            if len(raw) > 16 << 20:
                raise ValueError('repo bound')
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                members = tar.getmembers()
                if sum(m.size for m in members) > 32 << 20 or not all((m.isfile() or m.isdir()) and not m.name.startswith('/')
                        and '..' not in m.name.split('/') and '.git' not in m.name.split('/') for m in members):
                    raise ValueError('repo members')
                tar.extractall(inputs, members)
            outputs = tmp/'outputs'
            spec = {'schema':'dsmack-agent-turn/1', 'state_in':None, 'agent':PIN, 'prompt':job['prompt'], 'inputs_sha256':find.tree_digest(inputs)}
            find.run(spec, inputs, outputs, Path('/usr/local/bin/claude'))
            result = {name:base64.b64encode((outputs/file).read_bytes()).decode() for name,file in
                      [('patch','patch'),('transcript','run-1-transcript'),('verdict','verdict')]}
        sys.stdout.buffer.write(find.canonical(result))
    finally:
        if server:
            server.shutdown(); server.server_close()
        credential.unlink(missing_ok=True)
        shutil.rmtree(workroot)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Task/credential/provider error text must never reach the VM console.
        sys.exit(1)
