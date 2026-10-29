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
import subprocess
import time
import socket
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit
import inference_provider

sys.path[:0] = ['/opt/agent-turns', '/opt/sentinel']
import find
from harness.sentinel.sentinel import SentinelServer
from harness.sentinel.sentinel_oauth import SubscriptionSentinel, load_subscription_credential

PIN = {'cli_version': '2.1.187', 'cli_sha256': 'b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2',
       'model': os.environ['MODEL'], 'tools': ['Read','Grep','Glob','Edit','Write'], 'max_turns': 8,
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
    proxy = urlsplit(os.environ['HTTPS_PROXY'])
    proxy_port = proxy.port or 80
    blocked_port = 18080 if proxy_port != 18080 else 18081
    probes = {}
    for host, port in [('1.1.1.1', 443), (proxy.hostname, blocked_port), (proxy.hostname, proxy_port)]:
        try:
            with socket.create_connection((host, port), timeout=3):
                probes[f'{host}:{port}'] = 'connected'
        except OSError:
            probes[f'{host}:{port}'] = 'refused'
    Path('/workspace/artifacts/egress').write_bytes(find.canonical(probes))
    job = json.load(sys.stdin)
    workroot = ROOT/('job-' + job['job_id'])
    workroot.mkdir()
    os.environ['TMPDIR'] = str(workroot)
    tempfile.tempdir = str(workroot)
    credential = ROOT/'credential'
    server = None
    gateway = None
    gateway_log = None
    try:
        credential.write_bytes(find.canonical(job['credential']))
        credential.chmod(0o400)
        provider = json.loads(os.environ['INFERENCE_PROVIDER']) if 'INFERENCE_PROVIDER' in os.environ else None
        if provider is not None:
            inference_provider.validate_credential(job['credential'])
            policy_path = workroot/'gateway-policy.json'
            policy_path.write_bytes(find.canonical(inference_provider.gateway_policy(provider)))
            gateway_log = (workroot/'gateway.jsonl').open('wb')
            gateway = subprocess.Popen(['/usr/local/bin/dsmack-egress', '-policy', str(policy_path),
                '-http', '127.0.0.1:8080', '-dns', '', '-upstream-timeout', '120s', '-upstream-proxy', os.environ['HTTPS_PROXY']],
                stdout=gateway_log, stderr=subprocess.DEVNULL)
            for _ in range(100):
                if gateway.poll() is not None:
                    raise ValueError('guest egress gateway exited')
                try:
                    with socket.create_connection(('127.0.0.1', 8080), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise ValueError('guest egress gateway not ready')
        else:
            args = SimpleNamespace(credential_fd=None, credential_file=str(credential), allow_group_readable_credential_file=False,
                                   provider_route='https://api.anthropic.com', ca_bundle='/etc/ssl/certs/ca-certificates.crt')
            subscription = load_subscription_credential(args, lambda _: None)
            if subscription.refreshable:
                token = secrets.token_hex(32)
                sentinel = SubscriptionSentinel(job['job_id'], token, args.provider_route, args.ca_bundle, subscription)
                sentinel.log = lambda _: None
                server = SentinelServer(('127.0.0.1', 0), sentinel)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                os.environ['DSMACK_SENTINEL_ENDPOINT'] = f'http://127.0.0.1:{server.server_port}/{token}'
            else:
                os.environ['DSMACK_SENTINEL_ENDPOINT'] = args.provider_route
                os.environ['CLAUDE_CODE_OAUTH_TOKEN'] = subscription.access_token
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
            if provider is None:
                find.run(spec, inputs, outputs, Path('/usr/local/bin/claude'))
            else:
                inference_provider.run(provider, job['credential'], job['prompt'], inputs, outputs)
                gateway.terminate(); gateway.wait(timeout=5); gateway = None
                gateway_log.close(); gateway_log = None
                with (outputs/'run-1-transcript').open('ab') as transcript:
                    for line in (workroot/'gateway.jsonl').read_bytes().splitlines():
                        transcript.write(find.canonical({'type': 'gateway_event', 'event': json.loads(line)}) + b'\n')
            result = {name:base64.b64encode((outputs/file).read_bytes()).decode() for name,file in
                      [('patch','patch'),('transcript','run-1-transcript'),('verdict','verdict')]}
        sys.stdout.buffer.write(find.canonical(result))
    finally:
        if gateway:
            gateway.terminate(); gateway.wait(timeout=5)
        if gateway_log:
            gateway_log.close()
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
