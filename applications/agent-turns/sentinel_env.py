#!/usr/bin/env python3
"""The turn's `sentinel` service: the credential sentinel (base-vm/.../guest/sentinel) for the agent's model calls.

The credential and the per-run token arrive as private env values that only this service receives. The credential
goes to sentinel.py on a pipe and leaves this process's environment before the exec.
"""
import os
import sys

credential = os.environ.pop('SENTINEL_CREDENTIAL').encode()
token = os.environ.pop('SENTINEL_TOKEN')
r, w = os.pipe()
os.write(w, credential)
os.close(w)
os.set_inheritable(r, True)
os.execv(sys.executable, [sys.executable, '-I', '-B', '/opt/sentinel/harness/sentinel/sentinel.py', '--run-id', 'turn',
                          '--token', token, '--listen-port', '8100', '--provider-route', 'https://api.anthropic.com',
                          '--ca-bundle', '/etc/ssl/certs/ca-certificates.crt', '--auth-mode', 'claude-subscription',
                          '--credential-fd', str(r)])
