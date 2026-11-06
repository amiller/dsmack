#!/usr/bin/env python3
"""Install directory and capacity checks in the current user's crontab."""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess

APP = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--deno', default=shutil.which('deno'))
parser.add_argument('--heartbeat-base', default='http://192.168.100.3:18766', help='zed Nebula HTTP endpoint')
args = parser.parse_args()
deno = args.deno
if not deno:
    raise SystemExit('deno must be installed on the monitoring host')
if not (Path.home()/'.hermes-3090/.env').is_file():
    raise SystemExit('existing on-host Hermes environment is required')
state = Path.home()/'.local/state/dsmack-directory'
state.mkdir(parents=True, exist_ok=True, mode=0o700)
notifier = APP/'directory-notify.sh'
notifier.chmod(0o755)
subprocess.run([deno, 'cache', str(APP/'directory-health.mjs')], check=True)
prior = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
if prior.returncode and not (prior.returncode == 1 and 'no crontab for' in prior.stderr):
    raise SystemExit('could not read existing crontab: '+prior.stderr)
lines = [line for line in prior.stdout.splitlines() if not line.endswith(('# dsmack-directory', '# dsmack-health'))]
for target, project in [('production', 'private-agent'), ('staging', 'private-agent-staging')]:
    for kind, schedule, url in [
        ('directory', '*/5', f'https://pod.dstack.soc1024.com/{project}/config.json'),
        ('capacity', '*', 'https://pod.dstack.soc1024.com/'+project.replace('private-agent','relay-broker')+'/network')]:
        name=target+'-'+kind
        command = [deno, 'run', '--allow-net', '--allow-read', '--allow-write', '--allow-run', '--allow-env',
                   str(APP/'directory-health.mjs'), kind, target, url,
                   str(state/(name+'.json')), str(notifier), args.heartbeat_base+'/ping/'+target+'/'+kind]
        shell = ' '.join(shlex.quote(part) for part in command)
        locked = 'flock -n '+shlex.quote(str(state/(name+'.lock')))+' '+shell
        lines.append(schedule+' * * * * '+locked+' >>'+shlex.quote(str(state/(name+'.log')))+' 2>&1 # dsmack-health')
subprocess.run(['crontab', '-'], input='\n'.join(lines)+'\n', text=True, check=True)
print('Installed directory (5 min) and capacity (1 min) checks with independent heartbeats; state and logs: '+str(state))
