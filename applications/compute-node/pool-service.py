#!/usr/bin/env python3
"""Write, install or uninstall a launchd user agent for a Mac pool command."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('write', 'install', 'uninstall', 'run'))
    parser.add_argument('--label', default='org.dsmack.pool.staging')
    parser.add_argument('--root', type=Path, required=True, help='dedicated pool generations and launchd logs')
    parser.add_argument('--command', type=Path, required=True, help='Mac-local JSON argv, without --state or adoption')
    args = parser.parse_args()
    root, command_path = args.root.resolve(), args.command.resolve()
    label = args.label
    if not label.startswith('org.dsmack.pool.') or '/' in label:
        parser.error('label must start with org.dsmack.pool. and contain no slash')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = json.loads(command_path.read_text())
    if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
        parser.error('command must be a JSON argv array')
    if any(arg.split('=', 1)[0] in ('--state', '--adopt-launcher') for arg in command):
        parser.error('service owns fresh state directories; remove --state and --adopt-launcher')
    if args.action == 'run':
        state = root / ('pool-'+str(time.time_ns()))
        os.execv(command[0], command + ['--state', str(state)])
    plist = Path.home()/'Library/LaunchAgents'/(label+'.plist')
    domain = 'gui/'+str(os.getuid())
    if args.action == 'uninstall':
        subprocess.run(['launchctl', 'bootout', domain+'/'+label], check=True)
        plist.unlink()
        return
    definition = dict(Label=label, RunAtLoad=True, KeepAlive=True, ThrottleInterval=60,
                      ExitTimeOut=4400, WorkingDirectory=str(root),
                      ProgramArguments=[sys.executable, str(Path(__file__).resolve()), 'run',
                                        '--label', label, '--root', str(root), '--command', str(command_path)],
                      StandardOutPath=str(root/'launchd.stdout.log'),
                      StandardErrorPath=str(root/'launchd.stderr.log'),
                      EnvironmentVariables={'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'})
    plist.parent.mkdir(parents=True, exist_ok=True)
    with plist.open('wb') as stream:
        plistlib.dump(definition, stream)
    print(plist)
    if args.action == 'install':
        subprocess.run(['launchctl', 'enable', domain+'/'+label], check=True)
        subprocess.run(['launchctl', 'bootstrap', domain, str(plist)], check=True)


if __name__ == '__main__':
    main()
