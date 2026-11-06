#!/usr/bin/env python3
"""Install the independent staging health watchdog on zed."""
from pathlib import Path
import subprocess
import sys

app = Path(__file__).resolve().parent
state = Path.home()/'.local/state/dsmack-heartbeat'
state.mkdir(parents=True, exist_ok=True, mode=0o700)
units = Path.home()/'.config/systemd/user'
units.mkdir(parents=True, exist_ok=True)
unit = units/'dsmack-health-staging.service'
unit.write_text(f'''[Unit]
Description=Dsmack independent check heartbeat watchdog
After=network-online.target

[Service]
ExecStart={sys.executable} {app}/heartbeat-watch.py --state {state}/checks.json
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
''')
subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
subprocess.run(['systemctl', '--user', 'enable', '--now', unit.name], check=True)
print('Independent watchdog active; existing zed Alertmanager routes firing/recovery notifications.')
