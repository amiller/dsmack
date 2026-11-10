#!/usr/bin/env python3
"""Watch check deadlines independently and send alerts to the existing Alertmanager."""
import argparse
from datetime import datetime, timezone
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import threading
import time
from urllib.request import Request, urlopen

DEADLINES = {'capacity': 180, 'directory': 420}


def timestamp(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


class Watch:
    def __init__(self, state, notify, now=time.time):
        self.state, self.notify, self.now = state, notify, now
        self.lock = threading.Lock()
        try: self.checks = json.loads(state.read_text())
        except FileNotFoundError: self.checks = {}

    def save(self):
        temporary = self.state.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.checks)+'\n')
        temporary.chmod(0o600)
        temporary.replace(self.state)

    def ping(self, name):
        with self.lock:
            record = self.checks.setdefault(name, {'alerted': False, 'last_sent': 0})
            record['last_ping'] = self.now()
            self.save()

    def remove_proof(self, name):
        if not name.startswith('staging-proof/'):
            raise ValueError('only staging-proof checks may be removed')
        with self.lock:
            if self.checks.get(name, {}).get('alerted'):
                raise ValueError('recover the proof check before removing it')
            self.checks.pop(name, None)
            self.save()

    def tick(self):
        with self.lock:
            now = self.now()
            for name, record in self.checks.items():
                target, kind = name.split('/')
                deadline = DEADLINES[kind]
                late = now - record['last_ping'] > deadline
                if (late and (not record['alerted'] or now-record['last_sent'] >= 30)
                        or not late and record['alerted']):
                    alert = {
                        'labels': {'alertname': 'DsmackHealthcheckMissing', 'target': target,
                                   'check': kind, 'severity': 'warning'},
                        'annotations': {'summary': f'Dsmack {target} {kind} monitor heartbeat missing',
                                        'description': f'No completed check for {deadline} seconds; independent zed watchdog.'},
                        'startsAt': timestamp(record.get('outage_started', record['last_ping']+deadline)),
                        'endsAt': timestamp(now+120 if late else now),
                    }
                    self.notify(alert)
                    if late: record.setdefault('outage_started', record['last_ping']+deadline)
                    else: record.pop('outage_started', None)
                    record.update(alerted=late, last_sent=now)
                    self.save()
                    print(json.dumps({'event': 'heartbeat_missing' if late else 'heartbeat_recovered',
                                      'check': name, 'at': now}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', default='192.168.100.3', help='zed Nebula interface')
    parser.add_argument('--port', type=int, default=18766)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--alertmanager', default='http://127.0.0.1:9094')
    args = parser.parse_args()
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def notify(alert):
        request = Request(args.alertmanager+'/api/v2/alerts', json.dumps([alert]).encode(),
                          {'Content-Type': 'application/json'}, method='POST')
        with urlopen(request, timeout=10) as response:
            if response.status != 200: raise RuntimeError('Alertmanager HTTP '+str(response.status))

    watch = Watch(args.state, notify)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass

        def heartbeat(self, remove=False):
            # Pings use the authenticated Nebula overlay, without distributing
            # another bearer credential between the monitoring hosts.
            peer = ipaddress.ip_address(self.client_address[0])
            parts = self.path.split('/')
            if not (peer.is_loopback or peer in ipaddress.ip_network('192.168.100.0/24')):
                self.send_error(403); return
            if len(parts) != 4 or parts[1] != 'ping' or parts[2] not in ('production', 'staging', 'staging-proof') or parts[3] not in DEADLINES:
                self.send_error(404); return
            name = '/'.join(parts[2:])
            try:
                if remove: watch.remove_proof(name)
                else: watch.ping(name)
            except ValueError as error:
                self.send_error(409, str(error)); return
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok\n')

        def do_POST(self): self.heartbeat()
        def do_DELETE(self): self.heartbeat(remove=True)

    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        try: watch.tick()
        except (OSError, HTTPException) as error:
            print(json.dumps({'event': 'heartbeat_notification_failed', 'error': str(error)}), flush=True)
        time.sleep(15)


if __name__ == '__main__':
    main()
