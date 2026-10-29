#!/usr/bin/env python3
"""Keep testnet payment keys local while a client uses an SSH loopback forward.

service.py CONFIG FUNDING_KEY STATE_DIR PORT
"""
import http.server
from contextlib import nullcontext
import json
from pathlib import Path
import re
import subprocess
import sys
import threading

config,funding,storage=map(lambda p:Path(p).resolve(),sys.argv[1:4])
port=int(sys.argv[4]);storage.mkdir(mode=0o700,parents=True,exist_ok=True)
cli=Path(__file__).with_name('client.mjs')
mutation=threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):
        pass

    def do_POST(self):
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=200000:
                raise ValueError('request size')
            request=json.loads(self.rfile.read(size));command=request['command'];state_id=request['stateId']
            if not re.fullmatch('[0-9a-f]{64}',state_id):
                raise ValueError('state ID')
            state=storage/state_id;state.mkdir(mode=0o700,exist_ok=True)
            argv=['deno','run','--allow-read','--allow-write','--allow-net','--allow-env',str(cli),command,str(config)]
            if command in ('inspect','check-grant','stop'):
                path=state/(command+'.json');path.write_text(json.dumps(request['value']))
                argv.append(str(path))
                if command=='stop':argv += [str(funding),'--send']
            elif command=='confirm':
                argv.append(str(state/'buyer.json'))
            elif command=='buy':
                if not re.fullmatch('0x[0-9a-fA-F]{64}',request['buyerKey']) or not 1<=int(request['amount'])<=600:
                    raise ValueError('buyer allowance')
                path=state/'node.json';path.write_text(json.dumps(request['node']))
                argv += [str(state/'buyer.json'),str(funding),str(path),request['buyerKey'],request['amount'],'--send']
            elif command=='finish':
                path=state/'receipt.json';path.write_text(json.dumps(request['value']))
                argv += [str(state/'buyer.json'),str(funding),str(path),'--send']
            else:
                raise ValueError('unknown payment command')
            # Funding wallet nonces are serialized; buyer transactions use fresh keys.
            with (mutation if command in ('buy','finish') else nullcontext()):
                result=subprocess.run(argv,capture_output=True,timeout=3700)
            if result.returncode:
                (state/(command+'.log')).write_bytes(result.stderr)
                raise RuntimeError('payment helper failed; inspect its local log')
            value=json.loads(result.stdout);body=json.dumps(value).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(body)
        except (ValueError,KeyError,RuntimeError,subprocess.TimeoutExpired) as exc:
            self.send_response(400);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'error':str(exc)}).encode())

http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
