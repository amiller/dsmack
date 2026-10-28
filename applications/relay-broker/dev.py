#!/usr/bin/env python3
"""Run the webhost handler locally with the real dstack simulator GetKey.

dev.py DSTACK_SOCKET DATA_DIRECTORY [HOST PORT]
Uses the same handler and project GetKey path as webhost.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    data = Path(sys.argv[2]).resolve()
    data.mkdir(parents=True, exist_ok=True)
    env = {'DSTACK_SOCKET': str(Path(sys.argv[1]).resolve())}
    host, port = sys.argv[3:] or ['127.0.0.1', '18270']
    deno = os.environ.get('DENO', str(Path.home() / '.deno/bin/deno'))
    source = Path(__file__).resolve().parent / 'server.ts'
    raise SystemExit(subprocess.run([deno, 'run', '--allow-read', '--allow-write', '--allow-net',
                                    str(source), host, port, str(data)], input=json.dumps(env).encode()).returncode)


if __name__ == '__main__':
    main()
