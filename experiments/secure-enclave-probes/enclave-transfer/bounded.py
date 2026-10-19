"""Bound one local command and its children; no remote calls or shell expansion."""
import os
import signal
import subprocess
import sys

if len(sys.argv) < 3:
    raise SystemExit("usage: bounded.py seconds command [args...]")
seconds = float(sys.argv[1])
if not 0 < seconds <= 90:
    raise SystemExit("seconds must be positive and at most 90")
process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    status = process.wait(timeout=seconds)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    print("bounded command timed out", file=sys.stderr)
    status = 124
raise SystemExit(status if status >= 0 else 128 - status)
