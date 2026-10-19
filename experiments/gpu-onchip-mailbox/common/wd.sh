#!/usr/bin/env bash
# Independent parent watchdog (macOS bash 3.2 compatible).
# usage: wd.sh <bound_seconds> <cmd> [args...]
# TERM at bound, KILL one second later. Child stdout/stderr are inherited.
# Watchdog messages go to stderr; the child's exit status is propagated.
set -u
bound=$1; shift
"$@" &
pid=$!
( sleep "$bound"; echo "WD: bound ${bound}s reached, sending TERM to $pid" >&2; \
  kill -TERM "$pid" 2>/dev/null; sleep 1; \
  echo "WD: sending KILL to $pid" >&2; kill -KILL "$pid" 2>/dev/null ) &
wd=$!
wait "$pid"
st=$?
kill -TERM "$wd" 2>/dev/null
wait "$wd" 2>/dev/null
echo "WD: child exit status $st (bound ${bound}s)" >&2
exit $st
