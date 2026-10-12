#!/bin/bash
# Recovery when every holder of the overall group key is gone (no live peer, no usable seal).
# Stops the seed (launchd wrapper and the app process it opened), has the owner call
# startKeyEpoch(0), restarts the agent and waits for `seed ready` at the new epoch.
# usage: seed-recover.sh --rpc URL --registry ADDR --plist AGENT.plist [--host SSH_HOST] [--account NAME]
# The owner signs with PRIVATE_KEY from the environment, or the cast keystore --account.
# --host runs the launchd steps over ssh (SSH_OPTS is passed to ssh); the chain steps run here.
set -euo pipefail
die() { echo "seed-recover: $*" >&2; exit 1; }
args_of() { plutil -extract ProgramArguments json -o - "$1" | python3 -c 'import json,sys;print("\n".join(json.load(sys.stdin)))'; }
after() { args_of "$1" | grep -A1 -xF -- "$2" | sed -n 2p; }
app_of() { args_of "$1" | grep -E '\.app/?$' | head -1; }

if [ "${1:-}" = mac-stop ]; then # plist: bootout the wrapper, then TERM the app process(es) it opened
  plist=$2; label=$(/usr/libexec/PlistBuddy -c 'Print :Label' "$plist"); domain=gui/$(id -u)
  config=$(after "$plist" --args); bundle=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$(app_of "$plist")/Contents/Info.plist")
  ! launchctl print "$domain/$label" >/dev/null 2>&1 || launchctl bootout "$domain/$label"
  pids=()
  for asn in $(lsappinfo find bundleid="$bundle" | grep -oE '0x[0-9a-f]+-0x[0-9a-f]+'); do
    pid=$(lsappinfo info -only pid "ASN:$asn-" | grep -oE 'pid = [0-9]+' | grep -oE '[0-9]+' || true)
    [ -n "$pid" ] && ps -o args= -p "$pid" | grep -qF -- " $config " && pids+=("$pid")
  done
  echo "stopping $label ($bundle) app pids: ${pids[*]:-none}" >&2
  [ ${#pids[@]} -eq 0 ] && exit 0
  kill -TERM "${pids[@]}"
  for _ in $(seq 40); do
    alive=0; for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
    [ $alive = 0 ] && exit 0; sleep 0.5
  done
  die "app process did not exit: ${pids[*]}"
fi
if [ "${1:-}" = mac-start ]; then # plist epoch: bootstrap and wait for `seed ready` at epoch
  plist=$2; epoch=$3; log=$(after "$plist" --stdout); start=$(($( [ -f "$log" ] && wc -c < "$log" || echo 0)+1))
  launchctl bootstrap "gui/$(id -u)" "$plist"
  for _ in $(seq 300); do
    line=$(tail -c +"$start" "$log" 2>/dev/null | grep -E "\"event\":\"seed ready\",\"keyEpoch\":$epoch[,}]" | head -1 || true)
    [ -n "$line" ] && { echo "$line"; exit 0; }; sleep 2
  done
  die "no seed ready at epoch $epoch in $log; see $(tail -n 3 "$log")"
fi

host=; account=; rpc=; registry=; plist=
while [ $# -gt 0 ]; do
  case $1 in --rpc) rpc=$2;; --registry) registry=$2;; --plist) plist=$2;; --host) host=$2;; --account) account=$2;;
    *) die "unknown argument $1";; esac; shift 2
done
[ -n "$rpc" ] && [ -n "$registry" ] && [ -n "$plist" ] || die "need --rpc, --registry and --plist"
if [ -n "$account" ]; then signer=(--account "$account"); else signer=(--private-key "${PRIVATE_KEY:?PRIVATE_KEY or --account required}"); fi
mac() { if [ -n "$host" ]; then ssh ${SSH_OPTS:-} "$host" "bash -s -- $(printf '%q ' "$@")" < "$0"; else bash "$0" "$@"; fi; }
zero=0x0000000000000000000000000000000000000000000000000000000000000000
before=$(cast call --rpc-url "$rpc" "$registry" 'keyEpochs(bytes32)(uint64)' $zero)
mac mac-stop "$plist"
cast send --rpc-url "$rpc" "${signer[@]}" "$registry" 'startKeyEpoch(bytes32)' $zero >&2
epoch=$(cast call --rpc-url "$rpc" "$registry" 'keyEpochs(bytes32)(uint64)' $zero)
[ "$epoch" = $((before+1)) ] || die "keyEpochs(0) is $epoch, expected $((before+1))"
echo "keyEpochs(0) $before -> $epoch; restarting seed" >&2
mac mac-start "$plist" "$epoch"
