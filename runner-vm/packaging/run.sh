#!/bin/bash
# run.sh enroll <name> <challenge> | run.sh run <name> <config.json> <image.oci.tar> <input> <challenge> [<host-socket>]
# Challenges are 32-byte files issued by the verifier. MAR_OUT holds captures; MAR_BASE holds vmlinux-arm64 and store/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
abs() { python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$1"; }
mode=${1:?enroll|run}; capture_root="$(abs "${MAR_OUT:?capture root}")"
out="$capture_root/${2:?capture name}"
app="$HERE/build/DsmackRunner.app"
codesign --verify --strict "$app"
if [ "$mode" = enroll ]; then args=(enroll "$out" "$(abs "$3")")
else args=(run "$out" "$(abs "${MAR_BASE:?vm base}")" "$(abs "$3")" "$(abs "$4")" "$(abs "$5")" "$(abs "$6")" "$capture_root/${MAR_ENROLL:?enroll capture name}/keyId.txt" ${7:+"$(abs "$7")"})
fi
logs="$capture_root/$2.launch"; mkdir -p "$logs"
codesign -d --verbose=4 "$app" 2> "$logs/codesign.txt"
open -n -W --stdout "$logs/stdout.txt" --stderr "$logs/stderr.txt" "$app" --args "${args[@]}"
cat "$logs/stderr.txt"
ls "$out"
