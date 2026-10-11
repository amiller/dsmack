#!/bin/bash
# Collect the app's persistent documents after an operator-run device experiment.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
lab_run=${1:?Usage: collect_device.sh EXISTING_RUN_ID}
[[ "$lab_run" =~ ^[A-Za-z0-9_-]+$ ]] || exit 2
: "${LAB_DEVICE_ID:?Set LAB_DEVICE_ID}"
: "${LAB_BUNDLE_ID:?Set LAB_BUNDLE_ID}"
: "${LAB_DATABASE:?Set the verifier database path on this Mac}"
lab_run_dir="$lab_root/captures/$lab_run"
[[ -f "$lab_run_dir/manifest.json" ]] || { echo 'No saved build for this run' >&2; exit 2; }
[[ ! -e "$lab_run_dir/phone-documents" && ! -e "$lab_run_dir/server.json" ]] || {
  echo 'Capture already exists; keep it and use a distinct run for another capture' >&2; exit 2;
}
xcrun devicectl device copy from --device "$LAB_DEVICE_ID" --domain-type appDataContainer \
  --domain-identifier "$LAB_BUNDLE_ID" --source Documents --destination "$lab_run_dir/phone-documents" \
  --json-output "$lab_run_dir/copy.json"
cd "$lab_root"
.venv/bin/python -m verifier.export "$LAB_DATABASE" "$lab_run_dir/server.json"
echo "Saved phone captures and server evidence in $lab_run_dir"
