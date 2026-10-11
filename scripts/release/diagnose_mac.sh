#!/bin/bash
# Local read-only checks; prints no App Attest IDs, proof blobs or profile contents.
# Usage: bash diagnose_mac.sh /path/to/Node.app [participant-state-basename]
set -u
app=${1:-}
if [[ -z "$app" ]]; then
  app=$(/usr/bin/osascript -e 'POSIX path of (choose application with prompt "Choose the downloaded AttestNode (Node.app)")') || exit 1
fi
[[ -d "$app/Contents" ]] || { echo 'Choose the Node.app bundle, not its ZIP.'; exit 1; }
/usr/bin/sw_vers
/usr/bin/uname -m
/usr/bin/csrutil status
/usr/bin/csrutil authenticated-root status
/usr/sbin/spctl --status
printf '\nApp signature verification:\n'
/usr/bin/codesign --verify --deep --strict "$app" 2>&1
printf 'codesign exit: %s\n' "$?"
printf '\nExecutable SHA-256:\n'
/usr/bin/shasum -a 256 "$app/Contents/MacOS/node" | /usr/bin/awk '{print $1}'
printf '\nProfile eligibility (no identifiers):\n'
scratch=$(mktemp -d) || exit 1
trap 'rm -rf "$scratch"' EXIT
if /usr/bin/security cms -D -i "$app/Contents/embedded.provisionprofile" > "$scratch/profile.plist" 2>/dev/null; then
  for field in ProvisionsAllDevices ExpirationDate; do
    printf '%s: ' "$field"
    /usr/bin/plutil -extract "$field" raw -o - "$scratch/profile.plist" 2>/dev/null || echo unknown
  done
else
  echo 'Profile missing or could not be decoded.'
fi
if [[ -n "${2:-}" ]]; then
  [[ "$2" =~ ^0x[0-9a-f]{64}$ ]] || { echo 'Invalid state basename'; exit 1; }
  state="$HOME/Library/Application Support/AttestNode/$2.json"
  if [[ -f "$state" ]]; then
    echo 'Participant state exists: key generation reached the save step.'
    if /usr/bin/plutil -extract attestation raw -o - "$state" >/dev/null 2>&1; then
      echo 'Saved Apple attestation exists.'
    else
      echo 'No saved Apple attestation.'
    fi
  else
    echo 'No participant state file: key generation may have failed, or this participant ID/path is no longer current.'
  fi
fi
printf '\nThese observations do not prove Full Security or establish the root cause. No keys or settings changed.\n'
