#!/bin/bash
# Usage: run.sh <probe> <fresh-work-dir>, probe = probe | acl_certificate_probe | chain_format_probe |
# provider_route_probe | platform_binding_probe | eligible_attestor_probe. Stock Apple-silicon Mac, ad hoc signing.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
probe=${1:?probe name}
umask 077
work=${2:?fresh work directory}
mkdir -m 700 "$work" "$work/output"
work=$(cd "$work" && pwd)
b() { python3 "$here/bounded.py" "$@"; }
r="$work/recipient"
case "$probe" in
  probe|acl_certificate_probe)
    mkdir -m 700 "$r"
    b 30 openssl ecparam -name prime256v1 -genkey -noout -out "$r/private.pem"
    b 30 openssl req -new -x509 -key "$r/private.pem" -out "$r/cert.pem" -days 1 -subj /CN=dsmack-synthetic-recrypt-negative-control
    b 30 openssl x509 -in "$r/cert.pem" -outform DER -out "$r/chain.der"
    b 30 openssl ec -in "$r/private.pem" -outform DER -out "$r/private.sec1.der"
    b 30 python3 "$here/recipient_x963.py" "$r/private.sec1.der" "$r/private.x963"
    args=("$r/chain.der" "$work/output" "$r/private.x963");;
  chain_format_probe|provider_route_probe)
    python3 "$here/prepare_chain.py" "$r"
    args=("$r/chain.der" "$work/output" "$r/leaf.x963" "$r/leaf.der");;
  platform_binding_probe|eligible_attestor_probe) args=();;
  *) echo "unknown probe $probe"; exit 64;;
esac
b 60 clang -fobjc-arc -framework Foundation -framework Security "$here/$probe.m" -o "$work/$probe"
b 30 codesign --force --sign - "$work/$probe"
b 30 "$work/$probe" ${args[@]+"${args[@]}"} 2>&1 | tee "$work/run.log"
