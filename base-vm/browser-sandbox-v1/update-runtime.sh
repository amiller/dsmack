#!/bin/bash
set -euo pipefail
umask 0022
LEG=/w/build/legs/diagnostic
mkdir -p "$LEG/files" "$LEG/work"
unsquashfs -no-progress -processors 4 -d "$LEG/work/rootfs" /prior-image/rootfs.squashfs.verity
RDEST="$LEG/work/rootfs/usr/local/lib/dsmack/compose-runner"
for file in security.py lowering.py; do
    install -m0644 "/w/source/runner-content/lib/dsmack_compose_contract/$file" "$RDEST/lib/dsmack_compose_contract/$file"
done
install -m0644 /w/source/runner-content/dsmack_compose_runner/lifecycle.py "$RDEST/dsmack_compose_runner/lifecycle.py"
(cd "$RDEST" && find . -type f ! -name SHA256SUMS ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
cp /prior-image/Image /prior-image/config-6.18.40-dstack "$LEG/files/"
bash /w/source/build/assemble_leg.sh diagnostic
chmod 0644 "$LEG/files/"*
