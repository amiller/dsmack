#!/bin/bash
set -euo pipefail
umask 0022
LEG=/w/build/legs/diagnostic
mkdir -p "$LEG/files" "$LEG/work"
unsquashfs -no-progress -processors 4 -d "$LEG/work/rootfs" /prior-image/rootfs.squashfs.verity
TREE=$LEG/work/rootfs
RDEST=$TREE/usr/local/lib/dsmack/compose-runner
install -m0755 /w/source/guest/supervisor-dstack-trixie.sh "$TREE/usr/bin/dsmack-supervisor"
for file in public_inputs.py public_toc.py; do
 install -m0644 "/w/source/runner-content/dsmack_guest_io/$file" "$TREE/usr/local/lib/dsmack/guest-io/dsmack_guest_io/$file"
done
for file in manifest.py lowering.py security.py browser-sandbox-v1.json; do
 install -m0644 "/w/source/runner-content/lib/dsmack_compose_contract/$file" "$RDEST/lib/dsmack_compose_contract/$file"
done
install -m0644 /w/source/runner-content/dsmack_compose_runner/lifecycle.py "$RDEST/dsmack_compose_runner/lifecycle.py"
for file in agent.py guest_attest.py secret_box.py; do
 install -D -m0644 "/w/dstack-compat/$file" "$TREE/usr/local/lib/dsmack/dstack-agent/$file"
done
(cd "$RDEST" && find . -type f ! -name SHA256SUMS ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
cp /prior-image/Image "$LEG/files/Image"
cp /prior-image/config-6.18.40-dstack "$LEG/files/config-6.18.40-dstack"
bash /w/source/build/assemble_leg.sh diagnostic
chmod 0644 "$LEG/files/"*
