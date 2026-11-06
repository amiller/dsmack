#!/bin/bash
# Install the dsmack guest tree from the repo into a rootfs: install-guest.sh REPO TREE
set -euo pipefail
umask 0022
R=$1 T=$2
S=$R/base-vm/browser-sandbox-v1/source L=$T/usr/local/lib/dsmack
copy() { mkdir -p "$2"; rsync -r --exclude=__pycache__ --chmod=D0755,F0644 "$1/" "$2/"; }
rm -rf "$L" "$T"/usr/local/bin/dsmack-*
copy "$S/runner-content/dsmack_compose_runner" "$L/compose-runner/dsmack_compose_runner"
copy "$R/compose-contract/dsmack_compose_contract" "$L/compose-runner/lib/dsmack_compose_contract"
copy "$S/runner-content/dsmack_guest_io" "$L/guest-io/dsmack_guest_io"
copy "$S/guest/sentinel" "$L/sentinel"
for f in agent.py guest_attest.py dsmack_dstack.py secret_box.py; do install -D -m0644 "$R/dstack-compat/$f" "$L/dstack-agent/$f"; done
install -D -m0644 "$S/profile/dstack-trixie-arm64-minimal/guest-network.env" "$L/net/guest-network.env"
install -D -m0644 "$S/profile/dstack-trixie-arm64-minimal/docker-daemon.json" "$T/etc/docker/daemon.json"
install -D -m0755 -t "$T/usr/local/bin" "$S/runner-content/bin/dsmack-compose-runner" "$S/runner-content/bin/dsmack-guest-io"
install -D -m0755 "$S/guest/supervisor-dstack-trixie.sh" "$T/usr/bin/dsmack-supervisor"
