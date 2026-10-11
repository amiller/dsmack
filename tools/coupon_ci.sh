#!/usr/bin/env bash
# Local credential-free CI entry point. Source fetching/distribution is separate.
set -euo pipefail
# BuildKit applies the client umask to COPY; the image runtime user must be
# able to read the packaged files, so pin the traditional public default.
umask 022
[[ $# == 1 ]] || { echo 'usage: bash tools/coupon_ci.sh /absolute/reviewed/abalone' >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
mkdir -p local-data
run_dir=$(mktemp -d "$root/local-data/coupon-ci.XXXXXX")
python3 tools/coupon_package.py --abalone-source "$1" --output "$run_dir/first.tar.gz"
python3 tools/coupon_package.py --abalone-source "$1" --output "$run_dir/second.tar.gz"
cmp "$run_dir/first.tar.gz" "$run_dir/second.tar.gz"
mkdir "$run_dir/package"
tar -xzf "$run_dir/first.tar.gz" -C "$run_dir/package"
# Reproducible archives carry mtime 0 and stable file sizes; BuildKit's
# incremental context transfer keyed on path+size+mtime then reuses a stale
# cached copy when only content changed (observed: source-manifest.json).
# Current mtimes force a full re-transfer of the context.
find "$run_dir/package" -exec touch {} +
# The Docker allowlist must also exclude an accidental secret added after export.
printf '%s\n' 'PRIVATE_OPERATOR_BUILD_CONTEXT_CANARY' > "$run_dir/package/.operator-canary"
for directory in experiments/coupon_redemption vendor/abalone/lib packaging/coupon; do
  printf '%s\n' 'PRIVATE_NESTED_BUILD_CONTEXT_CANARY' > "$run_dir/package/$directory/operator_secret.py"
done
image="dsmack-coupon-node:ci-$(basename "$run_dir")"
docker build --platform linux/amd64 -f "$run_dir/package/packaging/coupon/Dockerfile" -t "$image" "$run_dir/package"
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m --entrypoint node "$image" packaging/coupon/smoke.mjs
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m -v "$root/experiments/coupon_redemption:/regression/experiments/coupon_redemption:ro" -w /regression --entrypoint python3 "$image" -m unittest experiments.coupon_redemption.test_dstack_identity experiments.coupon_redemption.test_peer_worker experiments.coupon_redemption.test_runner experiments.coupon_redemption.test_service experiments.coupon_redemption.test_service_v2 experiments.coupon_redemption.test_service_v3 experiments.coupon_redemption.test_service_v4 experiments.coupon_redemption.test_issuer_service experiments.coupon_redemption.test_spike experiments.coupon_redemption.test_transport experiments.coupon_redemption.test_staging_approval experiments.coupon_redemption.test_issuance_guard experiments.coupon_redemption.test_async_service_v4 experiments.coupon_redemption.test_async_fixture experiments.coupon_redemption.test_live_worker
# Regression stages intentionally execute test-only helpers in /tmp (the
# issuance guard's generated checker, node lifecycle wrappers); Docker's
# default tmpfs is noexec, so exec must be enabled explicitly.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m -v "$root/experiments/coupon_redemption:/regression/experiments/coupon_redemption:ro" -w /regression --entrypoint node "$image" --test experiments/coupon_redemption/test_peer_bridge.mjs
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m -v "$root/experiments/coupon_redemption:/regression/experiments/coupon_redemption:ro" -v "$root/tests/test_coupon_node_issuer.mjs:/regression/test_coupon_node_issuer.mjs:ro" -e DSMACK_PACKAGE_DIR=/opt/dsmack -e DSMACK_FIXTURE_DIR=/regression --entrypoint node "$image" --test /regression/test_coupon_node_issuer.mjs
# The staging node lifecycle runs against the packaged node with the current
# mounted Python source, exactly like the bridge regression above it.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=64m -v "$root/experiments/coupon_redemption:/regression/experiments/coupon_redemption:ro" -v "$root/tests/test_coupon_live_node.mjs:/regression/test_coupon_live_node.mjs:ro" -e DSMACK_PACKAGE_DIR=/opt/dsmack -e DSMACK_FIXTURE_DIR=/regression --entrypoint node "$image" --test /regression/test_coupon_live_node.mjs
python3 -m unittest discover -s tests -p test_coupon_package.py
printf 'PASS reproducible-source-package, isolated packaged Noise smoke and pinned-runtime regressions; evidence %s\n' "$run_dir"
