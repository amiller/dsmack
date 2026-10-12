#!/bin/bash
# Mac (macOS 27, pinned Xcode). Builds the two-team fixtures (measure_two_teams.sh), packages them,
# writes updates.json with publish_update.py and runs tests/native_update_measured.swift.
# RPC: a dev chain where OWNER is unlocked and deployed MeasurementRegistry at REGISTRY, e.g.
#   anvil; forge create --root contracts --broadcast --unlocked --from $OWNER src/MeasurementRegistry.sol:MeasurementRegistry
# Usage: tests/native_update_measured.sh OUT_DIR RPC REGISTRY OWNER   (OUT_DIR must not exist)
set -euo pipefail
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
OUT=$1
"$ROOT/scripts/release/measure_two_teams.sh" "$OUT/teams"
OUT=$(cd "$OUT" && pwd)
for n in honest-a honest-b modified; do
  python3 "$ROOT/tools/native_update_archive.py" --app "$OUT/teams/signed/$n/Node.app" --output "$OUT/$n.zip"
  python3 "$ROOT/scripts/release/publish_update.py" --archive "$OUT/$n.zip" --tag node-v0.1.0 --notes "fixture $n" --output "$OUT/$n.json" >/dev/null
done
python3 "$ROOT/tests/make_native_update_fixtures.py" "$OUT/zips"
cd "$ROOT"
xcrun swiftc -D GUI -framework AppKit node/shared/Protocol.swift node/shared/Chain.swift node/shared/Measure.swift node/mac/NetworkConfig.swift \
  node/mac/UpdatePolicy.swift node/mac/UpdateArchive.swift node/mac/NativeUpdater.swift tests/native_update_policy.swift -o "$OUT/policy"
"$OUT/policy" "$OUT/zips"
xcrun swiftc -D GUI -framework AppKit node/shared/Protocol.swift node/shared/Chain.swift node/shared/Measure.swift node/mac/NetworkConfig.swift \
  node/mac/UpdatePolicy.swift node/mac/UpdateArchive.swift node/mac/NativeUpdater.swift tests/native_update_measured.swift -o "$OUT/measured"
"$OUT/measured" "$OUT" "$2" "$3" "$4"
