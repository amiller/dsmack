#!/bin/bash
# build.sh — UNSIGNED build + package of DsmackRunner.app (SWIFT03 repair3).
#
# This is the UNSIGNED compile/package workflow the review required: it NEVER
# requires KEYCHAIN, imports NO signing credentials and runs NO codesign. Signing
# is a SEPARATE step (packaging/sign.sh) gated on independent review. The rejected
# repair2 build.sh demanded KEYCHAIN at its first line and proceeded straight into
# codesign, so there was no unsigned path at all.
#
# It consumes the pinned native v3 archive (packaging/ARCHIVE-PIN.json —
# loop40-native-nat-repair2 libdsmack_hvf_returning.a) and, BEFORE building:
#   (1) PINS the archive by sha256 (so a different/stale archive is refused), and
#   (2) verifies the archive exports the COMPLETE v1/v2/v3 application symbol set
#       the mar executable links (Backend.swift v1 + BackendV2.swift v2 +
#       BackendV3.swift v3) — repair2 checked only the v3 names and never pinned
#       the archive bytes.
#
# DsmackRunner NAMING (RUNNER-NAMING-AND-CHAIN-HANDOFF, dsmack-private#29): the
# bundle is DsmackRunner.app, the executable is Contents/MacOS/dsmack-runner,
# CFBundleName=DsmackRunner, CFBundleExecutable=dsmack-runner, CFBundleIdentifier
# dev.dsmack.provider, team DC9JH5DRMY. The Swift executable TARGET stays "mar"
# (compile command unchanged: `swift build -c release --product mar`); only the
# COPIED binary and Info.plist carry the product name. Existing build output is
# refused, never removed automatically.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
app="$HERE/build/DsmackRunner.app"
if [ -e build ]; then
  echo "refusing: build/ already exists; remove it yourself if it is disposable" >&2
  exit 1
fi

# ---- (0) portable sha256 + authoritative JSON string field reader -----------
# sha256sum on Linux, shasum -a 256 on macOS (the Mini).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
# Read a top-level string field from the reviewed ARCHIVE-PIN.json WITHOUT a JSON
# tool (jq is not guaranteed on the Mini). The regex anchors to a `"<key>": "..."`
# member; the value is taken verbatim. This is the SOLE source of the pins — there
# is deliberately no environment fallback for any of them.
pin_str() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$PIN_FILE" | head -1
}

# ---- (1) pin the reviewed native v3 archive by its AUTHORITATIVE sha256 -------
# SWIFT03 repair4: the reviewed digest, the frozen native handoff CONTENT hash and
# the native source-inventory CONTENT hash are ALL read authoritatively from
# packaging/ARCHIVE-PIN.json. The rejected repair3 used
# `EXPECT_ARCHIVE_SHA256="${EXPECT_ARCHIVE_SHA256:-...}"`, so a caller could supply
# ANOTHER archive plus its matching env-provided digest and pass the "frozen pin".
# Here the environment CANNOT replace the reviewed digest: if EXPECT_ARCHIVE_SHA256
# is set in the environment at all, it is only honoured when it EQUALS the pin (an
# explicit, harmless no-op) and is REFUSED outright when it diverges — the archive
# the production build accepts is fixed by the reviewed file, full stop.
PIN_FILE="$HERE/ARCHIVE-PIN.json"
if [ ! -f "$PIN_FILE" ]; then echo "refusing: $PIN_FILE (reviewed archive pin) not found" >&2; exit 1; fi
PIN_ARCHIVE_DIR="/Users/amiller/dsmack-accepted-native-swift8-20261022-codex/native-archive"

# Capture any environment EXPECT_ARCHIVE_SHA256 BEFORE deriving the authoritative
# pin, so we can REFUSE an attempt to substitute a different digest (rather than
# silently honour it, as the rejected repair3 did).
ENV_EXPECT="${EXPECT_ARCHIVE_SHA256:-}"
# The authoritative digest is ALWAYS the reviewed file; the environment cannot
# replace it.
EXPECT_ARCHIVE_SHA256="$(pin_str archive_sha256)"
if [ "${#EXPECT_ARCHIVE_SHA256}" -ne 64 ] || [ -n "$(printf '%s' "$EXPECT_ARCHIVE_SHA256" | tr -d '0-9a-f')" ]; then
  echo "refusing: ARCHIVE-PIN.json archive_sha256 is not a 64-hex digest ('$EXPECT_ARCHIVE_SHA256')" >&2; exit 1
fi
if [ -n "$ENV_EXPECT" ] && [ "$ENV_EXPECT" != "$EXPECT_ARCHIVE_SHA256" ]; then
  echo "refusing: an environment EXPECT_ARCHIVE_SHA256 ($ENV_EXPECT) may not replace the reviewed pin ($EXPECT_ARCHIVE_SHA256)" >&2
  echo "  (the production build path accepts ONLY the archive digest recorded in packaging/ARCHIVE-PIN.json)" >&2
  exit 1
fi

# ---- (1a) verify the FROZEN native handoff + source-inventory CONTENT pins ----
# The archive bytes are bound to the frozen native source: the native handoff file
# must hash to native_handoff_sha256, the handoff must ITSELF declare this exact
# archive sha256, and the native source-inventory manifest must hash to
# native_source_inventory_sha256. repair3 recorded only field NAMES, not content
# pins, and never verified the handoff.
NATIVE_HANDOFF="${NATIVE_HANDOFF_FILE:-$(pin_str native_handoff)}"
EXPECT_HANDOFF_SHA="$(pin_str native_handoff_sha256)"
NATIVE_INVENTORY="${NATIVE_INVENTORY_FILE:-$(pin_str native_source_inventory)}"
EXPECT_INVENTORY_SHA="$(pin_str native_source_inventory_sha256)"
for v in NATIVE_HANDOFF EXPECT_HANDOFF_SHA NATIVE_INVENTORY EXPECT_INVENTORY_SHA; do
  eval "val=\${$v}"
  if [ -z "$val" ]; then echo "refusing: ARCHIVE-PIN.json is missing $v" >&2; exit 1; fi
done
if [ ! -f "$NATIVE_HANDOFF" ]; then echo "refusing: frozen native handoff $NATIVE_HANDOFF not found" >&2; exit 1; fi
GOT_HANDOFF_SHA="$(sha256_of "$NATIVE_HANDOFF")"
if [ "$GOT_HANDOFF_SHA" != "$EXPECT_HANDOFF_SHA" ]; then
  echo "refusing: native handoff content sha256 $GOT_HANDOFF_SHA != pinned $EXPECT_HANDOFF_SHA" >&2; exit 1
fi
# The handoff must declare the SAME archive digest we are about to accept, binding
# the archive bytes to the frozen native source the handoff provenance covers.
HANDOFF_ARCHIVE_SHA="$(sed -n 's/.*"archive_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$NATIVE_HANDOFF" | grep -x "$EXPECT_ARCHIVE_SHA256" | head -1)"
if [ "$HANDOFF_ARCHIVE_SHA" != "$EXPECT_ARCHIVE_SHA256" ]; then
  echo "refusing: frozen native handoff does not declare archive sha256 $EXPECT_ARCHIVE_SHA256" >&2; exit 1
fi
if [ ! -f "$NATIVE_INVENTORY" ]; then echo "refusing: native source-inventory $NATIVE_INVENTORY not found" >&2; exit 1; fi
GOT_INVENTORY_SHA="$(sha256_of "$NATIVE_INVENTORY")"
if [ "$GOT_INVENTORY_SHA" != "$EXPECT_INVENTORY_SHA" ]; then
  echo "refusing: native source-inventory content sha256 $GOT_INVENTORY_SHA != pinned $EXPECT_INVENTORY_SHA" >&2; exit 1
fi
echo "native provenance pinned: handoff=$GOT_HANDOFF_SHA inventory=$GOT_INVENTORY_SHA"

# ---- (1b) verify the archive bytes against the authoritative pin --------------
# ARCHIVE_DIR may be relocated (e.g. onto the Mini) but ONLY to a byte-identical
# archive: a non-identical archive fails this check regardless of any env variable.
ARCHIVE_DIR="${ARCHIVE_DIR:-$PIN_ARCHIVE_DIR}"
V3_ARCHIVE="$ARCHIVE_DIR/libdsmack_hvf_returning.a"
if [ ! -f "$V3_ARCHIVE" ]; then
  echo "refusing: $V3_ARCHIVE not found (ARCHIVE_DIR must hold the pinned dsmack-hvf-returning staticlib)" >&2
  exit 1
fi
GOT_SHA="$(sha256_of "$V3_ARCHIVE")"
if [ "$GOT_SHA" != "$EXPECT_ARCHIVE_SHA256" ]; then
  echo "refusing: archive sha256 $GOT_SHA != authoritative pin $EXPECT_ARCHIVE_SHA256 (ARCHIVE-PIN.json)" >&2
  exit 1
fi
echo "archive pinned: $V3_ARCHIVE sha256=$GOT_SHA"

# ---- (2) verify the COMPLETE v1/v2/v3 application symbol set ------------------
# Every C symbol the mar executable references across Backend.swift (v1),
# BackendV2.swift (v2) and BackendV3.swift (v3). The link needs ALL of them; an
# archive missing any one is refused here with a NAMED error, never at an opaque
# late link stage.
V1_SYMS="dsmack_join_vm_new dsmack_join_run dsmack_join_err_cap_min"
V2_SYMS="dsmack_ctl_v2_init dsmack_ctl_join_vm_new dsmack_ctl_join_run dsmack_ctl_join_receipt \
dsmack_ctl_join_receipt_cap_min dsmack_ctl_join_abi_version dsmack_ctl_join_err_cap_min"
V3_SYMS="dsmack_ctl_v3_init dsmack_ctl_join_vm_new_v3 dsmack_ctl_join_run_v3 dsmack_ctl_join_finalize_v3 \
dsmack_ctl_join_receipt_v3 dsmack_ctl_join_result_v3 dsmack_ctl_join_free_v3 \
dsmack_ctl_join_abi_version_v3 dsmack_ctl_join_err_cap_min_v3"
missing=""
nmout="$(nm -g "$V3_ARCHIVE" 2>/dev/null || true)"
for s in $V1_SYMS $V2_SYMS $V3_SYMS; do
  # Mach-O nm prefixes C symbols with a leading underscore; match a defined (T/t)
  # text symbol in either form. Use a here-string (NOT `printf | grep -q`): under
  # `set -o pipefail`, grep -q's early exit sends SIGPIPE to the producer and the
  # pipeline reports failure even on a MATCH, which would falsely flag every present
  # symbol as missing.
  if ! grep -Eq " [Tt] _?${s}\$" <<<"$nmout"; then
    missing="$missing $s"
  fi
done
if [ -n "$missing" ]; then
  echo "refusing: pinned v3 archive is missing required exported symbol(s):$missing" >&2
  echo "  (the mar executable links v1 (Backend.swift) + v2 (BackendV2.swift) + v3" >&2
  echo "   (BackendV3.swift); the archive must export the COMPLETE set.)" >&2
  exit 1
fi
echo "symbol set verified: 19 v1/v2/v3 application symbols exported"

# ---- build (unsigned) --------------------------------------------------------
# Build in a scratch copy so the lane sources stay pristine. No sed: the manifest
# reads DSMACK_V3_ARCHIVE_DIR directly. The app-src/control-src trees are siblings.
mkdir -p build/work
cp -R ../app-src ../control-src build/work/
(cd build/work/app-src && DSMACK_V3_ARCHIVE_DIR="$ARCHIVE_DIR" swift build -c release --product mar --skip-update --disable-automatic-resolution --disable-sandbox)

# ---- package (unsigned bundle) ----------------------------------------------
mkdir -p "$app/Contents/MacOS"
# Swift target is "mar"; the product executable is dsmack-runner.
cp build/work/app-src/.build/release/mar "$app/Contents/MacOS/dsmack-runner"
# The provisioning profile is OPTIONAL at the unsigned stage (it is needed only to
# sign). Embed it if provided, so the unsigned bundle is complete for sign.sh.
if [ -n "${PROFILE:-}" ]; then cp "$PROFILE" "$app/Contents/embedded.provisionprofile"; fi
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>dsmack-runner</string>
<key>CFBundleName</key><string>DsmackRunner</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST

# Record the unsigned build pins (NO signing metadata — the CDHash only exists
# after sign.sh runs and is gated separately).
if command -v sha256sum >/dev/null 2>&1; then BIN_SHA="$(sha256sum "$app/Contents/MacOS/dsmack-runner" | cut -d' ' -f1)"; else BIN_SHA="$(shasum -a 256 "$app/Contents/MacOS/dsmack-runner" | cut -d' ' -f1)"; fi
cat > build/UNSIGNED-BUILD.json <<JSON
{
  "stage": "unsigned-build-and-package",
  "signed": false,
  "archive": "$V3_ARCHIVE",
  "archive_sha256": "$GOT_SHA",
  "symbol_set_verified": "v1+v2+v3 (19 symbols)",
  "unsigned_binary": "$app/Contents/MacOS/dsmack-runner",
  "unsigned_binary_sha256": "$BIN_SHA",
  "note": "No signing performed. Run packaging/sign.sh (requires KEYCHAIN + SIGN_IDENTITY + ENTITLEMENTS + PROFILE) as a separate, independently-reviewed step."
}
JSON
echo "unsigned build complete: $app"
echo "  binary sha256=$BIN_SHA"
echo "  NEXT (separate, gated): packaging/sign.sh"
