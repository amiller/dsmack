# Verified native updates

This candidate adds **Check for updates…** and **Recover a previous version…**
to the native Testnet menu. It does not change the currently distributed RC3 app
or its blocked seed. A new signed release and its actual admission/upgrade
qualification are required before this flow is offered to friends.

## Friend journey

1. Choose **Check for updates…**. If the release owner has published a compatible,
   unexpired recommendation, the app shows its version/build. Otherwise the
   current app keeps running and explains the refusal.
2. Choose **Download and verify**. Dsmack checks the exact archive checksum,
   safe ZIP paths, notarized Developer ID assessment, the current app's signing
   requirement/team/bundle identifier, unchanged identity-access entitlements,
   and the candidate's signed version/build/network metadata.
3. Choose **Install and restart**. The verified app is installed under
   `~/Applications/Dsmack Releases/`. A helper waits for the old peer to quit,
   verifies the candidate again, then opens it. The old app is retained.
4. Confirm a fresh peer exchange and the expected personal account/receipt.
   Preserved files are not an acceptance verdict. Expired App Attest enrollment
   renews as a new member; personal account continuity separately depends on the
   original Keychain identity and linked-account metadata.

Downloads and verification failures leave the running app intact. No updater
operation deletes enrollment files or touches Keychain. If launch fails, the
helper explains that the previous app remains available. **Recover a previous
version…** reveals the retained old app when its recorded executable hash still
matches, otherwise the releases folder. It never silently launches an old build:
network policy may no longer admit it. Obtain the coordinator's confirmation
before reopening an older version. This candidate does not promise automatic
rollback of network admission, App Attest renewal or on-chain effects.

## Recommendation authority

Discovery is pinned to the GitHub release named `native-recommended` in
`amiller/dsmack`, specifically its single `dsmack-update.json` asset. GitHub HTTPS
and repository release permissions authenticate the release owner's
recommendation. This is **owner-qualified guidance**, not an independently
verified chain-admission proof. Compromise of that release authority can deny or
misrecommend updates; the app separately constrains installed bytes to its Apple
signing identity, unchanged entitlements and sealed network profile.

The recommendation must expire within seven days, explicitly support the current
build, and select a strictly newer numeric build. A previously verified higher
build prevents replaying a lower offer. These local preferences are not a
rollback-resistant hardware counter. Archive downloads are limited to 250 MB;
expanded ordinary non-symlink `Node.app` ZIPs are bounded to 600 MB. Only HTTPS
GitHub API/release/CDN redirects are accepted. No arbitrary update URL override
is offered in the ordinary app.

The current build script seals `Contents/Resources/dsmack-release.json` alongside
the executable. That metadata includes source revision, version, numeric build,
native V2 profile and all compiled chain/category/contract/relay/RPC/seed pins.
Changing the network requires a separately reviewed migration; this updater
refuses it. Signing, notarization and admission remain release-owner operations.

## Release-owner preparation

Build the GUI with `scripts/release/build_mac.py`, sign and notarize using the
reviewed existing release process, then package the complete app with
`tools/native_update_archive.py --app /path/to/Node.app --output Node.zip`.
The updater refuses ZIP extra fields, symlinks and resource-fork sidecars; use
this packager instead of a general Finder/ditto ZIP. Review
its exact bytes and qualify fresh admission, actual exchange, identity/account
continuity, restart and failure recovery before recommending it. Keep a live
admitted key holder throughout any planned admission change. The updater does
not administer the registry or rotate the shared-key epoch.

`tools/native_update_recommendation.py` prepares JSON without publishing it:

```sh
python3 tools/native_update_recommendation.py \
  --archive Node.zip --tag native-v0.2.0-rc.1 \
  --expires 2026-10-15T00:00:00Z --previous-build 5 \
  --evidence https://github.com/amiller/dsmack/pull/REVIEW_NUMBER \
  --owner-qualified --output dsmack-update.json
```

These values are illustrative, not a recommendation for an existing release.
The flag is an owner assertion, not a test. Pin the immutable native release tag,
exact ZIP and review evidence; publish its recommendation asset only after the
release owner approves the exact packet. `rollbackBuilds` records owner guidance
but does not trigger automatic rollback. Renew an expired recommendation only
with current availability/admission evidence. Do not edit old tagged artifacts.

## Checks and remaining acceptance

`tests/make_native_update_fixtures.py` generates small adversarial ZIPs. The actual
Swift policy/archive tests in `tests/native_update_policy.swift` cover valid
recommendations, expiry, downgrade/replay, wrong network/host/qualification,
unsafe ZIP entries and unsigned-app refusal. Run them with the updater sources
on the supported remote Mac; these tests do not launch a peer or mutate a chain.

A signed/notarized positive install, actual GUI discovery/handoff recording,
identity/account continuity and a controlled failure/recovery journey remain
separate release gates. Developer/ad-hoc fixtures must not be accepted merely to
make that recording green. RC3 has no updater: the initial upgrade to a build
with this feature still uses the documented signed download-and-replace path.

The code registry normalizes away Info.plist and resource hashes. A displayed
version is signed, self-reported release metadata, not an on-chain attested
version. The updater compares its signed network metadata with network pins
compiled into the executable. Changed executable code still requires an explicit
admission-policy transition; installing it does not authorize that transition.
