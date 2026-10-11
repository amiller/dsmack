# Ad hoc CDHash probe build — 2026-09-23

Mac rig: `~/projects/appattest-iphone-20260923/ios-app-attest` (fresh copy of this repo's
ios-app-attest; the 20260909 rig was left untouched). macOS 27.0, Xcode 27.0 (27A266a).

Source changes: `app/AppAttestLab.entitlements` adds
`com.apple.developer.devicecheck.app-attest-opt-in = [CDhash]` (same as the Mac probe);
default verifier URL is the build setting `LAB_DEFAULT_ENDPOINT` via Info.plist `LabDefaultEndpoint`.

Build (per variant, lab keychain unlocked in the same SSH session as in earlier Mac runs):

    LAB_ENVIRONMENT=production LAB_DEFAULT_ENDPOINT=https://probe.ln.soc1024.com \
      bash scripts/build_adhoc.sh honest|modified

`xcodebuild archive` + `-exportArchive` (method `release-testing`, automatic signing,
`-allowProvisioningUpdates`). Xcode created/used `iOS Team Ad Hoc Provisioning Profile:
dev.dsmack.provider` (UUID 7a691543-…, 18 devices incl. papi REDACTED_DEVICE_IDENTIFIER) and
signed with the Cloud Managed Apple Distribution certificate. The profile grants
appattest-environment [development, production]; the builds use `production`.

Both IPAs: identifier dev.dsmack.provider, team DC9JH5DRMY, version 1.0 (1), thin arm64,
identical signed entitlements (opt-in present, get-task-allow false), identical Info.plist /
requirements / resources / entitlement slots; only code pages differ. Full CodeDirectory
SHA-256 (independently recomputed by `macos/check_evidence.py --dump-codedirectory`, every
code page checked, equal to `codesign -dvvv` CandidateCDHashFull on the Mac):

    honest   5395bf39ecded47ab804eb78b7f878c246baa4860ca32cad1c63ed468783b591
    modified 85678f245cf838860723c1374e78a9321fa4c87c91900e4921e5877ed0f31b2c

Install: `install/render.sh <https base URL>` writes `install/out/` (index.html, itms-services
manifests, IPAs) to serve at that URL. Not served anywhere yet.

Verifier: run with an identity-only policy (no CDHash allowlist) during the phone session so
every enrollment is stored and later assertions can proceed; apply the approved-CDHash policy
offline afterwards, as in the Mac matrix. The evidence table keeps each raw request.
