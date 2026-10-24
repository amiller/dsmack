# Releasing and inspecting DsmackRunner

## Maintainer

1. Tag a reviewed commit `vX.Y.Z`. Never move a released tag or replace an asset.
2. Build unsigned with `runner-vm/native/build.sh` and `runner-vm/packaging/build.sh`
   (see [runner-vm](../../runner-vm/README.md)). Record the unsigned executable hash.
3. Sign with `runner-vm/packaging/sign.sh` and the five-key
   `DsmackRunner.entitlements`. Record the signed executable hash, the full
   SHA-256 CodeDirectory digest, Team ID, bundle ID and provisioning profile.
   Re-signing changes the app identity, so enrollments must be redone.
4. Notarize and staple, then publish the archive with a provenance attestation
   over the final signed bytes, the release inventory and its signature. No OAuth
   keys, private disks, device keys or signing secrets go in the release.

## Inspecting a download before running it

On macOS, without launching the app:

```sh
codesign --verify --deep --strict --verbose=4 /absolute/path/DsmackRunner.app
codesign --display --verbose=6 /absolute/path/DsmackRunner.app
codesign --display --entitlements - --xml /absolute/path/DsmackRunner.app
spctl --assess --type execute --verbose=4 /absolute/path/DsmackRunner.app
python3 tools/release/inspect_runner.py \
  /absolute/path/DsmackRunner.app/Contents/MacOS/dsmack-runner \
  --expected-cdhash FULL_SHA256_CD_DIGEST \
  --expected-team TEAM_ID --expected-bundle BUNDLE_ID
```

`inspect_runner.py` uses `contracts/cd_args.py` to check every CodeDirectory,
every code page and the embedded special slots of a thin ARM64 executable.
Apple signature trust comes from the `codesign` and `spctl` checks.

## Tests

```sh
python3 -m unittest discover -s tools/release -p 'test_*.py' -v
```
