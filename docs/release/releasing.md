# Releasing and inspecting Dsmack

What a release is, and when to cut one, is in [versioning.md](../versioning.md). A
release `vX.Y.Z` ships the signed Mac app, the base images it admits, and the
verifier that reads its evidence.

## Cadence

A release is cut every other Friday. The next one always exists as a GitHub milestone with a due date, so there is one place to propose what goes in it. If nothing in the milestone is ready, the date moves two weeks and the milestone says why. A release with nothing in it is skipped, not cut empty.

- **Input.** Open an issue and ask for it to go in the next milestone. Anything not done by the freeze moves to the one after.
- **Freeze.** On the Wednesday before, the milestone stops taking new work. What's left is fixes and the release notes.
- **Review.** Before tagging, the diff since the last release gets a security read, with the base image, the Mac app, the verifier and the evidence formats first. The release notes say what was read and by whom.
- **Notes.** Each release adds an entry to [CHANGELOG.md](../../CHANGELOG.md): what changed in each layer, the new identities (app cdhash, base image hashes), whether it breaks anything, the evidence formats it writes and reads, and who should upgrade and by when.
- **Next.** The day a release is tagged, the next milestone is created with its due date.

## Maintainer

1. Tag a reviewed commit `vX.Y.Z`. Never move a released tag or replace an asset.
2. Build unsigned with `runner-vm/native/build.sh` and `runner-vm/packaging/build.sh`
   on Xcode 27.0, and publish `contracts/cd_args.py --measure` of the executable so a rebuild
   can be compared (see [runner-vm](../../runner-vm/README.md)). Record the unsigned executable hash.
3. Sign with `runner-vm/packaging/sign.sh` and the five-key
   `DsmackRunner.entitlements`. Record the signed executable hash, the full
   SHA-256 CodeDirectory digest, Team ID, bundle ID and provisioning profile.
   Re-signing changes the app identity, so every Mac re-enrolls.
4. Write the release inventory (`dsmack-alpha-release/2`): the app identity and the
   admitted base-image profiles. Sign it with the Ed25519 release key. Installs
   check it with `applications/pilot-client/alpha-release.mjs`; the inventory is
   currently written outside this repo.
5. Notarize and staple, then publish the archive with a provenance attestation
   over the final signed bytes, the release inventory and its signature. No OAuth
   keys, private disks, device keys or signing secrets go in the release.
6. List the evidence format numbers the release writes and reads in the release notes.

A new workload or a new task needs none of this; it names the release it runs on.

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
