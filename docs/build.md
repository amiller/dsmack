# Build the Mac app under your own team

You can build the Mac node from source, sign it with your own Apple developer
team, and check that it is the same program as the build the network admits.
The signature, team and app name will differ from ours. The code must not.

## What gets compared

Every signed Mac app carries a code directory: a hash of each page of the
program, plus hashes of its settings and entitlements. Apple hashes that
directory again to get the CDHash, which is what App Attest reports. Your
CDHash will never match ours, because the code directory also contains your
Team ID, your bundle ID and the size of your signature.

The measurement M is a hash of the same code directory with those parts left
out. It keeps every code page, the hardened-runtime flags, the first page of
the program with its signature sizes blanked, and every entitlement except the
four that name a team or app (`application-identifier`,
`com.apple.application-identifier`, `com.apple.developer.team-identifier`,
`keychain-access-groups`). Two builds have the same M only if they run the same
code with the same permissions. The
[measurement registry](https://base-sepolia.blockscout.com/address/0x976C2F9DF2bab0616f25D07CEC77cab7C5272203)
on Base Sepolia admits builds by M, so a build whose M is admitted can join
whoever signed it.

## What you need

- An Apple Silicon Mac on macOS 27.
- The exact Xcode, SDK and Swift versions in
  [node/mac/toolchain.json](../node/mac/toolchain.json). The build stops if
  they differ.
- An Apple developer team with a Developer ID Application certificate, an
  explicit App ID with the App Attest capability, and a Developer ID
  provisioning profile for that App ID.

## Build and sign

Check out the commit of the release you are reproducing, then use an output
directory that does not exist yet:

```sh
python3 scripts/release/build_mac.py --gui --out build/mine \
  --team ABCDE12345 --bundle-id com.example.node \
  --version 0.2.0 --build-number 5
```

Use your own Team ID and bundle ID, and the release's version and build number.
Omit `--gui` for the command-line node. Besides the unsigned `Node.app`, the
build writes `build/mine/entitlements.plist` from
[node/mac/Entitlements.template.plist](../node/mac/Entitlements.template.plist).
The only things your Team ID and bundle ID change are `Info.plist` and that
entitlements file; the program file is byte-for-byte the same as ours.

Sign with your certificate and profile:

```sh
python3 scripts/release/sign_mac.py --build build/mine --out build/mine-signed \
  --profile mine.provisionprofile --team ABCDE12345 \
  --identity "Developer ID Application: Your Name (ABCDE12345)" \
  --channel developer-id --notary-profile your-notary-profile
```

The signer refuses a profile whose entitlements differ from the template. If
you sign by hand, pass `--entitlements build/mine/entitlements.plist
--generate-entitlement-der --options runtime` to `codesign` and add nothing
else: an extra entitlement changes M.

## Check your M

```sh
python3 scripts/release/measure_two_teams.py \
  --one build/mine-signed/Node.app/Contents/MacOS/node
```

This prints your M and your CDHash. Compare M with the one admitted for that
release; the [0.2.0 release notes](https://github.com/amiller/dsmack/releases/tag/node-v0.2.0)
list `0xf8c1da8e…f8fb58` for the app. If it does not match, the usual causes are a different commit, a different toolchain, a
different flavor (`--gui` or not), or a change to the entitlements.

## Try it without an Apple account

```sh
scripts/release/measure_two_teams.sh build/two-teams
```

This builds the command-line node from two checkouts at different paths under
two made-up teams, checks that the two unsigned programs are identical, signs
each with a throwaway self-signed certificate, and also builds and signs a
deliberately modified version. It passes only if the two honest builds share
one M, the modified build has a different M, and all three CDHashes differ. The
certificates live in a temporary keychain inside the output directory and are
deleted when the script ends. Self-signed copies cannot use App Attest, so this
only checks the measurement. The same check runs on every change to the Mac
code in the [Mac build workflow](../.github/workflows/mac-build.yml);
[here is the run](https://github.com/amiller/dsmack/actions/runs/38295216891/job/114964549520)
for the 0.2.0 source commit `e72641c`.
