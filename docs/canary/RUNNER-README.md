# dsmack-runner, CDHash 0x7011…7970

`dsmack-runner` is the DsmackRunner executable exactly as signed, thin arm64:

- CDHash (full SHA-256 CodeDirectory) `7011178cdb7a92bac0c28faa651ba54d20470a8057c569b2afe55dbf8b467970`
- Team `DC9JH5DRMY`, bundle `dev.dsmack.provider`, Apple Development, hardened runtime
- Approved on Base Sepolia by CDRegistry `0xD6567Da581BCcA8Ce965cD16785a43acbf3378f6`,
  `buildId` `0xc930e34c3997c53022aae6ead1d006ca6b270abe2be76ed6e640551c2d39a758`
- Source: `runner-vm/` at commit `6f248a8` of github.com/amiller/dsmack

`Info.plist` and `entitlements.plist` are the bundle's Info.plist and the entitlements it
was signed with. The provisioning profile is not included: it names one Mac. To run the
app you re-sign it for your own Mac. Re-signing changes the CDHash but not the code, and
CDRegistry admits any copy whose code pages, masked page 0, CodeDirectory header and
entitlement keys match the approved build.

## Check the binary as shipped

Run the commands below in the directory holding the release files, with a checkout of
github.com/amiller/dsmack and its Python packages:

```sh
git clone https://github.com/amiller/dsmack.git ~/dsmack
python3 -m venv ~/dsmack/venv && ~/dsmack/venv/bin/pip install -r ~/dsmack/requirements-runtime.txt cbor2 eth-account
DSMACK=~/dsmack PY=~/dsmack/venv/bin/python
$PY $DSMACK/tools/release/inspect_runner.py dsmack-runner \
  --expected-cdhash 7011178cdb7a92bac0c28faa651ba54d20470a8057c569b2afe55dbf8b467970 \
  --expected-team DC9JH5DRMY --expected-bundle dev.dsmack.provider
```

## Re-sign for your Mac

In your Apple Developer account: an explicit App ID (say `com.example.dsmack`) with the
App Attest capability, an Apple Development certificate, your Mac's provisioning UDID
registered, and a macOS development profile for that App ID and Mac. The hypervisor
entitlement needs no capability in the profile.

```sh
TEAM=ABCDE12345 BUNDLE=com.example.dsmack ID="Apple Development: Your Name (XXXXXXXXXX)"
mkdir -p DsmackRunner.app/Contents/MacOS
cp dsmack-runner DsmackRunner.app/Contents/MacOS/ && chmod 755 DsmackRunner.app/Contents/MacOS/dsmack-runner
sed "s/dev.dsmack.provider/$BUNDLE/" Info.plist > DsmackRunner.app/Contents/Info.plist
cp your.provisionprofile DsmackRunner.app/Contents/embedded.provisionprofile
sed -e "s/DC9JH5DRMY/$TEAM/g" -e "s/dev.dsmack.provider/$BUNDLE/g" entitlements.plist > my.entitlements
codesign --force --options runtime --sign "$ID" --entitlements my.entitlements \
  --generate-entitlement-der --timestamp=none DsmackRunner.app
codesign --verify --strict --verbose=2 DsmackRunner.app
codesign -dvvv DsmackRunner.app 2>&1 | grep CandidateCDHashFull
```

Keep the five entitlement keys as they are apart from the team and bundle values: the
registry compares the rest byte for byte. Then check your copy and register it:

```sh
$PY $DSMACK/tools/release/inspect_runner.py DsmackRunner.app/Contents/MacOS/dsmack-runner \
  --expected-cdhash YOUR_CDHASH --expected-team $TEAM --expected-bundle $BUNDLE
$PY $DSMACK/contracts/cd_args.py DsmackRunner.app/Contents/MacOS/dsmack-runner > build.json
b(){ python3 -c "import json,sys;print(json.load(open('build.json'))[sys.argv[1]])" $1; }
cast wallet import claimer --interactive   # once: store your key in a foundry keystore
ACCOUNT=claimer CDS=0xD6567Da581BCcA8Ce965cD16785a43acbf3378f6 RPC=https://sepolia.base.org
cast call $CDS 'registerBuild(bytes,bytes,bytes)(bytes32)' $(b cd) $(b page0) $(b ent) --rpc-url $RPC
cast send $CDS 'registerBuild(bytes,bytes,bytes)' $(b cd) $(b page0) $(b ent) --rpc-url $RPC --account $ACCOUNT
cast call $CDS 'rpIdHash(bytes32)(bytes32)' $(b cdhash) --rpc-url $RPC
```

The `cast call` reverts with the field that differs (`code slots`, `page0`, `header`,
`entitlements`) if your copy does not match. `rpIdHash` must equal
`sha256("$TEAM.$BUNDLE")`.
