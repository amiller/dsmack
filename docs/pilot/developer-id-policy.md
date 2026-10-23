# Developer ID metadata policy prototype

`applications/pilot-client/alpha_signing_policy.py` adds a separately versioned
`dsmack-developer-id-signing/1` parser. It preserves the current engineering
coordinator's Development-only policy. The explicit alpha parser checks the
selected team/bundle/Developer ID authority, exact independently selected full
CDHash, hardened runtime without ad hoc or linker-signed flags, and an unambiguous
Timestamp metadata field. Development authorities and missing timestamps refuse.

This is source preparation, not the production coordinator adapter. The parser
never invokes codesign, checks a certificate signature, or authenticates a release.
Its success reports `apple_signature_verified: false`, `launch_ready: false` and
other unperformed checks explicitly. A Timestamp line is not independently proved
by this parser. The selected operator must run codesign verification and verify
its cryptographic timestamp, compare the actual extracted leaf certificate digest
to the authenticated release, check the exact original HVF five entitlements,
verify the stapled ticket and default Gatekeeper assessment, then separately
perform fresh production/category6 enrollment. ARM64 and original source/build
correspondence checks also remain in the coordinator/release closure.

The current alpha inventory module requires Node (qualified here on Node24) for
built-in Ed25519 verification. It installs no dependency; future install/doctor
must report this prerequisite before credential import or claim. No production
maintainer root, download, notarization, or new Mac qualification is implied.

Run detecting controls:

```sh
python3 -m unittest discover -s applications/pilot-client -p alpha_signing_policy_test.py
```
