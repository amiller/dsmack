# Re-signing and identity fixtures

Runtime code does not depend on a third-party application executable. The former
`darkbloom-*.json` CodeDirectory/first-page fixtures were removed on 2026-10-07.
The repository's older commits and research citations still record that earlier
experiment; removing a fixture does not erase its history or prior art.

## Actual executable measurements

- `A-original` through `I-dev-resign-same`: our App Attest probe and Apple
  codesign variants. The tests admit permitted re-signings and reject missing
  entitlements. `M-modified` changes executable code and is rejected.
- `node-honest.json`, `node-resigned.json`, `node-modified.json`: our peer node,
  a codesign re-sign with different signature allocation, and changed code.
- `iphone-honest.json`, `iphone-modified.json`: our iPhone probe variants.
- Development/Developer ID release fixtures and actual Apple attestation captures
  are also tested by `AppleAttestRegistryV1.t.sol` outside this directory.

## Synthetic identity tests

Run from the repository root:

```sh
python3 scripts/make_identity_test_fixtures.py
forge test --root contracts
```

The generator reads `node-honest.json` and produces:

- `node-synthetic-team.json`: changes the team/prefix to `TESTTEAM01` in the
  directory and entitlements, then recomputes the DER special-slot seal and CD hash.
- `node-synthetic-prefix-only.json`: removes the explicit team entitlement.
- `node-synthetic-prefix-only-other.json`: changes the prefix on that no-team case.

Code pages are unchanged. These are **not valid Apple-signed second-team apps**.
No certificate or private key is used, and no CMS signature is produced. They
exercise metadata binding, independent CDHash/RP lookups, mismatched-identity
rejection, and the requirement never to infer a team from an App ID prefix.
The lookup test also patches authData and bypasses cryptographic verification;
its name and comments deliberately do not describe an actual attestation.

A real independent developer team must still build/sign/run the app and complete
App Attest plus the account handoff before the Level 2 journey is accepted.
