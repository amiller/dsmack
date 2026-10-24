# Re-signing and identity fixtures

CodeDirectory, first page and entitlements of real builds, used by
`contracts/test/CDRegistry.t.sol`.

- `A-original` through `I-dev-resign-same`: the App Attest probe and Apple
  codesign variants of it. Re-signs with the same code and entitlements are
  admitted; builds without entitlements are rejected. `M-modified` changes
  code and is rejected.
- `node-honest.json`, `node-resigned.json`, `node-modified.json`: the peer node,
  a re-sign with a different signature allocation, and changed code.
- `iphone-honest.json`, `iphone-modified.json`: the iPhone probe and changed code.

`contracts/test/make_identity_test_fixtures.py` derives these from
`node-honest.json` by editing metadata and recomputing the special-slot seal
and CDHash; code pages are unchanged and nothing is re-signed:

- `node-synthetic-team.json`: team and App ID prefix changed to `TESTTEAM01`.
- `node-synthetic-prefix-only.json`: no team entitlement.
- `node-synthetic-prefix-only-other.json`: no team entitlement, prefix changed.

They test that the registry binds team and App ID from sealed entitlements and
never infers a team from the App ID prefix.
