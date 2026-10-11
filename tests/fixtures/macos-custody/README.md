# Selected macOS regression inputs

Selected unchanged cryptographic inputs from `app/macos/custody/custody-20260916T173508Z` at public commit
`761cd18dc87f26b5fa72ccc8639ab7a0fbd74982` (original captures dated 16 September
2026). [manifest.json](manifest.json) records SHA-256 for every retained input.

The regression scope is: Five Apple-rooted custody transcripts, stale delivery, receiver-key substitution and authority binding. Tests use an explicit historical certificate-valid
time. These fixtures do not qualify a fresh identity, current issuer or production
secret custody. They contain public key identifiers, nonces, synthetic protocol
values and signed evidence; no provider credential or private signing key is included.

`probe` files are recorded signed executables consumed only as data by
CodeDirectory/page-hash tests and authority-binding checks. They are not executed.
The tests require their exact bytes. The selection excludes logs, runtime reports,
source copies, screenshots and intermediate builds. Full historical records are
outside the current tree.
