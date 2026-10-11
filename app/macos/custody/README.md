# App Attest custody probe

This lab code compares a synthetic Keychain-stored signing secret with an
attestation-bound, memory-only key-delivery protocol. It separates code recognition
from protection of a delivered secret. A modified same-credential/access-group
build attempts to use persistent key material; the volatile path checks restart,
stale delivery and fresh authorization.

`run_experiment.py` is an interactive coordinator using an explicitly authorized
Mac signing rig and SSH transport. It holds synthetic authority/category keys
in RAM. It creates capture output outside the maintained source tree; configure
paths, signing and credentials for the selected lab before running it.

The volatile protocol binds a fresh transport key, session and challenge to
App Attest. Parcels carry a signature under the authority pinned in the executable.
Restart loses the transport key and requires a new authorization; losing all
volatile category-key holders loses access. Revocation does not erase a live
process's memory. This experiment does not establish protection against kernel
attacks, swap, hibernation, debugging bypasses or physical memory forensics.

Selected [regression inputs](../../../tests/fixtures/macos-custody/README.md)
preserve historical cryptographic replay and adversarial tests. The full lab
captures and result reports are outside the current source tree.
