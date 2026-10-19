# macOS VM App Attest and serial probe, 2026-10-12

Host: the mini (macOS 27.0, 26A428, SIP on). Guest: `ghcr.io/cirruslabs/macos-golden-gate-vanilla:27.0`
(macOS 27.0, 26A428) run with tart 2.40.1 (Virtualization.framework). Only hashes of identifiers are
recorded. The VMs, the image cache and tart were deleted afterwards.

| Run | serial_sha256_16 | App Attest supported | generateKey | DeviceCheck token |
|---|---|---|---|---|
| host, signed (`probe/host-signed.txt`) | <redacted> | true | ok, attest 5938 B | 2236 B |
| host, ad hoc | <redacted> | false | error 1 | 2258 B |
| gg1 guest, ad hoc | <redacted> | false | error 1 | 3534 B |
| gg2 = clone of gg1, same ECID | <redacted> | false | error 1 | 3528 B |
| gg3 = clone, `tart set --random-serial` | <redacted> | false | error 1 | 3534 B |
| gg4 = clone, ECID set by hand to 0x1122334455667788 | <redacted> | false | error 1 | 3528 B |
| gg1 guest, signed dev build | did not launch | | | |

- The signed development build was killed by AMFI in the guest. The error was "No matching profile
  found" and "Restricted entitlements not validated", because the development provisioning profile
  does not list the VM's provisioning UDID (`guest1-signed-diag.txt`).
- The guest reports Full Security, SIP and Signed System Volume enabled, and Signature Type "Other"
  where the host reports BAA (`guest1-security.txt`). It reports `kern.hv_vmm_present=1` and model
  `VirtualMac2,1`.
- `VZMacMachineIdentifier` serializes as a bplist holding a single integer `ECID`, which the host
  chooses. The guest serial is a deterministic function of the ECID: a copied ECID gives the same
  serial, and a new or hand-picked ECID gives a new one. Guest serials look like `Z` followed by
  9 alphanumerics.

## Follow-up with a profile that lists the VM (`vmtag/`)

A separate dev profile "dsmack provider vm-test" covering the mini and a recreated guest. The
tag probe was rebuilt with it (CDHash 5948685b…).

| Run | App Attest supported | generateKey | core.py |
|---|---|---|---|
| guest, signed tag probe, two enrolls (`vmtag/guest-runs`) | true | DCError 0 | no attestation produced |
| guest, signed plain probe (`guest2-signed-plain.txt`) | true | DCError 0 | n/a |
| host, same build (`vmtag/host-enroll`, `host-assert`) | true | ok | attestation + assertion accepted, CDHash matches, counter 1 |

`vmtag/guest-keystore-log.txt`: devicecheckd's system-keychain add fails with -25308 "keychain is
locked" (bag -6), and `aks_get_extended_device_state` returns 0xE00002F0 (unsupported). Verify with
`python3 vmtag/verify_vm.py <unix-time inside the leaf validity, e.g. 1791871200>`.
