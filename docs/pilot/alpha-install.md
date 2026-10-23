# Authenticated alpha staging: candidate implementation

This source prepares an alpha installation without participant-authored approval
JSON. It does not yet constitute a distributed alpha release. A real release
inventory, detached signature and externally selected maintainer PUBLIC key are
required. The maintainer root is selected independently of this implementation; the example
commands do not create or adopt a release authority.

The initial bootstrap CLI must itself come from an inspected, trusted checkout.
A public key supplied inside the same untrusted archive is not a trust root.
Node24 is an explicit prerequisite; Python3 is also required. Bootstrap/2 records
the selected Node version, architecture, executable digest and actual loaded
non-system library closure. On macOS it retains the selected protected runtime
path; it does not pretend a copied Homebrew executable is portable. A private
standalone official Node24 ARM64 executable has passed a synthetic Mini staging
check. That bootstrap check was source/staging scope; later authenticated releases ran the final app on the Mini, with retained outputs
fully verified in the selected Linux verifier environment. Linux bootstrap copies the selected
standalone executable into its private directory.

The three-module verifier closure and stdlib staging helper are copied under a
fresh owned0700 directory. Group-writable runtime/source ancestry refuses.
NODE_* and DYLD_* injection variables refuse; child environment is sanitized,
and loaded-library membership is checked after authentication. OS shared-cache
libraries and the OS loader remain trusted. The bootstrap installs no dependencies
and generates no signing key. Startup trust in this inspected bootstrap and the
OS/interpreters is separate from authentication of a downloaded release.

Example commands, once actual release inputs are available:

```sh
mkdir -m700 "$HOME/.dsmack-alpha"
env -i HOME="$HOME" PATH=/usr/bin:/bin /PRIVATE/PATH/node applications/pilot-client/alpha-bootstrap.mjs \
  --trust-key maintainer-public.pem --key-id RELEASE_KEY_ID --channel alpha \
  --min-sequence MINIMUM_SEQUENCE --out "$HOME/.dsmack-alpha/bootstrap"
python3 -I "$HOME/.dsmack-alpha/bootstrap/alpha_stage.py" \
  --bootstrap "$HOME/.dsmack-alpha/bootstrap/bootstrap.json" \
  --inventory release.json --signature release.sig \
  --target "$HOME/.dsmack-alpha/version1" --plan
python3 -I "$HOME/.dsmack-alpha/bootstrap/alpha_stage.py" \
  --bootstrap "$HOME/.dsmack-alpha/bootstrap/bootstrap.json" \
  --inventory release.json --signature release.sig --archive release.tar.gz \
  --target "$HOME/.dsmack-alpha/version1"
```

The metadata arguments above describe public release trust, not signing keys,
credentials, operator enrollment secrets or locally invented approval verdicts.
The minimum sequence is supplied independently of the archive. The installer
also persists the accepted root/channel/sequence/inventory digest outside it.
An older sequence, silent root rotation, or different inventory at the same
sequence refuses. Revocation delivery and explicitly authorized rollback are not
implemented; users must not treat expiry checks as an online revocation service.

## Exact input contracts

Inventory/1 remains the earlier prototype. Installation requires
`dsmack-alpha-release/2`, signed over its schema followed by NUL and exact canonical
JSON bytes. Version2 adds an exact compressed archive descriptor and replaces the
prototype ticket hash with `notarization_evidence_sha256`: the public qualification
record's digest. That record must eventually bind the exact signed app/CDHash/leaf
and actual Apple outcomes. It is not a substitute for OS signature/notary checks.

Every file has an exact ASCII release-relative path, size, SHA256 and selected
0600/0700 mode. Case aliases and file/ancestor conflicts refuse. Each signed
profile descriptor uses a selected closed schema (`dsmack-alpha-profile/2` for
public-only tasks, or profile/3 for explicitly permitted private inputs) with exact role membership and
unique inventory-file references, including complete app, base, helper,
coordinator, verifier, public task scanner and installer source roles. The task
disk is separately admitted per attempt rather than fixed in this release. The historical initial admitted profile was
credential-free `bounty-board-search-browser-review-v1`, with4096MiB/1CPU,
600s runtime,4GiB scratch,256MiB result, no model and browser-sandbox-v1. These
resources and the compose/base digests are checked against file descriptors;
labels alone do not authorize them. Later releases also select closed development/generation private profiles; none
is implied by the presence of the installer. No arbitrary workload/profile
override is accepted. Private JIT consumes a strictly projected credential
document through protected stdin, not arbitrary configuration or environment
overrides. Private VM input files remain plaintext to the trusted Mac owner/root.

## Extraction and recovery

`--plan` performs informational signature/metadata and sizing checks without creating an installation. It does not consult persisted rollback state and reports install_admissible:null; actual staging enforces that additional floor.
It reports signed download bytes, the full expanded closure and free-space
requirements. Scratch is fully materialized: sparse extraction is **not** claimed.
When the archive is already downloaded, it requires the expanded bytes plus64MiB
free headroom. Before download, reserve download bytes in addition. Archive
construction, downloads and full-size qualification belong on Zed/Mini under the
workspace disk policy.

The installer checks the compressed archive hash and preflights raw tar headers,
all file bodies, padding and bounded trailing zeros before writing. Only USTAR
regular files and known directories are accepted; PAX/GNU/sparse, links, devices,
FIFOs, duplicates, traversal, unknown/missing members and trailing payload refuse.
The second extraction pass uses only exclusive regular files under a fresh0700
sibling directory, ignores archive ownership/modes and applies signed modes.
It reauthenticates/checks the staged closure before fsync and an atomic rename.

A private per-parent lock serializes protocol-compliant installers. A permanent
per-destination journal is fsynced before extraction; failures preserve incoming
files and refuse implicit retry at that destination. The monotonic release state
is durably advanced before final rename. A crash can therefore leave a stricter
floor and an incomplete installation, rather than silently permitting rollback.
These are conservative local guarantees, not global exactly-once installation or
indefinite retention. A trusted operator must inspect/recover preserved state;
this CLI never deletes uncertain output or replaces an existing version.

All staging output remains `launch_ready:false`. Production coordinator admission,
actual Apple signature/leaf/entitlements/stapled-notary/Gatekeeper checks and fresh
category6 enrollment remain distinct gates. The current engineering path retains its separate admission checks. The candidate
[alpha runtime adapter](alpha-runtime.md) adds real local OS checks; staging alone
never authorizes launch. See [metadata policy](developer-id-policy.md) and
[inventory prototype](alpha-release.md).
