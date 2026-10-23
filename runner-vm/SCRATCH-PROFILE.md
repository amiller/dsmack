# Separate scratch and result ceilings

This source candidate admits scratch templates up to 4GiB while retaining the
1GiB result and private-input limits. Public workload admission remains 4GiB.
The pilot still selects 600 seconds; the generic runner's existing 86400-second
ceiling is unchanged. The maximum is not an instruction to allocate that size:
authorized task/profile inputs must pin the exact template bytes and SHA-256.

`SOURCE-IMPORT.json` and `QUALIFIED-INPUTS.json` preserve historical app3 source
and archive provenance. `SOURCE-DERIVATION.json` lists every changed or added
source with before/after hashes and the new native inventory. Both builders
require its **independently selected digest**. Derived source refuses the
historical native archive shortcut: it needs a new independently pinned native
build record and archive. The unsigned build records the source derivation;
new signing and enrollment must bind the resulting application identity.

Swift uses one pure capacity implementation for admission and staged-copy
bounds. Native spec admission and actual template initialization separately
check their role's ceiling. System/workload/private roles cannot enter template
initialization. The result finalizer, result envelope and existing result checker
retain their 1GiB contract. The source checker verifies all unchanged imported
bytes and refuses unlisted source additions and symlinks.

A 4GiB browser run has not yet passed. The full reference browser image alone
exceeds 2.49GB; a measured headless-only spike is about 876MB, and the existing
ARM64 Claude harness is 854MB before workspace and temporary storage. The old
1GiB scratch cannot be assumed to support that complete profile. The next gate
is actual native ARM64 execution with measured peak disk/memory and headroom,
a named pinned browser sandbox preset, and the existing 600-second pilot bound.
No browser acceptance or payment authority comes from these ceilings.
