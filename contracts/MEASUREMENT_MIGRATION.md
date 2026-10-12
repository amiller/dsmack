# Measurement registry migration

Deployed on Base Sepolia 2026-10-12: `contracts/network/deploy-measured-base-sepolia.json`
(`scripts/release/deploy_measured.py`). No measurement is admitted yet; the old category and
`ResearchBadges` are unchanged.

`MeasurementRegistry` admits code measurements (`Measurement.sol`) in block windows instead of
one `CDRegistry` baseline. `AppleAttestMeasuredV1` is the matching adapter. It keeps
`cds()`, `rpIdHash`, `teamIdHash` and `bundleIdHash`, so `Upgrade.swift` reads it unchanged.

DemoV2 `0xd4B33C83576a6049d29c6B849ec73491e52781a0` pins each category's adapter code hash, so the
cutover adds a category instead of swapping the adapter:

1. Deploy `MeasurementRegistry`; `admit(M, from, until)` for each released flavor (GUI, CLI).
2. Deploy `AppleAttestMeasuredV1(DemoV2, registry, aaguid, validationCategory, false)`.
3. `addCategory(family, policy', adapter, true)` with a new `policy'`: the id is
   `keccak256(1, family, policy)` and an existing id reverts. Then `setCategoryEnabled(id, true)`.
4. Seeds on the new build join first. Scope 0 serves every overall-eligible category, so the
   old seeds deliver the key to them with `keyEpochs(0)` unchanged.
5. Disable the old category once the old seeds have handed over.

Member ids change with the category. `ResearchBadges` takes an `AppleAttestRegistryV1` and
pins the old category; badges on the new category need an owner decision.

A release opens `M_new` and sets the old window's expiry to now plus the overlap
(`admit(M_old, from, now + overlap)`). Revoking a vulnerable build is `revoke(M)` plus
`startKeyEpoch`.
