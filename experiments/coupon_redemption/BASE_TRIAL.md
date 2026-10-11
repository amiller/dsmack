# Base mainnet debug trial guard

The explicit `base-mainnet-rpc-safe-debug-v1` profile uses chain 8453 and
`https://mainnet.base.org`. It trusts that configured HTTPS RPC's `safe` view;
it does not verify L1 finality or replace the separate Helios Ethereum profile.
The signed staging approval carries the exact confirmation descriptor:

```json
{"version":1,"profile":"base-mainnet-rpc-safe-debug-v1","block_tag":"safe","rpc_url":"https://mainnet.base.org","trust":"configured-rpc","l1_finality_verified":false,"reorg_action":"quarantine-no-retry"}
```

Only operator-readable debug staging with synthetic prompts and an aggregate
cap of at most $5 can use this profile. The recipient must verify the signed
approval and disclose RPC trust before presenting a bearer coupon. The profile
provides neither private custody nor rollback qualification.

The config's existing `finality_profile` field uses an exact Base schema:
`version`, `trust_profile`, `chain_id`, `execution_rpc`, `guard_address`,
`guard_code_hash`, `issuer_address`, `issuance_policy_hash`,
`max_safe_age_seconds`, and `timeout_seconds`. Guard pins must match the signed
approval. Freshness depends on the disclosed local host clock.

Each live attempt generates a fresh RAM-only nonce, signs and submits one
transaction, then checks its exact successful receipt and calldata. The selected
safe block must cover the canonical receipt block. Guard code, immutable issuer
and policy, and the exact consumed intent are read at the same safe hash using
EIP-1898 with `requireCanonical`. The adapter checks that hash again, rechecks
that the current safe head has not dropped below it, and checks age and deadline
before returning one permission to the immediately following provider POST.
Missing state, mismatch, reorg, timeout or an ambiguous submission quarantines
that claim. It never resubmits or reconstructs permission from stored receipts.

A mainnet deployment/funding packet must separately bound actual execution gas,
L1 data fees and any active operator fee. The former Ethereum Sepolia spending
cap is not a Base mainnet spending authorization. Deployment or image updates
require new measured identity and signed policy pins. Existing grants, winners,
reservations and quarantined attempts must survive explicit offline migration;
old offers must not acquire new provider-creation permission.
