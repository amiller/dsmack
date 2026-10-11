# Authenticated Ethereum finalized guard state

This read-only experimental adapter uses genuine Helios Ethereum consensus and
execution verification. It does not sign, send transactions, deploy a guard,
select a live chain, or authorize a provider call. Ethereum Sepolia is the only
accepted development profile. Existing Base Sepolia/Mac configuration is unchanged.

The immutable Helios source is
[`2af9b41887e069144ee56cd710f3ddca195473f8`](https://github.com/a16z/helios/tree/2af9b41887e069144ee56cd710f3ddca195473f8).
The lockfile starts from that upstream dependency closure and preserves its
`ethereum_hashing` patch. A recent independently trusted beacon checkpoint is an
explicit bootstrap trust assumption. External checkpoint fallback and local
disk checkpoint overrides are disabled. Checkpoint age is enforced by Helios;
the operator must obtain and review the checkpoint independently of the execution
RPC. This is a light client, not execution of every beacon/EL block.

Checkpoint age, consensus slot selection and wall-clock freshness depend on local
`SystemTime`. The authenticated block timestamp does not authenticate that local
clock. This development profile assumes an honest clock and reports
`freshness_basis:"local-system-time-assumed"`; it does not qualify secure time.
Known CVMs with `secure_time:false` need a separately approved trustworthy clock
or a policy that explicitly retains this operator trust assumption. The service
must not relabel these bounds as authenticated wall-clock freshness. The fresh
unpersisted nonce and exact finalized consumed-state proof remain distinct checks.

## Verified path

Helios [Ethereum consensus](https://github.com/a16z/helios/blob/2af9b41887e069144ee56cd710f3ddca195473f8/ethereum/src/consensus.rs)
validates bootstrap and sync-committee finality updates against its configured
genesis validators root and fork schedule, then publishes an authenticated
finalized execution block hash. The execution provider fetches and validates the
block against that hash. The adapter freezes this finalized hash and performs
every guard read at that hash. It verifies:

1. Finalized timestamp is neither future nor older than the protected maximum.
2. Guard code hashes to the exact protected runtime bytecode hash, including
   immutable authority and policy values.
3. Proof-backed local EVM calls return the expected `issuer()` and `policyHash()`.
4. Proof-backed storage returns the exact current intent commitment at
   `consumed[coupon_digest]`. The reviewed guard's mapping is at storage slot zero.
5. Finalized state remains within the same freshness bound after the reads.

Helios [account access](https://github.com/a16z/helios/blob/2af9b41887e069144ee56cd710f3ddca195473f8/core/src/execution/providers/rpc.rs)
checks requested account address and storage slots, verifies MPT account/storage
proofs against the authenticated state root, and verifies code against the account
code hash. RPC responses and a caller-provided `finalized` flag cannot bypass it.
The adapter does not use optimistic/latest state as permission or silently retry
against another trust profile. Its output is a trusted local verifier result; a
JSON-shaped object supplied by a peer is not equivalent evidence.

## Invocation and exact contract

From this directory:

```sh
cargo build --locked
target/debug/dsmack-ethereum-finality --config /protected/profile.json
```

The trusted host sends one current intent JSON object through stdin and closes
the anonymous pipe; it does not write the process nonce to a file or argv. The
host adapter owns an overall kill/reap deadline, including stalled pipe input.
Configuration must be a protected regular file. Both inputs are exact objects,
capped at 64 KiB with unknown and duplicate fields rejected. Endpoints require
HTTPS or local HTTP and no URL user/password. The
profile contains:

```text
version: 1
trust_profile: "helios-ethereum-sepolia-finalized-experiment"
chain_id: 11155111
genesis_validators_root: "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
bootstrap_checkpoint: independently approved recent beacon block root
consensus_rpc, execution_rpc: operator-selected read-only endpoints
guard_address, guard_code_hash, issuer_address, issuance_policy_hash: exact authority pins
max_finalized_age_seconds: 60..7200 (operator's explicit finality/freshness policy)
timeout_seconds: 1..300
```

The intent is `{version:1,coupon_digest,recipient_commitment,accepted_offer_hash,
process_nonce}`, with nonzero 32-byte values. The recipient commitment is the
service's approved binding of the actual Noise winner and delivery public key.
The commitment uses Solidity `keccak256(abi.encode(DOMAIN,chainId,guard,issuer,
policy,coupon,Attempt(recipient,offer,processNonce)))`; it does not use SHA3-256,
JSON hashing or a receipt identifier. Mapping access follows the exact
[guard reference](../../../contracts/COUPON_ISSUANCE_GUARD.md).

Successful output has exactly version, trust_profile, upstream_sha, chain_id,
genesis_validators_root, bootstrap_checkpoint, finalized_block
`{hash,number,timestamp,state_root,receipts_root}`, verified_at_ms, freshness_basis and guard
`{address,code_hash,issuer,policy_hash,coupon_digest,consumed_commitment}`.
Failures print only a stable refusal and return nonzero. Config URLs, public
proofs and underlying provider errors are not printed.

## Consume-before-create invariant

The service generates a random 32-byte nonce for the current process, submits the
exact intent through its independently admitted transaction authority, and then
invokes this verifier through a trusted local adapter. A successful result can
grant one RAM-only permission to that process, consumed **before** provider POST.
The nonce/permission must never be persisted or reconstructed from a receipt.
Durable `issuing` intent precedes submission; crashes, unknown submission outcome,
stale/unavailable finality and failed proof verification preserve reconciliation
obligations and prohibit blind reissue. Existing delivered ciphertext may replay.

Exact finalized consumed state suffices for this minimum invariant: the protected
bytecode admits only the pinned issuer, binds all current intent fields and permits
one consume per coupon. Receipt evidence is not needed to infer success when the
fresh process intent is proven in that state. This does not prevent a live memory
clone from copying an already acquired permission; exclusion of cloning or an
independent exactly-once effect authority remains a custody requirement.

## Receipts, finality and remaining live inputs

The pinned upstream also verifies full receipt roots, transaction association and
metadata. A receipt's height at or below the finalized height alone does **not**
prove ancestry. Its default historical path uses EIP-2935 anchored to latest;
an optional finalized receipt audit must instead prove the transaction block's
hash at the frozen finalized root (or verify a complete authenticated ancestor
chain), then verify the receipt against that block. This adapter deliberately
uses finalized consumed state without making a transaction-provenance claim.

Ethereum finality normally outlasts the Mac contract's 60-second activity lease.
This guard profile has its own explicit freshness budget; it must not repurpose a
finalized historical activity bit as current Mac authorization. Revoked local
custody approvals stop new effects; immutable on-chain historical consumption
cannot be undone. A halted or stale chain refuses permission and leaves the
coupon obligation pending. The current attempt guard is not an external monotonic
configuration-generation anchor.

A positive live guard verification still needs an independently approved recent
checkpoint, working beacon/execution endpoints, an existing exactly pinned guard
and finalized consumed current intent. No guard deployment or transaction is
authorized by building this binary. Integrating a bounded live provider journey
also needs actual dstack measurement/custody approval, signed configuration and
generation authority, protected issuer transaction key and owner/KMS behavior.
There is no genuine live consumption result or production chain qualification in
the repository merely because this normal verifier is runnable.

## Checks

`cargo test --locked` checks the specific freshness, domain/intent and authority
validation failure cases. At the immutable upstream pin, the genuine offline
`helios-ethereum` consensus tests for valid finality, invalid finality proof and
invalid signature passed; these use public historical consensus fixtures and are
not claims of a freshly synchronized live chain. There is no synthetic consensus
adapter in the normal binary.
