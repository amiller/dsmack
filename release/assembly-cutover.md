# Assembly release admission plan

Status: RC3 cutover completed and verified on Base Sepolia at block 47831271.
The exact signed ZIP’s measured code is admitted, the persistent seed serves
epoch 1, and the operator’s existing Apple key/account/NFT survived reconnect and
restart. Both original owners remained unchanged; nextId stayed 3. Relay writes
resumed with no pending transactions. See [release verification](v0.1.0-rc.3.json).
RC2 is no longer admitted; friends must install RC3 without deleting saved state
or Keychain entries. No new NFT contract or personal-account factory was used.

The plan and engineering constraints below are retained for the next update.
They describe the gates rehearsed before this cutover, not an outstanding request
for approval. Clean friend first-open and independent-team acceptance remain open.

## Why installing the new UI is not enough

`CDRegistry.setBuild` replaces one approved normalized executable and its
`buildId`. `registerBuild` accepts independently signed copies of that executable;
it cannot register a different UI executable alongside RC2. `rpIdHash` returns
zero for registrations whose stored build ID differs from the current baseline.
Replacing the baseline therefore prevents RC2 from making fresh admitted
assertions. Existing members may remain active until their short check-in expiry;
a baseline change is not an instantaneous revocation of every previously
accepted request.

The dependency chain is fixed:

- `AppleAttestRegistryV1.cds` points to that CD registry.
- `DemoV1` categories pin the adapter and its code hash.
- `ResearchBadges` pins its network, adapter and category.
- `PersonalBadgeAccountFactory` and each personal account pin `ResearchBadges`.
- The artwork collection reads those original receipts.

Deploying another category or NFT factory is not a transparent update preserving
this entire claim path. Do not change the measured production network settings
or call `setBuild` merely to make a new download start working.

## What must survive an app update

Keep the same chain, factory, original badge policy, signed bundle identity and
Keychain access group. The personal key lookup uses the service
`dev.attestnode.personal-badge-key.v1` and an account name derived from
`keccak(chainId || factory)`. A new factory or inaccessible signing access group
can produce a different personal account. Test the exact signed update, not just
matching source settings.

`claimParticipantBadge` derives the personal account from that existing key (or
checks its linked invitation), verifies the account's badge policy and controlling
public key, then reads `participantOf(account)`. A nonzero token is reused only
after `ownerOf(token)` matches the account. It does not mint another participant
receipt in this case. A handed-off account must continue in its authorized copy;
this update must not bypass the handoff checks.

The isolated tests demonstrated both fresh enrollment recovering the same account
and an in-place update retaining the existing App Attest key. In the latter,
the local verification record
(`data/assembly-native-20261007/in-place-verification.json`, not a public download)
shows a changed admitted CDHash, unchanged key/member/account, successful new
assertions, token #1 reused and unchanged `nextId = 2`. No new Apple key was
created. These were two instrumented candidates on Anvil, not an RC2 friend’s
production installation or a public rollout.

## App Attest enrollment: test before deciding to rotate

The enrollment file is namespaced by chain, registry, category and participant
name. `Node.start` resumes an enrolled, unexpired key. It generates a new key for
an expired enrollment, but it does not currently implement a measured-build
migration or recovery from a stale cached enrollment.

The adapter stores the attestation public key and expiry, not an enrollment-time
CDHash. Each assertion supplies its own code evidence, checked against the current
baseline. It is therefore incorrect to assume that every app update necessarily
requires a new App Attest key.

The isolated same-key trial passed. Fresh App Attest enrollment is therefore a
fallback for an observed failure, not a required update step. Before release,
rehearse the intended update and recovery sequence on an isolated chain:

1. Preserve the same participant name, enrollment file and personal Keychain item.
2. Change only the test chain's approved executable and register the new signature.
3. Verify whether the existing Apple key produces an accepted assertion for the
   new executable. Record the member ID, code hash and account before and after.
4. If Apple requires fresh enrollment, implement and test a narrowly scoped,
   recoverable migration of the App Attest enrollment only. Preserve the personal
   key, linked-account file and original enrollment backup. Do not ask friends to
   delete Application Support or reset Keychain items.
5. Verify restart, existing NFT recovery, explicit handoff and rejected stale
   enrollment behavior. Surface a useful error instead of an endless retry loop.

## Seed, group key and rollback

The group key is separate from the personal NFT key and intentionally lives in
RAM. Admission currently cannot overlap old and new executables. Do not stop the
only admitted holder and assume the new build can retrieve its key afterward.

A planned maintenance cutover may use `DemoV2.startKeyEpoch(scope)` and bootstrap
a new shared key with the new admitted seed. That operation increments the epoch
and clears the chain commitment; it does not erase keys already delivered to old
peers. Every participating scope needs an explicit plan. Do not export the old
shared private key just to bridge the update.

Prepare a journal of the exact old baseline arguments, registrations, seed
bundle/configuration and public account/receipt facts. Pause sponsor writes and
reconcile the transaction queue before any owner operation; use the existing
nonce journal. Finish and reconcile owner transactions, then resume sponsorship so the new
seed can bootstrap through the relay. Verify its fresh key receipt before giving
friends the update.

Rollback means restoring the old baseline and signed seed with verified enrollment
state. Old registrations should become visible again when the identical old build
ID is restored; prove this on Anvil first. Epochs cannot be decremented. If the
commitment changed, rollback needs another explicit epoch/bootstrap and verified
old-build participants. Restoring a JSON file alone does not restore network state.

## Pre-cutover gates (retained for subsequent updates)

Do not disrupt existing friends to ship visual polish. Either complete an agreed,
rehearsed maintenance update with working rollback, or first design a compatibility
path. A separate presentation app around the unchanged admitted core is a possible
future architecture, not something this candidate implements or has tested.

A release requires:

- An ordinary signed/notarized build excluding every `ASSEMBLY_PREVIEW` and
  `ASSEMBLY_CAPTURE` hook; reproducible unsigned inputs and bundled art hashes.
- In-place old-to-new enrollment/account continuity and rollback evidence.
- A healthy persistent seed and verified current-epoch exchange after the change.
- Actual diagnostics export, readable native consent, supported-Mac first open,
  and an honest account of untested independent-team acceptance.
- Accurate artwork behavior: current bundled images are only the two verified
  historical public receipts. Unknown/new receipts show no borrowed Fold. An
  automatic renderer/publisher is still needed for new participant artwork.
- A friend-facing update note and one working download. Keep future candidates
  isolated until their production admission and continuity gates pass. The RC3
  prerelease still explicitly lacks clean friend first-open and independent-team
  end-to-end acceptance; these are not represented as completed by this cutover.

Relevant source: `contracts/src/CDRegistry.sol`, `AppleAttestRegistryV1.sol`,
`AppleAttest.sol`, `application/DemoV1.sol`, `application/DemoV2.sol`,
`application/ResearchBadges.sol`, `application/PersonalBadgeAccount.sol`, and
`node/shared/{Node,PersonalAccount,BadgeClaim,Upgrade}.swift`.

## Follow-up: retryable sponsor requests

A participant reads the shared sponsor’s application-request nonce before Apple
creates the assertion. Concurrent participants can race that nonce, producing a
retryable HTTP503. The GUI rebuilds the request and recovered in the observed
run; this was not an account-ownership failure. A serialized request/nonce path
is follow-up engineering work. Do not promise an instant or retry-free join.

The isolated registry rehearsal executed RC2→RC3→RC2→RC3 and restored the
previous registrations without re-registering them. Epoch rollback behavior was
checked as monotonic; no production rollback was needed. The live cutover changed
only shared scope 0 from epoch 0 to 1; empty Mac/iPhone category scopes were left
unchanged.
