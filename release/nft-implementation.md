# Two-level NFT implementation notes

Status: contracts, Mac participant claim client, and relay routes implemented locally;
Level 1 deployed and exercised with real Mac attestation on isolated Anvil.
See [the screenshot and agent transcript](agent-transcript-nft.md). Public Base
Sepolia NFT distribution and the Level 2 live journey remain incomplete.
The signed v0.1.0-rc.1 app still implements only shared-key participation.

`ResearchBadges` is separate from the legacy sponsor-owned NFT action. It uses a
normal sponsored network `Receipt` action, with `envelopeDigest` bound to the
badge's domain-separated `claimDigest`. The app must explicitly produce this
additional receipt after acquiring the shared key; an ordinary peer-exchange
receipt cannot be repurposed as a badge claim.

The recipient also signs the claim digest, using an EOA or an ERC-1271 personal
account. The relay cannot change the recipient, level, parent, key identity, or
deadline. It may submit the transaction and pay gas. The intended zero-setup
client creates a personal account locally; its key is distinct from the shared
network key. `PersonalBadgeAccount` and its deterministic factory now implement that personal
recipient. The account accepts badge consent only from the configured badge
contract. Consent binds chain, account, and control generation. A handoff requires
both current-key approval and new-key proof of possession, binds a deadline, and
increments the generation so prior approvals cannot revive even if a key is
later reused. The account does not execute arbitrary calls or support spending
funds; it is a narrow NFT-control account, not a general wallet.

The Mac `PersonalAccountKey` implementation stores a separate P-256 software key
in the signed app's non-synchronizing, device-only data-protection Keychain. It
fails on Keychain errors instead of replacing an inaccessible identity. A signed
Mac test passed create/reload/sign with a random test scope and removed its own
entry afterward. CryptoKit-generated consent and handoff signatures also passed
Solidity P-256 verification. Tests use publicly known fixture keys only in the
vector executable, never in the participant or Keychain test.

The Mac participant now attempts Level 1 automatically after joining, verifies
confirmed ownership, and retries claim errors without disconnecting the peer.
It consults `participantOf(account)` on restart to reuse the existing NFT. The
release must pin both badge and factory addresses; RC2 pins both addresses and has passed a real Base Sepolia participant claim
and packaged restart. Sponsored account creation requires an additional fresh
network receipt bound to the proposed public key, factory, chain and member.

The working branch now includes the [developer-upgrade UI](builder-guide.md),
public invitation/request files, original-key approval, and automatic Level 2
claims after confirmed handoff. It validates the new app's on-chain assertion
context and independently signed code identity before exposing the approval
prompt, then revalidates immediately before signing. Peer work and upgrade
operations run on one serialized node worker. A request expires or must be
regenerated if a later assertion supersedes it. The full second-team journey is
not yet live-validated. The handoff will
exchange public keys and narrowly bound signatures, never the private key.
Retain the original app/key until the handoff confirms. There is no sponsor reset
or recovery backdoor: losing the controlling key before handoff loses control of
this research receipt. This limitation must be visible before the user deletes
an installation; it must not be described as permanent hardware identity.

The evidence-enabled Apple adapter stores only successfully verified assertion
context, CDHash, RP hash, counter, and verification time. Enrollment alone is not
claim evidence. Badge validation checks the exact network request context, fresh
receipt deadline, active member, current code admission, and recipient consent.
An epoch change invalidates outstanding key-receipt contexts.

Level 1 is limited to one claim per network category/App Attest key. It is not
one claim per physical Mac, human, or wallet. Level 2 also requires a sealed bundle identifier of
`dev.attestnode.builder.a` followed by the recipient account's lowercase `0x`
address. A borrowed build for another recipient cannot qualify. The CD registry
extracts the bundle suffix separately from the App ID prefix, and the NFT contract
checks its hash against the recipient. This proves team-authorized signing for
the specific account, not possession of Apple credentials by a particular human.
Level 2 is limited to one claim per
verified non-publisher signing team and one upgrade per Level 1 badge. Both
badges belong to the same recipient and are non-transferable historical receipts.
These limits are explicit research-demo policy, not evidence of human uniqueness.

`CDRegistry.teamIdHash` uses SHA-256 of the explicit sealed
`com.apple.developer.team-identifier` entitlement. Missing team entitlements return
zero and cannot qualify for Level 2. An App ID prefix is not substituted. Registry
registration is permissionless and does not prove an Apple signature: the live
App Attest assertion for that CDHash and RP is the necessary second check.

Deployment requires a new evidence-enabled adapter/network configuration. The
live deployed contracts are immutable; changing source files does not upgrade
them. Preserve the current seed until replacement network admission and client
builds are verified. Measure the additional enrollment/receipt gas before launch.

Tests:

```sh
forge test --root contracts
```

`ResearchBadgesTest` isolates badge policy with mocked verified evidence. It is
not a device integration test. `AppleAttestRegistryV1Test` separately exercises
actual Apple certificate/assertion fixtures and verifies that failures/replays do
not write successful assertion evidence. Neither substitutes for the pending
second-team, real-device NFT journey and screenshots.


Mac validation (local signing keychain already unlocked):

```sh
python3 scripts/release/test_personal_account_mac.py --out build/account-tests \
  --identity "$MAC_SIGNING_IDENTITY" --keychain "$SIGNING_KEYCHAIN" \
  --profile "$MAC_PROFILE" --entitlements "$MAC_ENTITLEMENTS" \
  --bundle-id "$APPLE_BUNDLE_ID"
```

Use an unused output directory. The signed development test bundle includes a
provisioning profile and stays private. `results.json` contains only public test
vectors and the persistence-test result. Its scope is component validation, not
screenshots or evidence that the friend's complete NFT journey already works.
