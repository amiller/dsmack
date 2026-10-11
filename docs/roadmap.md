# Product roadmap and platform research

The [charter](charter.md) fixes two commitments: actual peer-to-peer operation
with DevProof constraints on privileged control, and optimism about verified
TEE services with explicit trust limits. dsmack is a peer-to-peer router for
private inference. It supports coupon redemption and acting as an API-key router
using contributed provider credits. Abalone is the curated skill and incognito
window with an easy client experience; it does not require the recipient to
manage issuer infrastructure. Anonymous on-chain coupon redemption is one way
to use this product, not its entire scope. The first useful outcome is a friend
redeeming one coupon budget for one usable, bounded $1 inference route. Delivery can use a qualified
provider-native credit, key or wallet adapter for direct use, or a `RouterBalance`
that authorizes routed requests consuming contributed API credits. One supported
route is enough for the first milestone; every provider, pool custody and full
settlement are not prerequisites. This roadmap describes intended outcomes, not
a deployment claim or completion of the charter's broader independent-operation
requirements.

## Product milestones

1. **Inspect and understand.** Make source, onboarding, contribution guidance,
   visual journeys and implementation status coherent. Prepare reviewed public
   repositories and explainer pages. Pass: a new contributor can identify what
   runs, what is proposed, and where to make a bounded change.
2. **Gift to one usable inference route.** A friend receives a funded coupon and,
   using Abalone, redeems a bounded $1 entitlement and completes a useful task
   through one qualified direct or routed adapter. No existing account, advance
   pairing or funded wallet is required; the network sponsors any required
   recipient gas. First claim binds the gift to locally generated recipient keys.
   Show the actual provider, model, privacy profile, price cap, budget unit/window,
   expiry and remaining credit. A capped API key can draw on shared account credit;
   it is not automatically an isolated or transferable $1 purse. Direct private
   issuance must separately establish who can obtain the secret; a routed balance
   does not demonstrate that property. Credit, retained state and recovery are
   understandable, and claims survive supported restarts and upgrades. Track the
   coordinated [dsmack](https://github.com/amiller/dsmack/milestone/2) and
   [Abalone](https://github.com/amiller/abalone/milestones) milestones and their
   [shared success conditions](https://github.com/amiller/abalone/blob/main/docs/gift-public-preview.md).
   A bounded trial closes only its declared outcome; it does not qualify all
   providers, pooled custody, supplier payouts or deposit settlement.
   Incognito session lifecycle and prompt confidentiality do not require a VPN.
   Node-contributed VPN access belongs to the later portable-agent milestone;
   it needs separate routing and anonymity qualification.
3. **Independent operator.** Demonstrate second-Mac first-open, real joining,
   participation NFT/artwork, explicit service opt-in, serving a client, quit,
   return and upgrade. Pass: an independently operated node completes the same
   coupon service and its selected direct or routed adapter, with measured setup
   friction and failure/recovery evidence. Participation artwork and the broader
   joining experience remain
   worthwhile work; they are not requirements for the friend's first inference.
4. **Supported release.** Pin protocol, dependencies, host trust and supported
   system versions; validate packaging, signing, admission and recovery. Pass:
   a newcomer can reproduce the documented journey from the public release.

These outcomes do not require choosing every implementation in advance. Competing
proposals for hosting, gas sponsorship, credential storage or settlement can be
developed in separate worktrees and compared against the same success conditions.
The released configuration must describe what it actually supports. Existing
pre-bound and accountless local experiments provide evidence for their narrower
scope; they do not establish a usable live gift or qualified private custody.

## Near-term spike: a second node joins and serves

Make milestone 3's joining path concrete before expanding the participant
directory. First exercise two processes on one host with distinct node identities,
separate protected state and ledgers, and different listeners/mailbox names. This
tests the protocol; it does not demonstrate independent operators or hardware.
Then repeat on an independently operated second Mac with genuine admission.

The native prototype identifies members by category and App Attest key ID, rather
than a device serial number. Its persistent state is scoped by network, category
and configured name, with a lock against concurrent reuse. A second process must
generate its own enrollment key; copying an identity or changing only its session
key is not a second member. The coupon service separately needs a distinct Noise
PeerId and issuer state. Qualify genuine same-device attestation and the selected
service policy; do not assume a new key grants another device allowance or issuer
authority. Native membership and coupon-service admission are separate paths.

Acceptance for this spike:

- A fresh process discovers an initial peer from documented bootstrap inputs,
  verifies the network/service policy and joins. Record required administrator,
  sponsor and signer actions, including any manual address exchange.
- Choose and document where authenticated, expiring connection/service records
  live, who can publish or change them, and how clients obtain them. An on-chain
  address directory is a design option, not current functionality.
- An Abalone client discovers the second service, verifies its identity and
  completes a bounded synthetic request; specify coupon issuer affinity and
  accounting ownership without implying cross-peer coupon portability.
- Reject copied identity/state, forged or expired advertisements and wrong
  admission policy. Exercise quit/return, stale records and unavailable bootstrap
  or relay infrastructure. Follow the local proof with real NAT/relay connectivity
  between independently operated hosts.

The current contracts record membership, measurements and accounting commitments,
not dialable IP/multiaddr/onion addresses. Current libp2p clients receive explicit
addresses; the native prototype uses configured relay mailboxes. Neither path
establishes automatic network-wide peer discovery today.

[Participant offers issue #9](https://github.com/amiller/dsmack/issues/9) tracks the
broader directory and consent/freshness behavior. Keep that later work distinct
from this near-term joining spike. The spike remains open until its actual
bootstrap, identity, admission and serving journey is recorded; a second process
starting successfully is insufficient.

Evaluate GitHub-hosted macOS runners as a separate capability probe: record the
actual OS/architecture, App Attest `isSupported`, fresh key generation,
attestation/assertion and our verifier's acceptance of the required code identity
and ACL policy. Hosted runners are VMs; ordinary macOS CI support does not prove
Secure Enclave access or genuine App Attest support. Apple's macOS App Attest
support starts at macOS 27. Also probe nested virtualization separately for the
container-serving runner. Keep unsupported results explicit; a self-hosted
physical Mac can automate the genuine-device path without establishing support
on GitHub-hosted VMs. See [GitHub runner constraints](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [Apple's App Attest platform and key requirements](https://developer.apple.com/videos/play/wwdc2026/201/).

Hosted probe result, 11 October 2026: on GitHub `xcode-27` (macOS 27.0.1,
arm64), the Developer ID signed probe with an all-devices provisioning profile
launched successfully but reported App Attest `isSupported=false`. The identical
signed archive on a physical Mac reported true and generated fresh attestation
and assertion accepted by our verifier under the category-6 Mac/CDHash/ACL
policy. This qualifies neither GitHub-hosted App Attest participation nor the
full container runtime; the hosted capability gate failed. See the
[completed signed hosted probe](https://github.com/amiller/dsmack/actions/runs/38168460162).

## Research track: threshold authorization and distributed key custody

Investigate quorum approval for admission, secret release and membership/epoch
changes, and distributed key generation with threshold signing or decryption.
Current full-secret replication lets one compromised custodian disclose the
complete secret. Multiple approvals need enforceable custody: a node that already
holds the full key can bypass a local approval policy. Threshold operations should
avoid reconstructing that key; releasing full plaintext still exposes it at the
recipient. Require independent devices and failure domains, and evaluate malicious
participants, availability, churn, share refresh and recovery. Two processes on
one Mac do not provide compromise independence.

This is a future research track, separate from completing the immediate joining
spike. Secure Enclave boot-state binding and App Attest admission evidence do not
establish confinement of replicated plaintext against an active kernel compromise.
The existing shared-key protocol does not implement threshold custody.

## Funding and delivery are separate choices

Funding can come from pool-owned stake/capacity or a contribution whose owner
retains provider-account control. Delivery can be direct or routed with either
source, when the selected provider actually supports it. Record retained owner
powers, including revocation, account recovery and limit changes; pooled backing
has its own signer, recovery and withdrawal powers to qualify. Do not equate
stake principal with immediately spendable inference credit: a staking adapter
must establish the actual allowance, accrual, renewal and withdrawal conditions.

One coupon budget selects one supported delivery path. A provider-native adapter
must qualify its real credit/key/wallet interface and debit semantics. A
`RouterBalance` requires new request handling and atomic budget reservations
before using contributed API credentials, plus settlement of actual usage and
quarantine of ambiguous effects. Those router mechanisms are implementation work,
not behavior already demonstrated by the coupon issuer. General supplier
accounting, pool economics and settlement follow their own acceptance gates.

Account-free, on-chain-only anonymous redemption is a priority target, not an
achieved property of generating a fresh wallet. A wallet-linked provider account
and its public funding history can remain identifiable or linkable. Qualification
must establish which observers can join the coupon, wallet, provider account/key,
debits and network/timing information, with evidence for the stated anonymity
profile. A first wallet transfer does not itself establish anonymous redemption
or instant inference-credit funding.

## Inference routing and admission

[The routing project](https://github.com/amiller/dsmack/issues/8) implements the
routed delivery path: useful responses, explicit data visibility, admission,
reservation/accounting and recovery. A routed answer does not demonstrate private
credential issuance, or vice versa. A direct adapter can satisfy the first usable
route without implementing the router.

Privacy requirements, TEE/admission policy, model identity, E2EE and price/budget
caps determine eligibility **before** latency selection. Choose among eligible
routes; speed cannot authorize a weaker privacy profile or a more expensive
request. Report coupon redemption time separately from request time to first token
and streaming throughput. An ambiguous paid request must not be automatically
replayed or sent to another supplier as a free retry; retain its reservation and
resolve whether an effect/debit occurred.

Disclose each plaintext boundary. The current NEAR host adapter would read prompts
if used as a router. It is not a recipient-encrypted relay. Preventing router
plaintext access requires a separately implemented and qualified recipient E2EE
relay; a TEE label alone does not supply that mechanism. Direct model E2EE and
issuer/API-key custody are distinct claims.

## Current trial evidence

As of 11 October 2026, the earlier operator-readable staging trial produced a
verified synthetic selected-text response through the direct encrypted NEAR path.
That cloud/TDX staging record is historical; it does not qualify the selected Mac
issuer. The public Abalone source/client preview is available at
[v0.1.0-preview.1](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.1),
with reviewed source and independently checked public asset downloads. New Mac
issuer readiness, the final public bundle and independent friend acceptance remain
pending. Identity-only Mac admission does not prove operator-resistant custody,
rollback protection, anonymity or deposit release. Incognito needs no VPN;
portable-agent/VPN and stronger isolation remain separate milestones.

## Platform research

Explore user-defined TEE services, restricted compose and future service
schemas, application contracts, independent sponsorship, market allocation,
attestation profiles, memory protection, succession and heterogeneous hardware,
including Pixels with verified boot and App Attest nodes under distinct trust
profiles.
Connect each motivating question to its proposals, experiments and findings.
Keep competing approaches visible, including what each demonstrated, what remains
unknown and where development is happening. Research can inform the release
without being required to finish first. The release needs evidence for its promised
properties in the chosen configuration, not completion of a general market or
every hardware, provider and economic research direction.

## Evidence needed

Separate retained RC3 cutover evidence, prototype runner tests, rendered journey
books and new device tests. Record unknowns such as new-participant artwork,
independent signing, host confidentiality, local-KMS authority and worker/client
code ownership. Maintain the personality of joining and NFT reveal while
measuring ordinary reliability and usefulness.
