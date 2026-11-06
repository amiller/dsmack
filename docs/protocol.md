# Dsmack layered execution protocol

## Conventions and composition

This specification defines the public contracts between a requester, a relay
broker and an operator's Mac running a Linux guest. It specifies six layers:
manifest, evidence and appraisal result, session, receipt, heartbeat, and MacLink.
Applications select a profile rather than inventing another evidence format.
The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY and OPTIONAL have the meanings in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when capitalized.

A format identifier selects a complete contract. Implementations MUST reject an
unsupported identifier and MUST NOT silently reinterpret another version. This
document defines `dsmack.manifest/5`, `dsmack.evidence/1`, `dsmack.result/1`,
`/dsmack/session/1`, `dsmack.receipt/5` and `dsmack.heartbeat/1`. MacLink uses its
EIP-712 primary type and domain. A manifest selects the workload; evidence binds
its execution identity; a session admits a requester; receipts measure delivered
service. Heartbeats advertise availability. MacLink identifies the operator
associated with the publisher. None substitutes for another layer's checks.

Unless a field explicitly says otherwise, JSON hashes and raw public keys use
lowercase hexadecimal without `0x`, timestamps are integer Unix seconds, and
sizes are bytes. Ethereum addresses and EIP-712 byte strings use `0x`. Byte
concatenation is written `||`. `sha256` returns 32 bytes; it MUST NOT hash the
hexadecimal rendering of its input. Peer strings are base58btc representations
of multihashes; binding uses the decoded multihash, without a multibase prefix,
CID wrapper or text encoding. Integers beyond JSON's exact range MUST be decimal
strings at JSON boundaries.

Canonical JSON means UTF-8, lexicographically sorted object keys, no insignificant
whitespace, no duplicate keys and no non-finite numbers. Arrays retain order.
Protocol fields MUST use integers or strings rather than fractional numbers.
The embedded Compose string MUST itself contain canonical JSON before the outer
manifest is serialized. A verifier MUST hash the admitted bytes and MUST NOT
normalize signed or measured bytes on receipt. A directory's copy of a manifest
is an input to policy selection, never policy authorization by itself.

The worked examples below refer to repository fixtures and the tests that
consume their actual bytes. Historical artifacts retain their original format
identifiers and signatures. A projection into these layer names is an explanation
of those bytes, not a replacement signature or a claim that an earlier manifest
implements version 5. The unified binding has no old-layout admission mode.

## 1. Manifest — dsmack.manifest/5

A manifest is the requester's execution contract. Its `schema` MUST be
`dsmack.manifest/5`. Its identity is `sha256(canonical_manifest_bytes)`.
An admission policy MUST select this identity independently of a node's
registration. A workload image MUST use an OCI `sha256:` digest, not a mutable
tag. A manifest MUST bind the base VM, Compose workload, resource limits,
network policy, input delivery and output collection. A changed policy is a
new manifest identity even if it runs the same application.

`base_vm` MUST name the architecture, `os_image_hash`, kernel and initrd hashes,
root filesystem hash, metadata hash, kernel command line, memory and vCPU count.
When verity is used it MUST also bind the verity root and immutable filesystem
size. `os_image_hash` identifies the base checksum document's exact bytes; it is
not a self-asserted marketing name for an image. The signed runner MUST compare
the selected launch configuration against these pins before starting the VM.
The kernel command line MUST NOT allow a requester to replace the measured
init process or weaken the selected storage policy.

`docker_compose_file` MUST be a canonical JSON string containing the restricted
Compose document. Each service MUST have a digest-pinned image and an explicit
entrypoint or the pinned image's entrypoint. A multi-service workload MUST name
its completion service. Runtime selection, runtime executable identity,
mounts, environment, network access and completion behavior MUST be measured.
Inputs MUST have explicit service audiences. A writable mount MUST NOT expose
runner state, host credentials or another conversation's workspace. Agent tool
processes MUST NOT inherit access to the guest coordinator's attestation socket.

`limits` MUST bound execution time, workspace bytes and collected output bytes.
The VM's watchdog MUST start at VM boot, not at broker registration or the first
tool call. Admission MUST leave enough lifetime for the admitted operation and
final evidence export. A guest MUST stop admitting before its watchdog expires.
A process timeout and a whole-VM timeout are separate limits. An application
MUST NOT advertise the larger whole-VM limit as a per-command allowance.

The network contract MUST state whether networking is disabled or uses the
measured gateway. `network.egress` contains destination CIDR, transport protocol
and destination port tuples. `network.egress_hosts` contains exact DNS hostnames
and ports for a hostname-enforcing gateway. An empty list authorizes no hosts.
Wildcards MUST NOT be inferred. The gateway MUST reject destinations outside
both the measured transport rules and hostname policy, including redirects to
unadmitted destinations. Resolution MUST NOT authorize a hostname to reach a
private host address merely because it previously resolved to a public address.

`network.inbound` contains service, protocol and guest port entries. An omitted
or empty inbound list means no unsolicited inbound application ports; it does
not disable an expressly measured relay transport. Published discovery addresses
MUST NOT widen this list. The Mac's loopback relay and a public circuit locator
are routing infrastructure, not permission to expose arbitrary guest services.

`monitors` is an array of digest-pinned monitor definitions, each naming its
service, executable or image, observed events and failure action. A REQUIRED
monitor failure MUST terminate or refuse the operation it guards. A monitor
MUST NOT be reported as active solely because a directory lists its name.
Monitor output used in appraisal MUST be committed by the attested event log or
signed result. An empty monitor list asserts no additional monitoring policy.

`inputs` and `outputs` MUST describe delivery and collection paths. A requester
MUST check ciphertext integrity and the selected sealing key before delivering
secrets. Output collection MUST remain within the declared artifacts directory;
path traversal and symlinks outside it MUST be refused. The manifest's limits
apply to collected bytes as well as process output. The harness or tool server
MUST be part of the image measurement, rather than downloaded after admission.

The recorded [compute manifest](../applications/compute-node/testdata/compose-manifest.json)
is an exact version-4 example of the base, Compose and limits components. It
selects an aarch64 VM with 4096 MiB and one vCPU, a digest-pinned compute image,
a `node` service and an explicit proxy. Its historical worker entrypoint MUST
NOT be described as the later MCP server. The production manifest builder is
[workload.py](../applications/compute-node/workload.py); its
[existing tests](../applications/compute-node/test_workload.py) check measured
agent settings, resource sizing and the Mac gateway policy. Version-5 producers
MUST supply the additional host, inbound and monitor policy explicitly; a
version-4 hash MUST NOT be relabeled as a version-5 hash.

## 2. Evidence and result — dsmack.evidence/1 and dsmack.result/1

### Roles and appraisal

The vocabulary follows [RATS](https://www.rfc-editor.org/rfc/rfc9334): the Mac
runner and guest form the Attester, Apple supplies endorsement material, approved
builds and workload measurements supply reference values, and a Verifier
appraises evidence under a selected policy. The browser or secret releaser is
the Relying Party. A broker can act as a Verifier for registration; a browser
can independently act as a Verifier before opening a confidential session.
A relay or directory that only forwards bytes acquires neither role by doing so.

`dsmack.evidence/1` is a JSON envelope with `schema`, `attestation`, `peer`,
`seal_pubkey`, `receipt_pubkey` and `freshness`. `attestation` is the hexadecimal
encoding of the exact dstack VersionedAttestation bytes. `peer` is the transport
PeerId. The key fields contain the profile's exact public-key bytes defined
below. `freshness` is either `{mode:"challenge", challenge:HEX32}` or
`{mode:"epoch", admit_until:SECONDS}`. A consumer MUST select its allowed
freshness mode before trusting these fields. Merely decoding this envelope is
not appraisal.

The VersionedAttestation is MessagePack version 1, with platform kind
`apple-app-attest` and stack kind `dsmack`. Platform data carries `key_id` and
an App Attest assertion. Stack data carries 32-byte `os_image_hash`,
`manifest_sha256`, `run` and `caller`, 64-byte `report_data`, and the event log.
`caller` is the SHA-256 of the service name. The Verifier MUST replay the ordered
event log and reconstruct the client data before checking the assertion. It
MUST reject an unsealed log or events after the seal boundary.

The App Attest client data is the UTF-8 domain `dsmack.appattest.guest-attest/1` followed
by `os_image_hash || manifest_sha256 || run || event_head || caller || report_data`.
The reference [guest encoder](../dstack-compat/guest_attest.py) defines the
byte-level envelope and event-log framing. The App Attest signature MUST be
checked with the enrolled key, the expected app identity and validation category,
an approved runner CDHash, the enrollment lifetime and assertion counter policy.
A Verifier MUST also check image and build revocation policy. A valid signature
without admitted measurements MUST NOT authorize execution or secret release.

### One report_data binding

Every peer service MUST use this exact layout:

```text
first = sha256(UTF8("dsmack.bind/1") || peer_multihash || seal_pubkey || receipt_pubkey)
report_data[0:32]  = first
report_data[32:64] = sha256(first || challenge)
```

There is no terminator, length prefix, ABI encoding or implicit padding in
`first`. Profile-selected key lengths make concatenation unambiguous. A plain
attested echo peer has empty seal and receipt key byte strings. A metered egress
relay has an empty seal key and a 32-byte raw Ed25519 receipt public key. A
compute guest has a 64-byte P-256 seal public key `x || y` (no SEC1 `04` byte)
and a 32-byte raw Ed25519 agent receipt public key. During the existing dual
receipt deployment, paid compute's `receipt_pubkey` is exactly that Ed25519 key
followed by the 33-byte compressed SEC1 secp256k1 settlement receipt public key.
A receipt-5-only profile uses only its 33-byte compressed secp256k1 key. Profile
selection MUST establish the encoding; a Verifier MUST NOT guess a layout after
a hash mismatch.

The settlement public key is advertised as `payments.receiptPublicKey` using
`0x` hexadecimal. Its Ethereum address MUST equal `payments.receiptSigner`.
Binding only an address or the Ed25519 key does not authenticate the settlement
key. A dual-key deployment MUST bind both keys; neither receipt format is
converted by this binding. The payment run metadata and EIP-712 authorization
remain separately validated against enrollment, admitted workload and chain
policy. They are not additional bytes in `report_data`.

In challenge mode, `challenge` MUST be a fresh, unpredictable 32-byte nonce
selected by the Verifier. The Verifier MUST compare with its outstanding nonce,
expire it, and consume a broker admission challenge after successful admission.
A browser MUST use its own challenge rather than adopt a broker or directory's
nonce as fresh. A node MUST reject a request with a differently sized nonce.
A new assertion MUST cover each fresh challenge. A signature counter alone MUST
NOT be treated as a response to a Verifier's challenge.

In epoch mode, `challenge` MUST be exactly 32 zero bytes. The second half remains
`sha256(first || ZERO32)`; it MUST NOT be all zero bytes. The Relying Party MUST
bound admission by its selected epoch and the measured guest lifetime.
`admit_until` is an admission cutoff, not an assertion that the node was recently
challenged. A directory's unsigned cutoff MUST NOT extend a measured lifetime
or a broker-signed authorization. An existing admitted session MAY finish within
its grant after the node stops accepting new sessions.

The transport connection's authenticated remote PeerId MUST equal `peer`.
A matching circuit destination suffix alone is insufficient. The Verifier MUST
compare the entire 64-byte report, not just the identity half. The old peer,
compute and payments-v2 layouts MUST be rejected; there is no compatibility
negotiation. Key possession is then exercised by Noise, sealing and receipt
signatures, respectively.

### Appraisal result and claim names

`dsmack.result/1` contains `schema`, `status` (`affirming` or `contraindicated`),
`policy`, `iat`, `exp` and `submods`. `policy` identifies the independently
selected appraisal policy. `iat` and `exp` bound the result's validity; they MUST
NOT extend evidence or grant lifetime. `submods.guest` holds guest claims and
`submods.runner` holds runner build and enrollment claims. A failed appraisal
MUST NOT return an affirming result with missing checks. An unsigned local
result is valid only within the Verifier process that produced it. A result
forwarded to another Relying Party MUST be authenticated by a trusted Verifier.

The following names follow [EAT](https://www.rfc-editor.org/rfc/rfc9711):
`eat_nonce` is the challenge, `swname` and `swversion` describe measured software,
`measurements` carries manifest and image measurements, `eat_profile` identifies
the selected attestation profile, `submods` separates
entities, and `iat`/`exp` describe issuance and expiry. Binary values in a JSON
EAT claim projection use base64url without padding, distinct from the raw hex
wire envelope. `ueid` MUST be omitted unless a producer has an identifier meeting
EAT's UEID requirements; an ephemeral PeerId MUST NOT be labeled a UEID.
Dsmack-specific fields such as `peer`, `run`, `caller`, `event_head` and
`report_data` retain their own names. The JSON result adopts an appraisal-result
shape; it is not an EAR or JWT conformance claim.

For a worked cryptographic example, [relay.json](../applications/relay-broker/fixtures/relay.json)
contains a recorded registration, enrollment pin and approved app identity hash;
[compute.json](../applications/relay-broker/fixtures/compute.json) contains the
recorded compute assertion. The [binding tests](../dstack-compat/binding.test.mjs)
verify those historical Apple signatures and require their old layouts to fail
admission. [bind.json](../applications/relay-broker/fixtures/bind.json) supplies
valid synthetic P-256 signatures over the recorded guest identities for the
new binding; it is explicitly a test assertion, not Apple enrollment evidence.
Both the JavaScript reference test and [Python reference test](../applications/libp2p-attest/test_binding.py)
read these same bytes. The independent Apple-root enrollment and assertion
examples in [tests/fixtures](../tests/fixtures/README.md) are consumed by
[test_independent.py](../tests/test_independent.py).

## 3. Session — /dsmack/session/1

A session is a libp2p byte stream authenticated to the attested guest PeerId.
The requester MUST finish evidence appraisal before sending plaintext or sealed
workload secrets. The connection MUST use an authenticated encrypted libp2p
transport such as Noise. A relay MUST NOT terminate that guest connection and
present its own PeerId as the attested guest. A routing hint MAY change without
changing guest identity, provided the authenticated destination still matches.

The first message is a four-byte unsigned big-endian length followed by that
many UTF-8 JSON bytes. It is an admission frame with `grant`, `signature`, and
`mode`, where `mode` is `mcp` or `batch`. The admission frame MUST be bounded to
64 KiB before allocation. The signature authenticates the grant under its
selected grant scheme; it is not a signature over arbitrary frame whitespace.
The grant MUST name the guest or run, requester identity, budget unit and amount,
issue time, expiry, and destination policy. A purchase-backed grant MUST also
name its purchase and escrow domain.

The guest MUST check the grant signer against its measured configuration,
authenticate the client against the Noise remote identity, check target, unit,
budget, expiry and replay state, and exclusively claim the authorized work.
For an Ed25519 client, the purchase's buyer key MUST match the public key
extracted from the remote identity multihash. A grant signature belonging to
another buyer MUST NOT authorize the stream. Claims on a conversation workspace
MUST be exclusive even if the same buyer opens two connections.

The response uses the same length framing and is either `{status:"ready"}` or
a refusal carrying its reason. The requester MUST wait for ready. A refusal,
truncated frame or closed stream MUST end admission; the client MUST NOT infer
success from the presence of a relay reservation. The guest MUST admit no new
work after its admission cutoff. An admitted request MUST still observe its
command, budget and service-until limits.

In `mcp` mode, after ready both directions carry only newline-delimited UTF-8
JSON-RPC messages using MCP's stdio framing rules. There are no four-byte
length prefixes after admission and no diagnostic text on that byte stream.
Endpoints MUST perform the MCP version/capability exchange required by their
selected MCP version. Dsmack's custom transport preserves JSON-RPC semantics,
progress notifications and cancellation. The implementation's SDK pins protocol
`2026-07-28`; a peer MUST NOT silently upgrade a session by changing that value.

`tools/list` returns the measured Pi tool schemas. `tools/call` exposes `bash`,
`read`, `write` and `edit`. A shell call with an explicit timeout is the raw
process-execution operation; it does not need another exec protocol. File tools
MUST confine paths and symlinks to the workspace. Tool processes MUST use the
measured unprivileged identity and output bounds. The environment resource
`dsmack://environment` reports runtime facts; `dsmack://workspace/patch` returns
the binary Git diff relative to the imported baseline. Resource reads MUST use
the same session authority as tool calls.

In `batch` mode the admitted request is one sealed input envelope followed by
one signed `dsmack.output/1` object. The input MUST bind the job identifier,
manifest identity, guest seal key and grant scope as authenticated context.
The guest MUST verify that context before execution. The output MUST name the
job, manifest identity, run, input commitment, completion status, exit code and
artifact digests. Its signature MUST use the attested receipt key. A requester
MUST verify these fields and the output signature before treating an artifact
as the result of its job. Ciphertext delivery success alone is not job success.

Disconnect and cancellation do not authorize replay. A client MUST resolve a
failed or canceled tool call explicitly before retrying work. The guest MAY
retain a conversation's admitted workspace for reattachment by its authorized
owner while the grant remains valid; it MUST NOT let a new owner inherit it.
Session release MUST flush final usage and preserve original signed evidence.
A missing final receipt MUST remain unresolved rather than being fabricated
from a disconnected browser's estimate.

The existing agent adapter uses `/dsmack/agent-mcp/1.0.0` with
`{job_id:grant.grant_id, grant}` before the same ready frame and MCP byte stream.
Its grant carries `sig` internally. Batch's existing adapter uses the compute
job stream. These endpoint adapters do not implement `/dsmack/session/1` merely
by implementing one mode. The [guest admission tests](../applications/compute-node/peer/agent_test.go)
and [MCP tool tests](../applications/compute-node/agent-mcp.test.mjs) exercise
real admission, echoing tool output, cancellation, resources and signed metering.
The historical [v02-turn request](../applications/agent-turns/testdata/v02-turn/request.json),
[artifacts](../applications/agent-turns/testdata/v02-turn/artifacts/verdict) and
[turn tests](../applications/agent-turns/test_turn.py) provide a recorded batch
input/result example with original launch and enrollment evidence.

## 4. Receipt — dsmack.receipt/5

A receipt is a cumulative accounting statement signed by an attested
secp256k1 receipt key. The version-5 logical fields are `purchaseId`, `sequence`,
`unit`, `used`, `endedAt` and `final`. EIP-712 widths are `uint256`, `uint64`,
`uint8`, `uint128`, `uint64` and `bool`, respectively, in that order. The EIP-712
domain MUST bind the chain ID, verifying escrow, protocol name and domain
version selected by that escrow. A verifier MUST obtain those domain values
from its escrow policy and MUST NOT accept a domain selected solely by the
receipt sender.

`unit` identifies bytes or guest seconds as selected by the purchase. `used`
is the cumulative total for that purchase, not an increment. `sequence` MUST
increase for each accepted checkpoint. `endedAt` MUST NOT exceed the grant's
service-until time. `used` MUST NOT exceed the purchased and granted allowance.
The signature MUST recover the receipt signer authenticated by guest evidence
and the broker's authorized run binding. The escrow MUST validate the purchase's
buyer, node class, operator, run authorization and receipt unit.

A settlement processor MUST charge only the increase beyond the highest
accepted cumulative usage. A duplicate checkpoint MUST NOT charge twice.
A checkpoint with a lower sequence or lower cumulative usage MUST NOT replace a
newer one. `final=true` closes service for the purchase; later execution or
receipts MUST NOT reopen it. A zero-use final receipt is meaningful when an
admitted job delivered no billable service. Expiry and timeout refund behavior
belong to the selected escrow contract, not the heartbeat directory.

A node class fixes admitted workload measurements, unit and operator. A run
binding authorizes one attested receipt signer for that class and lifetime.
The purchase and grant MUST select compatible class and run terms. The broker's
run authorization MUST NOT be silently rewritten while settlement is pending.
Receipt originals MUST survive guest retirement so a missing final checkpoint
can be recovered and verified using its original signature.

The binding change in this specification does not rewrite existing receipts.
The current payment [schema](../applications/payments/schema.mjs) uses EIP-712
`Receipt(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)`
under `DsmackUsageEscrow`, version `2`, with the unit obtained from its purchase.
Agent sessions also have their existing Ed25519 accounting checkpoints. These
are distinct from the version-5 contract above and MUST NOT be labeled version
5 by renaming fields. The [Go receipt tests](../applications/payments/guest/payments_test.go)
produce a signed receipt that the [payment tests](../applications/payments/payments.test.mjs)
verify independently with ethers. This preserves the accounting test vector
while receipt unification changes the escrow separately.

## 5. Heartbeat — dsmack.heartbeat/1

A heartbeat is a publisher-signed availability statement. Its JSON body MUST
contain `schema:"dsmack.heartbeat/1"`, `publisher`, `updated_at`, `version`,
`config`, `hardware`, `slots`, `classes` and `errors`, with optional `region`.
`version` identifies the pool software. `config` describes configured capacity;
`hardware` describes the publisher's reported Mac; neither is measured guest
capacity. Each slot names its index and state: launching, attesting, ready,
busy, draining or failed. A directory MUST distinguish reported capacity from
attested guest registration and actual admission availability.

The `signature` is an EIP-191 personal-message signature over the UTF-8 string
`dsmack.heartbeat/1\n` followed by canonical JSON of the body without `signature`.
A directory MUST recover `publisher` from the signature, check a bounded clock
skew, and reject a timestamp older than its stored message for that publisher.
A publisher SHOULD send every 15 seconds. A directory SHOULD mark it offline
after 60 seconds without a fresh heartbeat and MUST disclose the observation
time separately from the publisher's signed timestamp.

A heartbeat MUST NOT contain a payout instruction or claim an operator binding.
The directory MUST obtain operator association from a valid MacLink. A region
is an optional explicit disclosure with a name and whole-degree latitude and
longitude. The directory MUST NOT infer or publish precise location from an IP
address. Omitting region on a later signed update removes that disclosure.
Errors MAY explain failed capacity, but MUST NOT contain secrets or credentials.

The current fleet endpoint's signed-message domain is `dsmack-fleet/1\n`, with
the existing pool snapshot body. It is the source example for this layer, not a
second signature domain accepted for `dsmack.heartbeat/1`.
[heartbeat.py](../applications/compute-node/heartbeat.py) and its
[tests](../applications/compute-node/test_heartbeat.py) exercise publisher
recovery, integer canonicalization and region removal; the
[fleet tests](../applications/relay-broker/fleet.test.mjs) exercise timestamp
replay and directory expiry. The directory is untrusted routing infrastructure:
a valid heartbeat MUST NOT bypass evidence appraisal, MacLink verification or
purchase authorization.

## 6. MacLink — publisher and operator association

MacLink is an EIP-712 statement relating an enrolled runner key ID `kid`, a
heartbeat/tunnel `publisher`, an `operator` and a monotonic `nonce`. Its type is
`MacLink(bytes32 kid,address publisher,address operator,uint64 nonce)`.
The domain is `DsmackMacOwnership`, version `1`, the selected chain ID and the
configured escrow as verifying contract. In the existing local/testnet profile
the chain ID is 84532. Changing an escrow or network changes the signature domain.

The publisher MUST sign the link. The operator MUST either sign the same link
or authorize a provisioner that signs it. Provisioning uses
`ProvisioningAuthorization(address operator,address provisioner,uint64 nonce)`
signed by the operator, and a provisioner signature on the exact MacLink.
`ProvisionerRevocation` uses those same fields under its own primary type.
A directory MUST reject a revoked provisioner and MUST NOT infer delegation
from a heartbeat, an IP address or possession of a relay reservation.

`MacUnlink` uses MacLink's four fields under the `MacUnlink` primary type and
requires the publisher's signature. A directory MUST check the currently linked
key and operator before unlinking. Publisher nonces and key/publisher nonces
MUST increase for new actions. Re-delivery of the identical signed action MAY
be idempotent. A conflicting action with an old nonce MUST be refused. State
MUST survive directory restarts so a revoked or superseded link cannot return
through replay.

An enrolled runner key can have several publishers, including separate pool
installations. A publisher has one active operator association. Replacing its
link MUST remove that publisher's previous association while preserving other
publishers attached to the same key. A link authenticates the two parties'
authorization; the Verifier MUST still verify that execution evidence names the
linked enrolled key when that association matters to the application.

[ownership.mjs](../applications/relay-broker/ownership.mjs) defines the exact
typed-data fields and domain. [ownership.test.mjs](../applications/relay-broker/ownership.test.mjs)
and the [Mac client tests](../applications/mac-ownership/test_ownership.py) check
direct and delegated signatures, monotonic state, unlinking and revocation.
The command-line interface is [dsmack link](../applications/mac-ownership/README.md).
MacLink MUST NOT itself transfer funds; settlement uses the escrow's independently
validated operator and purchase terms.

## 7. Application profiles

**agent-session.** Select MCP mode, epoch admission and a measured agent tool
server. The requester runs its agent loop in the browser and appraises the guest
before the first tool call. A conversation exclusively owns its guest workspace;
reattachment requires the same authorized owner. The profile permits a guest
lifetime up to one hour, bounded by the measured watchdog and signed grant, and
releases after five idle minutes. Bash timeout, raw output and model-facing
output caps remain separate measured limits. Guest seconds and model-token
accounting MUST remain distinguishable. A progress notification MUST NOT be
counted as a second execution of the tool call.

**batch-job.** Select batch mode, a fresh requester challenge and a sealed job
input. The manifest MUST pin the execution harness, all workload images, output
paths and runtime limits. The requester verifies the output commitment and
signature, then settles cumulative usage through the selected escrow. A broker
MUST NOT replace a failed job with another execution under the same grant
without explicit replay-safe job semantics. Successful input delivery or a
nonempty artifact directory MUST NOT be treated as a successful exit.

**artifact-guest-run.** Select batch mode with user-confirmed execution of an
artifact's bounded action. The confirmation MUST identify the code or artifact,
allowed inputs, budget and network authority. Artifact JavaScript MUST NOT
inherit the page's wallet, workspace decryption key or unrestricted guest grant.
The page seals only the confirmed inputs to the appraised guest. The signed
output binds that artifact action and its job identifier; the artifact viewer
receives only the authorized result. Cancellation MUST resolve the pending
request and release its UI and budget state.

**bounty-checker.** Select batch mode, a public digest-pinned checker and a fresh
challenge scoped to the bounty and submitted candidate. Private inputs MAY be
sealed, but acceptance policy and checker identity MUST be independently
selected by the bounty's authorizer. The attested output MUST commit to the
candidate, checker, inputs and verdict used for settlement. Escrow payment
requires that authenticated verdict under the bounty's rules; an operator's
heartbeat, a requester-supplied verdict or an unsigned transcript MUST NOT
substitute for the checker result. The recorded v02-turn artifacts above are a
worked input/attestation/result example consumed by the existing turn verifier.
