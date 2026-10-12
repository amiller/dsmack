# Opt-in native directory v1

This candidate exposes authenticated, explicitly public native check-ins through
the existing relay. It does not enumerate on-chain members, count unique people,
grant membership, or change a personal account. It requires separate deployment
and live qualification. A node running as a public node lists itself by default (see
[Listing by default](#listing-by-default)); the relay stays off by default. The relay enables this
feature only with `NATIVE_DIRECTORY_ENABLED=true`; enabling it is an operator
deployment decision, separate from a source review.

`GET /nft/directory` returns the schema below for the selected Mac NFT network.
An isolated deployment that mounts a complete NFT-enabled network at the relay
root exposes the same routes under `/directory`; it derives its verifier pins
from that exact root deployment, separately from `/nft`. There is no directory
route on the legacy deployment without badge/account configuration.
The dashboard can fetch that endpoint through an explicitly configured URL or a
same-origin operator proxy. A static `directory.json` may contain a dated copy;
copying it never refreshes its node check-in timestamps.

```json
{
  "schema": 1,
  "type": "dsmack-native-directory",
  "generatedAt": "2026-10-11T23:00:00Z",
  "network": {"chainId": 84532, "registry": "0x..."},
  "coverage": "explicit-opt-in",
  "status": "available",
  "error": null,
  "freshness": {"heartbeatTtlSeconds": 90, "staleRetentionSeconds": 300, "receiptFreshnessSeconds": 120},
  "nodes": []
}
```

Top-level `status` is `available`, `unavailable`, or `not-configured`.
An available empty list means no retained public check-ins. An unavailable feed
means observation failed; it must not be rendered as an empty healthy network.
`error` is null or `{ "code": "RPC_UNAVAILABLE" | "DIRECTORY_DISABLED" }`.
Do not display untrusted exception text or private relay configuration.

Each node has the following fixed fields. Addresses and hashes use lowercase
`0x` hex. Timestamps are UTC ISO 8601 strings. Token IDs are decimal strings.

| Field | Type and meaning |
| --- | --- |
| `id` | bytes32 deterministic network/member identifier |
| `member` | bytes32 derived and verified enrollment member |
| `account` | `{status: "verified" \| "unavailable", address: address \| null, participantToken: string \| null}`; verified means a fresh, separately domain-bound consent from the existing personal account control key |
| `label` | v2 only: string or null; a signed self-report of up to 32 characters `[A-Za-z0-9 ._-]` |
| `version` | `{selfReported: string, buildNumber: string, admittedCodeHash: bytes32, measurement: bytes32 \| null}`; the first two values are signed self-reports, the admitted hash comes from the verified App Attest assertion, and `measurement` (v2 only) is the code measurement M when the node's category is measured and the `MeasurementRegistry` maps the admitted hash to the signed M, else null |
| `checkIn` | `{lastVerifiedAt: timestamp, expiresAt: timestamp, status: "fresh" \| "stale"}`; verified check-in time differs from feed generation time |
| `sync` | `{scope: bytes32, keyEpoch: decimal UInt64 string, groupPublicFingerprint: string \| null, status: "receipt-verified-current-epoch" \| "stale" \| "unverified", receiptTransaction: bytes32 \| null, receiptCheckedAt: timestamp \| null, receiptBlockTime: timestamp \| null}` |

`receiptCheckedAt` is the time the relay verified a receipt. `receiptBlockTime`
is the original canonical receipt block timestamp; checking an old receipt again
never refreshes it. A current-epoch receipt label records the successful canonical
receipt and both times. It does not prove the process still holds the private key. A receipt
older than 120 seconds by `receiptBlockTime` is stale even when the app has checked in recently.
The node keeps its last receipt and session key in memory, so after a node restart it checks in
with `receiptTransaction: null`. The relay then keeps that member's previously verified receipt for
the same key epoch, with its original `receiptCheckedAt`, instead of reporting `unverified`. Fresh
check-in means a verified assertion arrived, not continuous online availability.
The list contains at most 64 entries. Version is 1–64 ASCII characters matching `[0-9][A-Za-z0-9._-]{0,63}`.
Build number is a canonical decimal string from 0 through `2147483647`. Decimal epoch strings are 1–20 digits and at
most `18446744073709551615`; token strings are canonical decimal UInt256 values (at most `2^256 - 1`).
Check-in requests are at most 16 KiB and leave requests at most 4 KiB. The
server accepts at most one check-in per member every five seconds.
Expired check-ins remain visibly stale until 300 seconds after their last verified
check-in, then disappear. A failed feed observation cannot renew either clock.

The app posts a bounded `POST /nft/directory/check-in` while listing is on.
A fresh App Attest assertion binds the entire canonical record context and session
public key. The relay simulates the deployed adapter's `verify` with `eth_call`
from the registry; it never broadcasts this verification or updates the adapter's
stored counter. It additionally rejects directory assertion counter replay in its
own bounded in-memory cache. The native loop serializes assertions and completes
on-chain requests before issuing the next directory assertion. Counter gaps are
allowed by the adapter; no directory counter is written back on chain.

Account consent uses the distinct `DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1` domain,
including network, member, session, existing account generation, and record context.
It cannot be reused as badge mint or handoff consent. The directory only looks up
an existing control key/account/NFT and never creates, mints, transfers, or hands
off anything. Missing account control produces no verified account binding.

`POST /nft/directory/leave` is signed by the session key bound by the verified
check-in. It removes only that matching entry and does not revoke membership,
erase enrollment, or alter account control. App shutdown tries a bounded leave;
an interrupted process instead expires. There are no stakes, stop tokens, or
consensus leases in this protocol.

## Signed request encoding

`POST /nft/directory/check-in` accepts exactly `member`, `keyId` (base64 Apple
key ID), `sessionPublic` (65-byte P256 SEC1 point), `issuedAt`, `expiresAt`
(integer Unix seconds), `selfReported`, `buildNumber`, `scope`, `keyEpoch`,
`receiptTransaction`, `account`, `accountGeneration`, `accountSignature` and
`assertion` (base64 Apple CBOR). A v2 request adds exactly `measurement`
(bytes32, the node's own M) and `label`. Nullable fields use JSON null. `scope` is the
zero overall scope. Account generation is a canonical UInt64 decimal string.
An unbound account requires generation `"0"` and null signature.

The record context is Keccak256 of the following concatenated ABI-width values:
domain hash `Keccak256("DSMACK_NATIVE_DIRECTORY_CHECK_IN_V1")`, chain ID,
registry address, category, member, session-public-key Keccak256, issuedAt,
expiresAt, version UTF-8 Keccak256, build number, scope, key epoch, receipt
transaction (zero if null), account address (zero if null), and generation.
Integers and hashes occupy 32 bytes; addresses have twelve zero padding bytes.
A v2 context uses domain `Keccak256("DSMACK_NATIVE_DIRECTORY_CHECK_IN_V2")` and
appends the measurement and the label's UTF-8 Keccak256. The category is the one
whose `Keccak256(category ‖ keyId)` equals the member: the legacy `macCategory`, or
`measuredCategory` when the network configures measured admission, which selects
that category's adapter and registry for verification. Shared vectors are in
`node/relay-hosted/directory_test.ts` and `node/tests/MeasuredEnrollTests.swift`.
The request expires exactly 90 seconds after issuedAt and must arrive within
30 seconds, allowing five seconds of forward clock skew. Accepted public
check-in clocks use relay verification time and expire 90 seconds later.

The personal account signature is raw 64-byte P256 ECDSA over SHA256 of
concatenated domain hash `Keccak256("DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1")`,
chain ID, registry, member, session-public-key Keccak256, account, generation
and record context, using the same widths. Every listed account generation is
rechecked on GET; a later handoff removes the old verified account binding.
No private account key, group key or encrypted parcel is sent to the directory.

Leave accepts exactly member, latest accepted context, Unix-second at, and a
raw 64-byte P256 session signature. Its SHA256 payload contains domain hash
`Keccak256("DSMACK_NATIVE_DIRECTORY_LEAVE_V1")`, chain ID, registry, member,
session-public-key Keccak256, context and at. Leave is valid for 30 seconds with
five seconds of forward skew. It cannot remove a subsequently refreshed record.

Public GETs share one in-flight verification and a five-second observation cache.
Cached responses preserve their original generatedAt and node clocks. Receipt
canonical blocks are rechecked (deduplicated by block) on each new observation;
a reorg removes the verified receipt label.

The relay retains at most 64 entries, 256 replay counters and 16 queued changes.
The replay cache and entries are written to the relay state file after each
accepted check-in or leave, restored on relay restart, and removed 300 seconds
after the last verified check-in. A redeploy therefore keeps the directory and its
replay counters. This is observation state, not on-chain membership or a new
consensus mechanism.

## Listing by default

A Mac node lists itself when running as a public node. The CLI node (`listen`,
`seed`, `participate`) checks in every 30 seconds unless its config sets
`"publicDirectory": false`; `"label"` sets the signed public label (default empty).
The Mac app asks once on first run, scoped to chain and registry, with listing as
the default answer, and records the choice; the menu toggles it later. Until that
choice is recorded the app does not check in. iPhone nodes default off.

The app menu offers a validated public membership ID to copy and an off switch. Global application termination (including the updater and system
quit) attempts a session-signed leave with a three-second network timeout and a
five-second GUI fallback. Failed leave expires naturally and never deletes
Application Support, App Attest enrollment, Keychain identity or NFT ownership.

Unit tests use synthetic adapter/RPC fixtures to exercise policy and the exact
browser schema. They are not Apple attestation, independent-operator, public-chain,
GUI first-open or live relay deployment acceptance evidence.
