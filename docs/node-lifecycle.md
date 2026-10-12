# Joining, updating and leaving

[Join the network](../README.md#join-the-network) names the current release. Peer participation, coupon redemption and operating a coupon issuer
are separate journeys. [Mainnet is planned](mainnet.md).

## Release lifecycle

Publishing a source tag or downloading a signed app does not change the network's
admission policy. The release owner must separately qualify the artifact and
announce a cutover. Current native admission uses a selected build baseline;
replacing that baseline can reject the older build. Do not assume a compatibility
window exists merely because both downloads remain public.

The release process must distinguish these states:

| State | Meaning |
| --- | --- |
| Candidate | Available for qualification; not recommended for joining. |
| Recommended | Exact signed artifact qualified against the named network. |
| Deprecated | Replacement is recommended; any remaining admission window is explicit. |
| No longer admitted | The network refuses this build; a retained download is historical. |

An update announcement must identify the old and new versions, admitted build
identities, network/protocol, cutover time and recovery options. With a single
baseline policy, describe the coordinated interruption honestly; a grace period
requires actual policy support. Do not silently reset accounts or shared-key
epochs to make an upgrade appear successful.

## Participant directory

Registration history is not an online-node list. A useful directory distinguishes
the public account and current membership, reported app version, attested build
identity where verified, last observation and synchronization evidence for the
current network/scope/epoch. A historical successful exchange is not perpetual
proof of synchronization. Old observations must expire.

The current dashboard candidate observes an explicitly supplied public roster;
it does not yet discover every joining node or collect their running versions.
Public directory participation must be clear to the participant. Keep secrets,
raw diagnostics and private device identifiers out of public status records.

## Stop and return

The existing app's **Quit peer** action exits the process. Closing its window
leaves the peer running. Keep Application Support and Keychain data so reopening
can use the existing account. Quitting does not erase the registration or revoke
the account, and it is not currently a demonstrated protocol-level departure
announcement.

The intended graceful-stop journey stops accepting new work, closes connections,
records a stopped state and retains identity. A directory must still expire a
node's check-in if power or connectivity disappears without a departure message.
Permanent revocation and deletion are separate from ordinary departure.

## Acceptance evidence

Qualify join → synchronized exchange → recognizable directory entry → verified
update → restart, checking the same personal account throughout. Include a failed
download or verification, recovery without identity loss, ordinary departure and
an abrupt disconnect. Record actual installed behavior. Two processes on one Mac
can exercise components, but independent-operator acceptance remains separate.
