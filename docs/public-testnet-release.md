# Public testnet release preparation

Status: candidate preparation, 11 October 2026. No upload, visibility change or
service rollout is authorized by this document. The release objective is an
owner-approved URL through which a friend can install Abalone, redeem a coupon
and complete useful private inference without hidden maintainer repairs.

## Paired release gates

| Gate | Required evidence | Current state |
| --- | --- | --- |
| Client | Reviewed fixes for admission lifetime, truthful remote-provider labels, responsive claiming and deliberate trace retention; installed-flow verification | In progress; earlier local fixes are not the release |
| Acquisition | Exact source/artifact hashes, license/notices, clean Linux install and short README | Candidate preparation |
| Public testnet | Named profile, persistent service, public discovery, explicit admission/debug policy and chain settings | Staging evidence is input; public profile not yet qualified |
| Operations | Management-credential renewal, bounded sponsor funding, recovery that preserves claims, sanitized fresh status | Qualification required |
| Source publication | Selected source and fixtures reviewed, reproducible source inventory, no operator material or private history | Required for both repositories |
| Acceptance | Clean-machine friend walkthrough, useful inference, lifecycle/failure behavior and owner acceptance | Not complete |

Runtime and source development will be public once released. Operator secrets,
private development/staging controls and private user traces do not belong in
that publication. Do not describe publishing source as opening management access.

## Source publication review

The local source tree includes historical evidence, native binaries and research
outputs. A prior component audit does not clear every current file or commit.
Prepare a selected snapshot with an exact path/hash inventory and preserved
third-party notices; independently review that snapshot and its build closure.
Preserve the original local repositories and historical worktrees unchanged.

Before any hosted action, record:

- The exact source revision and selected files for DSMACK and Abalone, including
  any omitted historical material and the reason for each omission category.
- The proposed first-party license and existing third-party obligations. Abalone's
  MIT approval does not itself settle DSMACK's first-party licensing.
- Checks for embedded credentials, device/user identifiers, captured bearer
  traffic, private paths and generated binaries; review findings without putting
  their values in issue comments or ordinary logs.
- Clean-clone build/test results for supported components. Historical Mac
  qualification cannot substitute for the Linux coupon-service build.
- The exact repository destination and history strategy. Existing private hosted
  history is not cleared by review of a fresh selected snapshot.
- Release asset digests, install URL, public configuration and its expiry or
  refresh behavior. No provider key, coupon bearer, management token or private
  issuer state may be bundled.
- The proposed GitHub actions, including any rename, creation, selected push,
  release upload and visibility change, for final owner approval.

## Operational acceptance

The public testnet needs a repeatable deployment profile and a read-only status
surface. Report actual observations with timestamps: profile/build, service
reachability and readiness, admission freshness, and known node coverage. Unknown
membership stays unknown. Restrict sponsor accounting and administrative state;
never publish recipient identifiers or conversations as telemetry.

Exercise management-token renewal and service recovery using the chosen
supervisor. Preserve issued credentials and ambiguous issuance obligations;
restarting from an older state snapshot is not a safe recovery procedure.
Record limits and ownership for funding, maintenance and incident response.

The friend walkthrough uses the public package and public instructions, with a
bounded funded coupon. It must not depend on the developer's workspace, copied
operator credentials, an already-funded recipient wallet or a VPN. Separate
provisional authorization, usable inference and settlement in measurements.

The [client release gate](https://github.com/amiller/abalone/issues/4),
[feedback tracker](https://github.com/amiller/dsmack/issues/47) and
[operator release packet](https://github.com/amiller/dsmack/issues/15) retain
their evidence. Optimistic redemption, another provider, a full peer directory
and the Mac release do not block this bounded Linux preview. Production custody,
economic settlement and broader decentralization claims require their own gates.
