# Source orientation

Start with [the charter](charter.md) and [roadmap](roadmap.md). The first journey
is coupon redemption and basic routing for Abalone clients under DevProof
constraints on privileged control.

| Component | Source and documentation |
| --- | --- |
| Native node and participation | node/, [builder guide](../release/builder-guide.md) |
| App Attest evidence | verifier/, app/, [protocol notes](../notes/PROTOCOL.md) |
| Admission/account contracts | contracts/ |
| Experimental workload runner | [runner README](../runner/README.md) |
| Release qualification | [assembly acceptance](../release/assembly-acceptance.md) |

A PeerId, relay address, app/code identity, contract address and participant NFT
identify different things. None alone establishes network decentralization or
confidential execution. Protocols remain spread across the original App Attest
peer work, runner interface and Abalone's client/service code. One qualified
coupon/routing profile remains a deliverable.

Historical guides and endpoints are not current health guarantees. The imported
runner retains machine-specific paths; a fresh portable build remains required
before this candidate is ready for outside maintenance.
