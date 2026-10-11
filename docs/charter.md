# dsmack charter

Direction confirmed by Andrew on 10 October 2026. This is a product commitment and contribution boundary, not a certification that the current implementation satisfies it.

## Decentralization is a requirement

dsmack is actual peer-to-peer node software, a network and its service protocol. It insists on decentralization in the DevProof sense: developers and operators must be constrained by verifiable rules, not merely trusted to behave. A fleet under one privileged coordinator does not meet the charter merely because its nodes communicate over libp2p.

For each supported service profile, identify who controls admission, discovery, routing, secrets, balances and upgrades. Show how users verify those controls and what any developer, operator or vendor can change. A privileged party must not be able to silently substitute the accepted service or seize its authority. Document upgrade notice, user choice and continuity mechanisms and test their actual enforcement. An individual peer can stop serving; independence must be evaluated at the network level rather than confused with a promise that every peer stays online.

Map deployment claims to the applicable DevProof requirements, including source/measurement correspondence, secret custody, operator-controlled configuration, client enforcement, infrastructure dependencies and upgrade governance. Peer counts and valid hardware quotes are insufficient. Necessary vendor roots and any remaining centralized dependencies must be explicit; do not weaken the charter to relabel a prototype as completion.

The local research reference is `~/projects/dstack/devproof-audits-guide/README.md` and `framework/AUDIT-GUIDE.md`. Those documents distinguish DevProof operator constraints from later multi-vendor decentralization stages. Pin the applicable criteria and publish a self-contained explanation before assigning a stage to a dsmack release. This charter assigns no stage.

## Optimistic about TEEs and explicit about evidence

dsmack treats TEEs and hardware-rooted verification as promising foundations for useful independent services. Pixels with verified boot and App Attest nodes are promising candidate paths. They are not assumed to provide identical guarantees or already-qualified dsmack support.

Qualify each device/service profile on its actual evidence: what code and configuration are bound, who controls keys, what the host can observe or change, how clients verify a session, and how upgrades work. Verified boot, app identity, workload integrity and confidentiality are different claims. Hardware diversity is a research direction that serves the charter; it does not justify inventing common guarantees across devices.

## First useful purpose

dsmack's first product scope is **coupon redemption and basic routing for Abalone clients**. This supersedes the earlier roadmap wording that left the first service undecided or foregrounded general remote task execution.

The first complete journey is: obtain a coupon, redeem it through a participating peer, route an eligible client request under the declared service policy, receive a useful response, and understand remaining credit and failures. Preserve identity and coupon/accounting continuity across the supported restart and upgrade paths. Abalone owns the graceful client experience; dsmack owns the peer service and protocol.

Keep routing modest. General compute markets, arbitrary user-defined services and a universal scheduler are not prerequisites for this first purpose. Precise routing/discovery policy, coupon format/accounting and supported hardware profile remain protocol design work; this charter does not silently select them.

## Contribution and acceptance priorities

Contributions should advance the first coupon/routing journey, remove privileged control inconsistent with the charter, improve verifiable guarantees, or make independent participation practical. Broader services belong in [platform research](roadmap.md#platform-research) until a concrete client journey requires them.

A qualifying demonstration must include independently operated peers and an Abalone client, not only several processes owned by the maintainer. Exercise coupon redemption, an eligible routed request, meaningful rejection, restart/return and the stated accounting behavior. Inventory remaining authorities and dependencies, then test what happens when the maintainer's infrastructure or permission is unavailable. Separate service availability, custody, confidentiality and upgrade powers in the result.

These are acceptance requirements to refine into bounded tests. Existing local, historical and ad-hoc evidence retains its original scope. No running node, protocol identifier, contract or release is changed by recording the charter.
