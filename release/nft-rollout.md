# NFT release rollout

The new Base Sepolia contracts are deployed and paused. Public addresses and
transaction hashes are in `contracts/network/deploy-nft-base-sepolia.json`.
Their runtime bytes match the local artifacts; see `nft-base-deployment-check.json`.

Candidate `eace7a3` reproduced independently on the Mac and GitHub CI, was signed
and notarized, and passed the signed-payload comparison. Its code was admitted
while the new network remained paused. The evidence in `reproducibility-nft-base.json`,
`notarized-payload-nft-base.json`, and `admission-nft-base.json` describes that
candidate, **not the final distribution**.

The first attempted relay update was rejected by automatic approval review
because replacing the root network would disrupt the existing shared-key demo.
No service change occurred. The revised rollout preserves root routes and their
network, seed, mailboxes and transaction journal, and adds `/nft` routes within
the same service. One sponsor queue serializes transactions across both networks.
The compatibility test checks network routing, retained journal state, separate
mailboxes, and rejection of cross-network categories.

The `/nft` endpoint changes a measured app input. Rebuild and notarize this
candidate again, replace the paused NFT network's baseline with its exact signed
CodeDirectory, and recheck independent reproducibility before distribution.
`scripts/release/admit_mac_release.py` performs only admission on a paused test
network and journals transaction hashes before submission. It never activates
the network and refuses to reuse an existing output journal.

Candidate `adda809` now pins `/nft`, independently reproduces on GitHub and the
Mac, and has passed notarization, stapled-ticket validation and signed-payload
comparison. It is admitted while the NFT network remains paused. See the
`*-nft-compatibility.json` reports and
`contracts/network/cd-args-nft-compatibility.json` for the final candidate evidence.
The compatibility relay is deployed; both `/info` routes return the intended
registries and the sponsor journal has no pending transactions. Its completed
count advanced from seven to eight while the legacy network remained active.
An initial HTTP 500 during redeployment cleared after startup.

The NFT network is now active, its separate user-session seed is running, and
its notarized candidate automatically claimed a participant NFT on Base Sepolia.
Reopening the packaged ZIP restored the same NFT with no duplicate mint. See
[the real transcript and screenshot](agent-transcript-nft-base.md).
The original seed remains running. Clean second-Mac and independent
developer-team acceptance remain required tests.
