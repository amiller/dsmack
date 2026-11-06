# Changelog

One entry per release. How releases are planned is in [docs/release/releasing.md](docs/release/releasing.md#next-releases). Layers and what counts as breaking are in [docs/versioning.md](docs/versioning.md).

## Next: v0.2.0 (tentative Tue Nov 17, 2026)

Milestone: [Platform v0.2.0](https://github.com/amiller/dsmack/milestone/9). Candidate branch: `release/v0.2.0`. Breaking changes are collected in #39; Macs re-enroll once, at this release.

The goal is that what runs is a tag. Today the base on Layover's couch pool (7c1ebf67) was built by `update-runtime.py` overlaying files from an uncommitted working tree onto 69b61e4a's image, so no commit reproduces it. Production pins are recorded in open PRs (#91, #96) rather than on `main`.

### In progress
- **Base image built only from the repo** (#103, audit #104). Derive installs the whole guest tree from `git archive HEAD`, a rootfs check refuses any file that isn't a tracked repo file, verifier-only code leaves the guest, `update-runtime.*` and dead paths are deleted. Moving the credential sentinel out of the base waits on per-service egress (#78).
- **Key-free guest manifest** (#101). An App Attest key rotation becomes an on-chain enroll plus a MacLink under the same manifest, with no repack.
- **Per-service egress** (#78).
- **#39:** one `vX.Y.Z` tag scheme, the release-inventory writer in the repo, evidence format names restarted at `/1`.

### Landed on main since v0.2.0-canary.1 (Oct 25)
488 commits.
- **Attestation.** The guest refuses to start unless it runs the attested manifest (#86). App Attest keys last until the intermediate expires, not the 3-day leaf (#52, #54). The pool detects a dead App Attest key and rotates it without touching the runner (#99). Task secrets are released only to an attested guest (#48, #49). A Mac guest can be an attested libp2p peer behind a circuit relay (#58).
- **Reproducible builds.** The base image build is checked in CI (#45), and the Mac runner build is reproducible (#47).
- **Network.** Guest containers resolve DNS through the guest resolver (#50). A hostname egress gateway with measured request budgets (#61). Per-stay browse terms for couch stays, enforced as a CONNECT policy (#100).
- **Agents.** Agent turns, Mac dispatch and the coordinator dstack app (#51). Sealed remote agent jobs and metered relays (#60). The private agent web app, v1 to v3 (#62, #63, #65).
- **Layover.** LayoverCredit (LAYC) and GuestEscrow, with guest-signed claims verified by App Attest on chain on Base Sepolia (#90). Broker and relay fixes: safe-head reads on Base Sepolia (#93, #95), two generations per relay slot (#94), closing stays whose guest stopped registering (#102), and pruning stopped run images (#92).
- **Canaries and bounties.** Self-claiming canary bounty contract and dashboard (#40–#44), canaries that survive `setBuild` (#55, #56), and an oracle canary whose funder can't withdraw early (#88).

Who upgrades: every host Mac, once, when the release ships. Workloads and applications pin the release they need and move when they're ready.
