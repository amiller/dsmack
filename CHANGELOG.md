# Changelog

One entry per release. The cadence and what each entry covers are in [docs/release/releasing.md](docs/release/releasing.md#cadence). Layers and what counts as breaking are in [docs/versioning.md](docs/versioning.md).

## Next: v0.2.0 (planned Fri Nov 20, 2026)

Milestone: [Platform v0.2.0](https://github.com/amiller/dsmack/milestone/9). Breaking changes collected in #39. Macs re-enroll once, at this release.

In progress:
- **Base image: built from the repo, no provider code** (#103, audit #104). The derived image installs the whole guest tree from source, verifier-only code leaves the guest, and dead paths go. Moving the credential sentinel out of the base waits on per-service egress (#78). Context: the base running on Layover's couch pool today (7c1ebf67) was built by `update-runtime.py` overlaying files from an uncommitted working tree onto 69b61e4a's image, so no commit reproduces it. This release is the first base built only from a tagged commit.

Who upgrades: every host Mac, once, when the release ships. Workloads and applications pin the release they need and move when they're ready.
