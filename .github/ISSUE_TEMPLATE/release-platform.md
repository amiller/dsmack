---
name: Platform release
about: Maintainer checklist for a vX.Y.Z platform release
title: "Platform release vX.Y.Z"
labels: epic
---

Steps from [docs/release/releasing.md](https://github.com/amiller/dsmack/blob/main/docs/release/releasing.md).

- [ ] Breaking changes collected on this milestone are decided together; list them here
- [ ] Tag a reviewed commit `vX.Y.Z`
- [ ] Unsigned build; publish the measured executable and its hash
- [ ] Sign; record signed executable hash, CodeDirectory digest, Team ID, bundle ID, profile
- [ ] Write and sign the release inventory (app identity, admitted base images)
- [ ] Notarize, staple, publish the archive with provenance
- [ ] Release notes list the evidence format numbers written and read
- [ ] Enrolled Macs re-enroll if the app was re-signed
