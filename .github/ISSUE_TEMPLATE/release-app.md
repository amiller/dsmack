---
name: App release
about: Maintainer checklist for an app release, e.g. private-agent-vX.Y.Z
title: "Release private-agent-vX.Y.Z"
labels: epic, app:private-agent
---

- [ ] Milestone issues merged to local main; `./test.sh` passes
- [ ] Staging page and broker deployed from that commit
- [ ] Browser journeys pass on staging in Chromium and Firefox: new wallet, first message, tool call, recovery
- [ ] Tag `private-agent-vX.Y.Z`
- [ ] Live testnet page and broker deployed from the tag
- [ ] Mac pool restarted on the new source; `relay-broker/network` shows ready slots
- [ ] Directory and capacity health checks report OK
