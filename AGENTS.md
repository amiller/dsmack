# Code contribution instructions

Read README.md and CONTRIBUTING.md. Keep private notes, credentials and operator
state out of commits. Work on topic branches/worktrees. Run `./test.sh` before
merging. Do not change live services or publish artifacts as a side effect of editing.

This is a prototype. Velocity matters more than ritual.
- Validate only at trust boundaries: the Apple attestation chain, the on-chain
  verifier, VM result evidence and network input to services. Trust internal data.
- Add a check, guard or test only for a concrete failure it prevents, and name it.
  No mutation/adversarial test generators, negative-control copies of source, or
  tests that pin hashes, file counts, manifests, tool versions or doc wording.
- No provenance, inventory or derivation manifests. Git history is the record.
- READMEs say what a thing is and how to run it. No caveats, qualification status
  or "this does not prove" disclaimers. If something must not be run, delete it.
- Prefer deleting code to adding layers. Remove dead modes, superseded versions
  and concluded experiments.
