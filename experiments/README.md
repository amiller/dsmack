# Experiments

Each directory here is a small, self-contained proof of concept. It answers one
question about an approach dsmack relies on, and it stays runnable so it can be
read, rerun and used as a guide when the approach is built into a larger
component. Integrated components may run a PoC as a conformance check.

Every PoC README uses the same sections:

- **Question** — the one thing it set out to establish.
- **Answer** — what it found, in a sentence or two.
- **Guides** — the architecture component it informs.
- **How it works** — the mechanism, briefly.
- **Run** — one command, and the hardware it needs.
- **Recorded result** — what happened when it ran, with date and machine, so a
  reader without the hardware can see the outcome.
- **Files** — what each file is.
- **Provenance** — where the code and evidence came from.
- **Limits** — what it does not show.

| PoC | Question | Runs on |
|---|---|---|
| [app-attest-offline-verify](app-attest-offline-verify/) | Does an App Attest attestation chain to Apple and bind this key and app? | Anywhere |
| [secure-enclave-probes](secure-enclave-probes/) | What does the Secure Enclave bind, revoke and transfer, and what does App Attest add? | Mac |
| [gpu-onchip-mailbox](gpu-onchip-mailbox/) | Can a computation keep its working set in GPU on-chip state? | Apple silicon Mac |
| [mac-vm-approaches](mac-vm-approaches/) | How can a signed Mac app run measured Linux workloads? | Mac |
