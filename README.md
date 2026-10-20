# dsmack

dsmack runs a measured workload on a Mac that someone else owns, and produces
evidence a smart contract can check: which program ran, which workload it
booted, and what that workload sent and received over the network. It follows
[dstack](https://github.com/Dstack-TEE/dstack), which does the same with Intel
TDX virtual machines. The difference is the root of trust. dstack relies on
hardware memory encryption, which also resists physical memory attacks; dsmack
relies on Apple's App Attest and an intact macOS, which protects against the
machine's owner acting through software but not against physical memory probing,
and is much easier to get hold of. Any Apple silicon Mac will do.

This README is the whole argument. It starts from the problem, adds one
mechanism at a time, says which file implements each one, and ends with what the
design does not protect against. If you are an agent deciding whether to run or
trust this code, read it critically and check each step against the code it
names.

## The problem

Suppose an application, say a contract on Base, wants a computation done on a
Mac it does not control. The naive version: the Mac's owner runs the program and
posts the result. That works until the owner prefers a different result. They
can run a modified program, or no program at all, and post whatever they like.
From the contract's side the two cases look identical.

Signing the program does not help. A signature says who built a binary, not what
is running now. What the contract needs is a statement, from someone other than
the owner, about the program that produced the result.

## Step 1: Apple says which binary holds a key

App Attest provides that statement. An app signed with the App Attest
entitlement asks macOS to generate a key in the Secure Enclave and to attest it.
Apple returns a certificate chain to its App Attestation root, covering:

- the public key,
- the app's team and bundle identifier,
- a 32-byte value the app chose (the client data hash),
- with the `CDhash` opt-in, the code directory hash of the exact binary.

Apple ties these keys to a Full Security boot with System Integrity
Protection; this repository has not tested App Attest with SIP off. Under
those conditions no other process, root included, can attach
to the app or read its memory. Later the app can sign assertions with the same
key, and each assertion again carries the code hash.

So a verifier that knows which code hashes it accepts can tell whether a message
came from one of those binaries on an intact Mac. The Secure Enclave alone would
not give this: a Secure Enclave key can be used by other code that reaches it,
such as the holder of its wrapped blob or an app sharing its keychain group. [`experiments/secure-enclave-probes`](experiments/secure-enclave-probes/)
shows both results.

Implemented in: [`verifier/core.py`](verifier/core.py) (offline),
[`contracts/src/AppleAttest.sol`](contracts/src/AppleAttest.sol) (on chain),
[`experiments/app-attest-offline-verify`](experiments/app-attest-offline-verify/)
(the five checks in 40 lines, with a real attestation).

## Step 2: the runner says which workload it booted

App Attest identifies one signed binary. That binary is the runner. Its job is
to boot a workload and to commit, in its attestation, to exactly which workload.

The runner takes a dstack-format `app-compose.json` and computes
`compose_hash = sha256(file bytes)`, the same definition dstack uses. It refuses
the compose unless every image is pinned by digest and there is no shell script,
pre-launch script, host mount or Docker config. It checks the kernel against a
digest compiled into the runner and builds the init filesystem from a pinned
image on every boot. Then it puts the compose hash into the client data it asks
App Attest to cover, and boots the workload in a Linux VM with Apple's
Virtualization framework.

Because the runner's own code hash is in the attestation, and the runner only
boots what it hashed, a verifier that accepts the runner's code hash and the
compose hash knows what is running inside the VM.

Implemented in: [`runner/Sources/runner/main.swift`](runner/Sources/runner/main.swift)
(compose checks, attestation, VM boot through Apple's Containerization package),
[`runner/README.md`](runner/README.md) (the exact rules).
[`experiments/mac-vm-approaches`](experiments/mac-vm-approaches/) records why it
is built this way and what else was tried.

## Step 3: everything that crosses the boundary is recorded

A workload that could reach the network freely could fetch new instructions or
leak its inputs, and its result would no longer follow from the compose hash.
So the VM has no network device. Its only way out is a socket to a proxy inside
the runner, and the proxy:

- forwards only HTTP requests whose host, method and path prefix match the
  egress allow-list declared in the compose (and therefore covered by the
  compose hash), and opens raw TCP tunnels only to the host:port pairs the
  compose lists under `egress.tcp`;
- drops credential headers the workload sent (`authorization`, `x-api-key`,
  `cookie` and a few others) and injects the rule's credential, so the
  workload never holds a provider key;
- accepts only TLS chains ending at roots pinned in the runner, and follows no
  redirects;
- enforces request and token budgets;
- signs a receipt for every forwarded HTTP exchange: the request and response
  hashes, a sequence number and the previous receipt's hash, with a key that
  the attestation covers.

Raw TCP tunnels get no TLS pinning, credential handling or receipts, and neither
do refused requests, upstream errors or the runner's own `runner.local`
endpoints (task attach and detach have their own chains). Anyone holding the receipt chain can check that nothing inside it was
dropped or reordered. The host stores the chain, so it can still cut off the
tail.

Implemented in: [`runner/Sources/runner/Proxy.swift`](runner/Sources/runner/Proxy.swift),
[`runner/Sources/runner/Anchors.swift`](runner/Sources/runner/Anchors.swift).
Receipts are checked by [`runner/kms/verify_receipts.py`](runner/kms/verify_receipts.py).

## Step 4: a contract checks the evidence

An application contract does not need to understand any of the above. It needs
to know which runner builds it accepts, and to receive an assertion that commits
to the thing it cares about.

[`AppleAttest.sol`](contracts/src/AppleAttest.sol) verifies an App Attest
enrollment against Apple's P-384 certificate chain in Solidity, and later
assertions with Base's P-256 precompile. Subclasses decide which builds count:
[`MacAppAttestV1`](contracts/src/MacAppAttestV1.sol) admits one approved code
hash; [`AppleAttestRegistryV1`](contracts/src/AppleAttestRegistryV1.sol) admits
any build that [`CDRegistry`](contracts/src/CDRegistry.sol) has measured, so a
re-signed copy of the same program, by any Apple developer team, is accepted.
The address fixed as `registry` at deployment calls `verify(context, proof)`, where `context` is the hash its own logic expects, for
example the hash of a result together with the compose hash that produced it.

Today the compose-hash check runs in the offline verifier
([`runner/verify/macrunner.mjs`](runner/verify/macrunner.mjs)); the contracts
check the runner's code hash and the assertion.

## What this does not protect against

- **The owner reading memory physically.** Apple silicon does not encrypt main
  memory. Someone probing the memory bus can read the workload's data. Research
  on keeping small computations in GPU on-chip state is in
  [`experiments/gpu-onchip-mailbox`](experiments/gpu-onchip-mailbox/).
- **The owner reading the VM's disk (current gap).** Volumes are plaintext
  files on the host, and the kernel and init filesystem sit on the host between
  being hashed and booted. Encrypted app volumes and verity, as dstack uses,
  close this.
- **A kernel exploit.** It defeats the premise of Step 1 on that machine.
- **A Mac without SIP.** App Attest's key policy is meant to exclude it; that
  exclusion is Apple's to enforce, not this code's.
- **What the workload does with its own inputs.** dsmack says which program ran.
  Whether that program is correct is the application's business.

Within those limits dsmack gives confidentiality as well as code integrity
against an owner acting through software. On an intact, attested macOS no other
process, root included, can attach to the runner or read its memory, and the
guest VM's memory lives in the runner's Virtualization host process, inside the
same trusted base.

## Layers

This repository is the bottom layer: the runner, and the code that checks its
evidence. Useful applications can stop here. A contract that pays for a result
only needs Step 4, and does not care how the Mac was found or who owns it.

Two layers can go on top, and neither lives here yet.

- **Keys.** Release secrets only to an admitted runner and compose, so a
  workload can hold credentials that its host cannot read. `runner/kms/` is a
  stand-in for this layer today; the runner currently boots against it.
- **Network.** Discovery, admission of strangers' Macs, scheduling and payment.
  Earlier prototypes of this layer (a peer testnet and a coupon service) are
  preserved outside this repository.

## Repository

| Path | What it is |
|---|---|
| `runner/` | Boots a measured compose in a VM, attests it, proxies egress, signs receipts |
| `verifier/` | Offline App Attest verification |
| `contracts/` | On-chain App Attest verification and build registries |
| `experiments/` | Small, runnable proofs of each claim above, with recorded results |
| `trust/` | Apple's App Attestation root certificate |
| `tests/` | Verifier tests and App Attest test vectors |

## Running it

Requirements: an Apple silicon Mac on macOS 27 with Full Security and SIP
(`csrutil status`), and an Apple Development signing identity with a
provisioning profile that grants App Attest. The runner must be built against
the macOS 27 SDK; built against the macOS 26 SDK, its attestation omits the code
hash. Build, sign and test instructions are in
[`runner/README.md`](runner/README.md).
