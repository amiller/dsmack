# Repaired-artifacts BUILD & DELIVERY (S01/S02) — GATED; `BUILD.sh` is normative

frozen-review-repair2 **S01** rejected the previous version of this document as
not executable: it invoked `extract_export.py --oci-manifest-digest` (a flag
that does not exist), omitted the required leg arguments and container mounts,
claimed `build_leg_rootfs.sh` installs the sentinel (it did not), omitted the
`images/`/`broker/` channels from the workload packer, and proposed a
`docker load` delivery that the runner's own `ensure_image` refuses (a loaded
tarball never populates `RepoDigests` on the guest's classic image store).

**The executable procedure is now a single frozen script: [`BUILD.sh`](BUILD.sh).**
This document only records the design decisions it implements. Where the two
disagree, `BUILD.sh` governs.

## Execution context

Run on the x86_64 build host after independent **Phase-A approval** of this
freeze. It needs: the pinned builder image
`sha256:df98b52e…` (`dsmack-dstack-arm64/builder:trixie-20260721`), host
`unsquashfs`, host `docker buildx` with the pre-existing arm64 binfmt, and the
read-only prior lanes `dstack-base-image` (debootstrap seed cache) and
`dstack-smoke-finish` (proven kernel bytes). All outputs land under
`$DSMACK_BUILD_ROOT` (default `integration-build-prep/build/`) on /data.
No VM boot, no credential, no external publication, no global config changes.

## Exact mounts and leg arguments (step 1–2)

```
docker run --rm --name dsmack-build-legs \
  -v $CAND/dstack-runner-join/source:/w/source:ro \   # frozen source (this candidate)
  -v $BUILD_ROOT/w-build:/w/build \                    # leg workspaces + artifacts (rw)
  -v $CAND:/cand:ro \                                  # sentinel/adapter source (JOIN-4)
  -v …/dstack-base-image:/prior:ro \                   # debootstrap seed cache
  -v …/dstack-smoke-finish:/proven:ro \                # kernel bytes (REUSED, no rebuild)
  sha256:df98b52e… bash /w/source/build/run-my-legs.sh # legs: legA, legB (concurrent)
```

`run-my-legs.sh` invokes `build_leg_rootfs.sh <legA|legB>` then
`assemble_leg.sh <legA|legB>` per leg. The rootfs leg installs, as measured
rootfs bytes: the repaired runner-content (compose runner + **patched
validator** `ddffbc55…`), the supervisor (with the S03 broker lifecycle), the
**sentinel package + its adapter dependency** (JOIN-4, from `/cand`), and the
profile `docker-daemon.json` carrying the explicit
`"insecure-registries": ["10.0.2.2:5005"]` policy. The kernel is **reused**
byte-identical from the proven `ec83a3fc` bundle (hash-pinned before use).
`promote_and_verify.sh` (same mounts + `/w/evidence`) enforces two-leg byte
agreement and mints `H′ = sha256(sha256sum.txt)`; the build **fails if
`H′ == 46c4bcc9…`** (repaired bytes not actually included).

## Harness delivery: real registry protocol, never a weakened digest check (step 3)

`ensure_image` requires the pinned `name@sha256:…` to appear in the daemon
image's `RepoDigests`. On the guest's docker.io 26.1.5 **classic image store**
only a **registry pull** populates `RepoDigests` — `docker load` cannot satisfy
the check (settled by fable-demo-unblock probes; try4 proved the digest-pull
path end-to-end). Therefore:

1. `BUILD.sh` builds the harness image for linux/arm64 (repaired wrappers
   `726412d1…`/`7827917b…` are the on-image bytes) and **pushes it to the
   throwaway loopback registry** `127.0.0.1:5005` (storage dir owned by the
   build);
2. `D′` is resolved with the **registry protocol**:
   `HEAD /v2/dsmack-claude-harness/manifests/<tag>` → `Docker-Content-Digest`;
3. the manifests pin `10.0.2.2:5005/dsmack-claude-harness@D′` — 10.0.2.2 is
   the slirp alias of host loopback, so the guest daemon pulls **by exact
   digest** and dockerd verifies the digest cryptographically regardless of
   transport. Required policy change, explicit and review-visible: the
   **measured** profile input `docker-daemon.json` (baked into `H′`) allows
   `10.0.2.2:5005` as an insecure (HTTP) registry. The digest check is never
   weakened: the PIN is the digest; HTTP affects only transport of
   self-verifying content.
4. The build registry container is stopped afterward; the BOOT request
   restarts it with the **same storage dir** and re-checks `D′` via HEAD
   before boot (`BOOT-REQUEST.template.json`). The `images/*.tar` docker-load
   channel remains for engineering workload children only — the harness image
   never travels by it.

## Identity chain regeneration (step 4)

`render_product_manifests.py --artifacts <rebuilt>` regenerates **base_vm**
(H′, verbatim rebuilt cmdline, kernel/initrd/rootfs/metadata hashes, verity
root, 2 vCPU/2048 MiB), the guest-reachable image reference and the repaired
`harness.sha256` in both product manifests, then re-validates + re-lowers each
output (fail closed). `make_guest_inputs.py` emits the engineering and product
`runner-inputs` (manifests/envelopes/admission/base-bundle/**images/**/
**broker/** channels) bound to the same `H′`; the broker channel carries
**config only** — the capability token is generated in-guest per run and the
credential is staged by the demo harness immediately before launch, never in
any artifact or checksum inventory (S03).

## Post-build verification and the lock (steps 5–6)

`verify_built_artifacts.py` independently `unsquashfs`-extracts the rebuilt
rootfs and proves the **selected source hashes are installed** (validator,
runner, supervisor, sentinel, daemon.json policy), streams the **registry
blobs** to prove the on-image wrapper bytes, requires every external manifest
to bind `H′`/`D′`/cmdline/2 vCPU/2048 MiB with **no** `127.0.0.1:5005`
reference, re-runs the paired embedded-validator probe (stale embed rejects
the subscription manifest, repaired embed accepts), and records the negative
checks (stale base/digest/wrapper refused). Only on `predicate == "pass"` does
`BUILD.sh` emit `BUILT-ARTIFACTS-LOCK.json` (schema
`dsmack.built-artifacts-lock/2`) carrying the identities **plus the
verification block**; `enforce_built_artifacts_lock()` refuses any lock
without it (S02), and `--pin` must equal the lock's `base_os_image_hash`.

## What still requires the boot (not closed by this build)

- Runtime proofs: actual console == declared cmdline, `boundary_ok=true`,
  receipt/artifact validation by the strengthened launcher acceptance (S05).
- Live credential import/refresh (`invalid_grant` is a live-credential
  dependency) and managed-settings qualification.
- ARM64 `runsc` qualification (this engineering repro uses plain runc;
  `runsc-hostnet` remains a distinct policy).
