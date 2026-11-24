# dev-session-v1 proof of concept

A workload under `security_profile: dev-session-v1` ([ADR 0010](../../docs/decisions/0010-dev-session-profile.md))
that runs rootless podman inside the guest: it pulls a busybox index by digest from ghcr.io, runs two inner
containers (one prints its id and arch, one probes an allowed and a disallowed address), writes `result.txt` and
binds it with the guest's `/v1/Attest`.

- `image/`: the workload image (Debian trixie, podman, crun; empty subuid so podman uses a single uid mapping).
  Build it for arm64 as an OCI layout, e.g.
  `SOURCE_DATE_EPOCH=0 docker buildx build --platform linux/arm64 --provenance=false --output type=oci,dest=<dir>/oci-layout,tar=false,rewrite-timestamp=true image`.
- `pack.py REPO BASE TEMPLATE_MANIFEST OCI_DIR DIGEST OUT`: writes the measured manifest and workload disk. Run it
  on Linux (the disk builder uses memfd seals). REPO's contract library must know `dev-session-v1`; BASE is a base
  image directory built with `base-vm/browser-sandbox-v1/update-runtime.py`; TEMPLATE_MANIFEST supplies the
  `base_vm`, `runner` and `limits` blocks (e.g. `applications/compute-node/testdata/key-free-manifest.json`).
- Launch on a Mac with `applications/compute-node/pool_mac_run.py <runner dir> <run dir> 900 mini-4096-1`, using a
  runner directory whose `base/` holds the new image.
- `verify_run.py`: checks the run's App Attest chain, the guest attestation over `result.txt` and the result disk, and
  prints each service's security profile from the measured compose.
