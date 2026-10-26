# browser-sandbox-v1 base VM

Source for the `browser-sandbox-v1` guest image the signed Mac runner boots. It
is a small dstack-derived Debian ARM64 system with Docker, the compose runner
(`source/runner-content/dsmack_compose_runner`), guest input/output transport
(`source/runner-content/dsmack_guest_io`), the shared compose contract library
(`source/runner-content/lib/dsmack_compose_contract`) and a closed browser
sandbox preset (`security.py` plus the Playwright seccomp policy
`browser-sandbox-v1.json`). Board checks, judges and settlement run in
application containers and external verifiers, not in the guest.

A workload selects the preset with `security_profile: browser-sandbox-v1`. The
guest then requires network none and no credential broker, and runs the service
with the preset's capabilities, resource limits and seccomp policy. Public file values travel on the measured public disk as
`public-inputs/<manifest-name>.envelope.json`; private inputs use the separate
private disk.

The host verifier (`applications/pilot-client/verifier-browser`) and the bounty
applications import the contract library from this directory, so guest and
verifier validate manifests and receipts with the same code.
`source/smoke/launch_vm_dstack_arm64.py` supplies the workload-disk packer used
by `applications/pilot-client/workload/transport_loader.py`.

## Derive the image

`derive.py` takes a base bundle (`Image`, `config-6.18.40-dstack`,
`rootfs.squashfs.verity`) and the 4GiB scratch / 256MiB result disk templates.
In an offline builder container it unpacks the base rootfs, overlays the runner
files listed in `derive-in-container.sh`, and assembles a new verity image with
`source/build/assemble_leg.sh`. It needs an x86-64 Docker host and about 2GB of
disk; it takes under two minutes.

Build the builder image from `builder/Dockerfile` (Debian trixie pinned by
digest, packages from snapshot.debian.org 20260721T000000Z):

```sh
docker build -t dsmack-builder base-vm/browser-sandbox-v1/builder
```

Then derive from the B44 base (`os_image_hash` `b44abf14…`, shipped in the
`runner-v0.1.0-alpha.1` release) and the release's `config-6.18.40-dstack` in
`b44/`, with the two templates and `disk-templates.json` in `templates/`:

```sh
python3 base-vm/browser-sandbox-v1/derive.py --builder dsmack-builder \
  --base-bundle b44 --templates templates --out derive
```

It prints the artifact directory and the image digest (`digest.txt`, the
SHA-256 of `sha256sum.txt`), which must equal `image.sha256`. The `image-repro` workflow runs this derivation on
GitHub Actions and fails on any other digest; a change that alters the image
updates `image.sha256` in the same PR.

```sh
python3 -m pytest base-vm/browser-sandbox-v1
```

Dstack adaptations keep their Apache-2.0 notices and the Playwright seccomp
policy keeps its upstream Apache-2.0 license; see `licenses/`.
