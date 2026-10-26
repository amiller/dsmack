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

`derive.py` takes the existing image7 base bundle (`Image`,
`config-6.18.40-dstack`, `rootfs.squashfs.verity`) and the 4GiB scratch / 256MiB
result disk templates. In an offline builder container it unpacks the base
rootfs, overlays the runner files listed in `derive-in-container.sh`, and
assembles a new verity image with `source/build/assemble_leg.sh`. Run it on Zed
under `/data`:

```sh
python3 base-vm/browser-sandbox-v1/derive.py \
  --base-bundle /data/selected/image7 \
  --templates /data/selected/templates-4g \
  --out /data/owned/new-browser-base-build
```

It prints the artifact directory and the image digest (`digest.txt`, the
SHA-256 of `sha256sum.txt`). The current source derives
`bfd41990bd82893d50a04c2a2e57debe162b75345fa5745cdadc0ea88a678831`.

```sh
python3 -m pytest base-vm/browser-sandbox-v1
```

Dstack adaptations keep their Apache-2.0 notices and the Playwright seccomp
policy keeps its upstream Apache-2.0 license; see `licenses/`.
