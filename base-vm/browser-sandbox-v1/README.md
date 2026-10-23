This is the source package for the versioned `browser-sandbox-v1` reference
base VM. The signed Mac application remains a general VM runner. This base
contains a small dstack-derived Debian ARM64 system, Docker, a compose runner,
public/private input transport and a closed browser sandbox preset. Board
checks, task terms, model judges and settlement policy belong to application
containers and external verifiers. No bounty verifier runs with guest-root
privileges.

The guest's public-file channel is a versioned credential-free reference:
`public-inputs/<manifest-name>.envelope.json` carries file values on the measured
public disk. The public disk measurement commits to the file-value bytes. The existing
runtime validator binds the envelope to the exact compose manifest and its
declared file slots. It permits no public environment,
broker credential, competing private envelope or arbitrary security options.
The current reference requires `browser-sandbox-v1`, network none, fixed nonroot
UID, read-only root and the pinned seccomp policy. Private subscription inputs
remain on the separate private disk. These bindings do not authorize a task or
prove a bounty succeeded. The application harness and external verifier must
check the original committed task/source/profile packet and the consumed files.

`source/` preserves 63 original source files and three additions. The original
64-file inventory also contained one generated Python bytecode cache; it is
recorded and excluded. `SOURCE-ORIGIN.json` maps every selected source file to
its original path/hash, and `SOURCE-CHANGES.patch` records eight modified files.
Runtime bytes match the independently reviewed guest used to derive image
`8eea5c4dff96a52878208dc4a1af8af8b2c03198d8603ae5e54a3f6e306dd6f2`.
Historical build and smoke scripts retain their original paths for inspection;
they are not portable entrypoints. Do not run their historical `BUILD.sh`.

The supported entrypoint is `derive.py`. It checks an independently selected
`SOURCE-LOCK.json` digest, all selected source bytes, the exact existing image7
rootfs/kernel/config, builder image and 4GiB scratch/256MiB result templates.
It extracts the existing measured rootfs into a fresh owned output directory,
overlays the reviewed runtime files and assembles a new verity image using an
isolated Docker container. Docker has network none, 4 CPUs, 4GiB memory and 256
PIDs; the build phase has a 900-second limit. Input hashing and output validation
are additional work. All heavy work belongs on Zed `/data`, not the laptop.

After independently obtaining the expected source-lock digest from the selected
reviewed source revision, inspect without execution:

```sh
python3 -I -B base-vm/browser-sandbox-v1/derive.py \
  --source-lock-sha256 "$EXPECTED_SOURCE_LOCK_SHA256" --check-source
```

To derive on Zed, supply the exact base bundle and reviewed templates already
available there, plus a new output path:

```sh
python3 -I -B base-vm/browser-sandbox-v1/derive.py \
  --source-lock-sha256 "$EXPECTED_SOURCE_LOCK_SHA256" \
  --base-bundle /data/selected/image7 \
  --templates /data/selected/templates-4g \
  --out /data/owned/new-browser-base-build
```

No private path or credential is required. A Docker failure, changed source,
unexpected output image or unconfirmed owned-container removal fails the run.
Unknown daemon/creation state is retained as an explicit recovery record; the
script does not claim to control a wedged Docker daemon or hostile administrator.
Keep the final artifacts and derivation record/log; remove intermediate rootfs
and tar copies after review. Never remove another VM or container.

This is an **existing-base derivation**, not a clean rebuild of Debian, Linux or
the builder image. It does not establish a fully reproducible supply chain,
friend distribution, native browser behavior or funded acceptance. Existing
bundle/builder binary availability and their source/license inventory remain
release requirements. Browser containers are selected separately by exact OCI
digest; they are not embedded in this base. The 4GiB scratch selection is explicit
and does not alter the generic app's default. Result/private maxima remain 1GiB.

Dstack adaptations retain their Apache-2.0 notices. The Playwright seccomp
policy retains its upstream Apache-2.0 license. See `licenses/` and
`SOURCE-ORIGIN.json`; the repository MIT license does not replace third-party
terms or license the entire Linux/Debian binary bundle under MIT.
