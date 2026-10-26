# DsmackRunner: generic VM runner for macOS

DsmackRunner.app boots an admitted Linux image under Hypervisor.framework and
signs what it observed with App Attest. It has two modes:

```text
dsmack-runner enroll <out> <challenge>                 # App Attest key + attestation
dsmack-runner hvf-v3 <out> <session.json> <challenge> <keyId>
```

`hvf-v3` reads an external session document naming the admission policy, image
manifest, dstack checksum manifest and metadata, contract admission, compose
manifest, workload disk and blank scratch/result templates. The app admits the
image against the policy, stages verified copies, and hands the native backend
the kernel/initrd bytes, a launch spec and five disks (vda system, vdb scratch,
vdc workload, vdd result, optional vde private input), plus an optional
virtio-net descriptor. After the guest halts it finalizes the result disk and
console, writes a run-result envelope, and produces two App Attest assertions
(launch evidence and result). A session with `"grant": {"url", "task_id"}` also fetches
the run's worker grant from that coordinator before boot and hands it to the guest
agent over the `dsmack-ctl` port (`dstack-compat/README.md`). The app carries no image identity; admitting a
new base image is a policy and manifest change. Base images and the application
client (`applications/pilot-client`) live elsewhere in this repository.

## Layout

- `app-src/` Swift executable `mar` (packaged as `dsmack-runner`).
- `control-src/` `marAttest`: App Attest CBOR decoding and offline verification.
- `native/source-tree/apple-static/` Rust staticlib `libdsmack_hvf_returning.a`:
  the v3 C ABI (`backend-v3/`) and its HVF consumption over libkrun.
- `native/source-tree/source/` modified libkrun.
- `packaging/` unsigned build, signing and entitlements policy.
- `guest-profile-source/` builder for the blank ext4 scratch/result templates.

## Build

Native archive, on any machine with rustup (the toolchain, Rust 1.97.1 with the
`aarch64-apple-darwin` target, is pinned in `native/source-tree/rust-toolchain.toml`):

```sh
runner-vm/native/build.sh
```

App, on an Apple silicon Mac with Xcode 27.0 (27A266a, Swift 6.4); `build.sh` checks the
Swift version:

```sh
runner-vm/packaging/build.sh runner-vm/native/source-tree/target/aarch64-apple-darwin/release
```

This produces `runner-vm/packaging/build/DsmackRunner.app`, unsigned. Sign it with
`KEYCHAIN=... SIGN_IDENTITY=... ENTITLEMENTS=runner-vm/packaging/DsmackRunner.entitlements PROFILE=... runner-vm/packaging/sign.sh`;
see `packaging/sign-production.md` for the production identity.

### Reproducing a published build

The build does not depend on the checkout directory, `CARGO_HOME` or the rustup
location: `native/build.sh` remaps those paths, and `packaging/build.sh` links without
the debug map. The same commit gives a byte-identical archive and unsigned executable.
The native archive can be built in a clean container:

```sh
docker run --rm -u "$(id -u):$(id -g)" -e CARGO_HOME=/tmp/cargo -v "$PWD":/src -w /src \
  rust:1.97.1-slim runner-vm/native/build.sh
```

CDRegistry admits a re-signed copy of the approved build when its code slots,
masked page 0 and CodeDirectory header match (`entitlements_der` is the raw DER; the registry compares its shape); the signature is
free. Signing changes only page 0 fields that CDRegistry masks and the signature
appended after the code, so an unsigned rebuild compares directly with a signed
release:

```sh
python3 contracts/cd_args.py --measure runner-vm/packaging/build/DsmackRunner.app/Contents/MacOS/dsmack-runner
python3 contracts/cd_args.py --measure dsmack-runner   # the release asset
```

`rest` (code slots 1..n), `maskedPage0` and `codeLimit` must be equal. `header` and
`entitlements` compare only between binaries signed with `sign.sh`. The digests are
SHA-256; CDRegistry stores keccak-256 of the same bytes.

## Run

LaunchServices must start the signed app so App Attest works:

```sh
open -n -W --stdout out.log --stderr err.log DsmackRunner.app --args hvf-v3 "$OUT" session.json challenge.bin keyId.txt
```

`applications/pilot-client/coordinator` drives this for real tasks.

## Test

```sh
(cd runner-vm/native/source-tree/apple-static/backend-v3 && cargo test)
(cd runner-vm/control-src && swift test)
python3 -m pytest runner-vm/guest-profile-source runner-vm/packaging
```

## License

libkrun under `native/source-tree/source` is Apache-2.0 (its `LICENSE` is
retained). See [THIRD-PARTY.md](THIRD-PARTY.md).
