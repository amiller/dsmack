# Mac ARM Base-only coupon image

[Dockerfile.mac-base](Dockerfile.mac-base) builds the `linux/arm64` coupon node
image that the live testnet issuer runs on a Mac mini. The image admitted
on 12 October 2026 has manifest digest
`sha256:4ce99a16c5a6b25fd24f2c6bd259af525fc1837334a9b447973c23d7d07fecc2`; its
source revision is not yet in this repository. The image is not a recipient CVM,
and the issuer's custody limits in the [packaged profile README](README.md)
(operator-readable secrets, no rollback protection) apply unchanged.

## What differs from the linux/amd64 image

- The pinned Node base `node:24.15.0-bookworm@sha256:f22d6a1f…` is kept exactly
  as supplied: it is a multiarch OCI index that already includes
  `linux/arm64/v8` (per-arch manifest
  `sha256:92c191629a40c9ca674e7d5c0c1edf25febb5e2f30f551f187ac71f61595b9f8`),
  so the same digest pins both profiles.
- The `finality` build stage is omitted and `bin/dsmack-ethereum-finality` is
  not installed. The Rust Helios checker, its pinned upstream checkout
  `2af9b41887e069144ee56cd710f3ddca195473f8` and its reviewed locked build and
  refusal evidence cover the `linux/amd64` profile only; no arm64 build of it
  is reviewed in this snapshot.
- The Python closure is installed from
  [python-wheels-mac-base.json](python-wheels-mac-base.json) via
  [install_python_mac_base.py](install_python_mac_base.py): the same 25 package
  names and versions as [python-wheels.json](python-wheels.json), with the five
  compiled wheels (`cryptography`, `cffi`, `cytoolz`, `pycryptodome`,
  `pydantic-core`) replaced by the `aarch64` wheels published in the same
  upstream releases. No package is upgraded, added or removed; pip is still
  bootstrapped from the pinned `pip-25.0.1` wheel with `--no-index --no-deps
  --no-compile`. The 20 pure wheels are byte-identical files.
- Everything else — approval-root measurement build arg, source layout,
  `npm ci --ignore-scripts --omit=dev`, `USER node`, the wrapped
  `python-worker` child execution, `ENTRYPOINT node node/coupon-node.mjs` — is
  unchanged from [Dockerfile](Dockerfile).

## Sepolia is unsupported on this profile

The Sepolia finalized-consumption issuance path
(`FinalizedIssuanceGuard`, trust profile
`helios-ethereum-sepolia-finalized-experiment`, chain 11155111) requires the
omitted checker binary. The Mac worker explicitly refuses any signed approval
whose `guard.chain_id` is not 8453 before state admission or effects. With the
shipped approval root (`{"public_key_hex":null}`) no admission passes. Only the
Base mainnet
single-RPC guard (`BaseSafeIssuanceGuard`, chain 8453, trust profile
`base-mainnet-rpc-safe-debug-v1`, pure Python over the pinned
`https://mainnet.base.org` courier) is offered. That guard is explicitly
debug-trust single-RPC reading, not authenticated L1 finality; see
`experiments/coupon_redemption/issuance_guard.py`.

## Build

```sh
python3 tools/coupon_package.py --profile mac-base --abalone-source /absolute/reviewed/abalone --output local-data/coupon-node.tar.gz
mkdir -p local-data/coupon-package
tar -xzf local-data/coupon-node.tar.gz -C local-data/coupon-package
docker buildx build --platform linux/arm64 -f local-data/coupon-package/packaging/coupon/Dockerfile.mac-base -t dsmack-coupon-node:mac-base local-data/coupon-package
docker run --rm --network none --entrypoint node dsmack-coupon-node:mac-base packaging/coupon/smoke.mjs
```

The explicit `--profile mac-base` exporter includes the Mac modules, native
wheel lock, installer and Dockerfile while preserving the default amd64
export. `--network none` and the nonroot user are preserved. Qualification
requires actual image checks and genuine new-workload evidence separately;
a dependency probe does not establish either.

## Dependency feasibility evidence

A credential-free probe (2026-10-11, anonymous HTTPS to `pypi.org` and
`files.pythonhosted.org` only) resolved the closure: all 20 pure wheels matched
the supplied pins byte-for-byte (PyPI-recorded sha256 equal to the lock values,
verified again by download), and each of the five compiled packages published
exactly one matching `aarch64` wheel for the same version, interpreter/abi and
glibc tiers, downloaded and sha256-verified. A disposable `linux/arm64`
container check built with the existing `abalone-oci` buildx builder (never the
whole production image, and not concurrently with any production build) ran the
real installer script on the arm64 base and imported the installed closure,
including the five compiled modules, under the arm64 interpreter. The probe
records are with the task results; they establish dependency feasibility only,
not a qualified runtime, Mac build, TEE deployment or any network behavior.
