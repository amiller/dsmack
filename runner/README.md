# Native workload runner

The prototype runs a digest-pinned compose workload through Apple's
Containerization 0.33.4 and Virtualization.framework. Its guest has no network
device. A Unix socket at `/run/egress.sock` reaches the host proxy, which applies
egress policy, originates pinned TLS and signs receipts. The host and stand-in
KMS can read issuer secrets; App Attest establishes identity and binding.

Read the [runner protocol](../docs/protocols/runner.md) and
[peer interface](../docs/protocols/runner-peer.md) for exact compose, key,
attestation, volume and task semantics. Provider verification has separate
[dstack issuer](verify/DSTACK_ISSUER.md) and
[Ethereum finality](chain/ethereum-finality/README.md) guides.

## Build and configure

Build on an Apple Silicon Mac with the declared Swift package toolchain:

```sh
cd runner
./build.sh
bin/runner check test/app-compose.json
bin/runner --help
```

An actual run requires the kernel and `vminit` bytes pinned by
`Sources/runner/main.swift`, a digest-pinned workload image/archive, an isolated
base/output directory and a deliberately configured KMS. Kernel acquisition,
Apple signing and hardware acceptance require their own qualification; this
repository does not include the old lab's image store or credentials.

`sign.sh` and the hardware scripts in `test/` retain lab-specific signing and
host assumptions. Review and adapt their configuration in your authorized Mac
environment before use. They are not a portable one-command installation.
Use the [native build guide](../docs/native-build.md) for participant app signing.

The KMS helpers import the repository's verifier and pinned Apple root. The
JavaScript verifier uses the vendored App Attest module and declared dependencies;
it requires no adjacent private repository.

## Local checks and state

```sh
python3 -m unittest runner.kms.test_app_binding
node runner/verify/macrunner.test.mjs
```

Additional quote checks require `npm ci` in `runner/verify` and explicit provider
or RPC configuration. `test/run_tests.sh` and `test/attested.sh` boot real VMs,
access hardware/services and retain output; run them only as configured hardware
rehearsals. Keep outputs outside tracked source and remove disposable installs
and VM/build output after preserving results.

Named volumes are unencrypted, operator-readable and rollbackable. They must not
hold the sole copy of a secret. The app-id binding preserves derived keys and
volumes across admitted upgrades; changed builds require explicit admission.

`--no-attest`, KMS `--dev-unattested` and receipt `--dev-unattested` are synthetic
paths. `--dev-test-anchor` and `--dev-task-boot-delay-ms` are refused with
`--attest`. Never use development paths with a real provider key.
