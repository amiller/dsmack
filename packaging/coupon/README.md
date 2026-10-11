# Packaged development dsmack coupon node

This package mounts the reviewed coupon service on the paired Abalone Noise peer
registry. It uses direct-provider delivery, not the older inference-routing gift
launcher. It is a synthetic Linux amd64 development profile, not a supported live
issuer or a recipient CVM. The selected future issuer is a dstack-backed dsmack
node; the Mac app participates in the network. Attestation/admission, sealed secret
provisioning and rollback protection must be qualified before a live launch.

Build an allowlisted source package from the code repository:

```sh
python3 tools/coupon_package.py --abalone-source /absolute/reviewed/abalone --output local-data/coupon-node.tar.gz
mkdir -p local-data/coupon-package
tar -xzf local-data/coupon-node.tar.gz -C local-data/coupon-package
docker build --platform linux/amd64 -f local-data/coupon-package/packaging/coupon/Dockerfile -t dsmack-coupon-node:local local-data/coupon-package
docker run --rm --network none --entrypoint node dsmack-coupon-node:local packaging/coupon/smoke.mjs
```

The paired source revision and every selected module/lock hash are pinned in
`paired-source.json`. A modified selected file is rejected. Extra checkout files,
state, tokens, node_modules, Pi/ACI trees and Git history are excluded. Use
`--export-pair` to export the same allowlisted dependency archive for separately
approved CI distribution; no archive is uploaded by the builder.

The compressed source tar has sorted names, normalized permissions/ownership and
zero timestamps. Two builds with identical input bytes/revision produce identical
tar bytes. `source-manifest.json` records actual source hashes as well as checkout
revision: uncommitted input changes produce a different tree hash and
`dsmack_inputs_match_checkout_revision: false`; the checkout revision alone does
not describe a dirty candidate or establish independent review. The OCI base
digest and Linux amd64 CPython 3.11 wheel bytes are pinned; npm uses the paired root
lock with install scripts disabled. Building fetches these dependencies, while
the packaged synthetic smoke runs with external networking disabled. Full image
byte reproducibility is not claimed: install/build metadata must be qualified
separately before approving production measurements. This is not a published image.

`node node/coupon-node.mjs init-synthetic --dir /absolute/new/operator-dir` creates
a new owner-only directory, synthetic config and distinct issuer/sponsor/observer
transport seeds. It refuses an existing directory. `serve --dir ...` opens the
peer and private worker using those files. The config's issuer must equal the
loaded private identity before readiness. A non-synthetic provider is refused by
this launcher. File ownership/modes are local protections, not TEE secrecy.

The host needs a persistent protected operator directory owned by the container's
`node` UID (1000), with directory mode 0700 and private files 0600. Keep the entire
directory, including the worker state/SQLite WAL and observer key; do not replace
it with an old snapshot to recover a failed claim. No volume or funded account is
created by the image. The source package is also runnable on its declared host
profile after installing the pinned Python closure and `npm ci` inside
`vendor/abalone`; there is no dependency on an adjacent/private checkout.

Serve's stdin/stdout are protected local operator pipes. Keep stdin open for the
service lifetime (for example, the trusted supervisor runs the image with `-i`).
EOF or SIGTERM closes the peer and worker; restarting preserves the identity,
winners, issuing intents and ciphertext. Do not connect these pipes to a network
socket. Do not send their stdout to an ordinary log collector: authorized
provisioning replies contain bearer coupons. The JSON line operations are:

```json
{"id":"one","op":"provision","budget_nano_usd":"1","claim_expires_at":"2030-10-10T00:00:00Z"}
{"id":"pending","op":"pending"}
```

Provisioning uses the protected sponsor mapping as local supervisor authority.
It does not prove a remote sponsor is authenticated. The peer frames never expose
this control operation or accept roles/principals. Public readiness has the issuer
peer, addresses, supported `/1`, `/2`, `/3`, local-unattested label and false release
authorization. All claims remain subject to the reviewed protocol and peer binding.

The packaged smoke starts and restarts the actual node process, claims through
Noise, decrypts locally, verifies identical stored ciphertext after restart and
denies a different peer. A test-only SQLite trigger records a synthetic create
then raises at the provider boundary; restart must retain reconciliation state
and never create again. It also refuses a changed identity and checks stderr for
bearer/credential leaks. It prints only a redacted result summary. This fixture
does not establish live provider retrieval, privacy, attestation or settlement.

The credential-free manual validation workflow requires an explicit HTTPS URL for the reviewed
allowlisted paired source archive. It checks the recorded source hashes without
using an operator credential or assuming that GITHUB_TOKEN can read another private
repository. Until the selected source/archive has separate distribution approval,
the hosted job cannot run from a private adjacent checkout. Automatic PR CI/CD is
not installed or qualified by this manual workflow. Local package checks
remain usable now. The source candidate and its artifacts are not cleared for upload.

The [public testnet profile and rollout](public-testnet.md) defines a separate
public discovery/status and operational acceptance contract. It preserves the
current debug custody limits and does not reclassify a staging node by its URL.
