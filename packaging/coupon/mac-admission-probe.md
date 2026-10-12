# Coupon-free Mac issuer admission probe

[`tools/coupon_mac_admission_probe.mjs`](../../tools/coupon_mac_admission_probe.mjs)
uses the normal Abalone client to open the public Noise connection and verify
fresh issuer info/evidence and signed staging approval. It closes that client
without calling offer, claim, wait, coupon status, redemption or inference.
It reads no coupon or provider credential and changes no live service configuration.
Network admission is read-only with respect to coupon/provider effects; it still
contacts the issuer and obtains fresh App Attest evidence.

## Reviewed inputs

Use Node 24 and a clean public Abalone Git checkout with its locked dependencies
already prepared on the operator's approved execution host. This command performs
no installation or build. The declared client revision must equal Git HEAD;
tracked edits and unexpected untracked files refuse before importing the client.
The entry module must be tracked. Ignored installed dependencies are trusted
operator inputs: this is not a verification of every `node_modules` byte or a
replacement for reviewing the selected public client and lockfile.

The public preview.2 client source is
[`e82897cfb205b3e3da2204eaeb5e8bde89b43b23`](https://github.com/amiller/abalone/tree/e82897cfb205b3e3da2204eaeb5e8bde89b43b23).
Its `lib/coupon-attested.mjs` matches the reviewed coordinator client for this
wrapper (SHA-256 `b8c2960f1aaffedaa1a789e8ef0fe536ac3fa4fa991a7ff3fdc335fcd261592e`).
This is a client source example, not permission to change an issuer epoch or
paired-source manifest. The release coordinator selects and records the exact
public revision compatible with the intended deployment; a later revision needs
its own source/interface review.

Supply absolute paths to two reviewed **public policy** files, each at most
64 KiB and a regular file rather than a symlink:

- The pin JSON has exactly `identityPolicy`, `expectedIdentityPolicySha256`,
  `expectedIssuancePolicySha256`, and `expectedIssuerPublicKeySha256`.
  The identity profile is `mac-appattest-coupon-v1`; expected hashes are 64
  lowercase hexadecimal characters. Use the epoch's reviewed signed inputs,
  never values copied from an untrusted probe response.
- The staging-approval file contains the exact signed approval bytes. The
  approval root is a separate trusted 64-hex public key argument, not a bearer
  secret. The normal client verifies approval signatures and issuer bindings.

The last argument is the reviewed public WSS multiaddress including the issuer
PeerId. Neither input file, any command argument nor the output needs a coupon,
management token, provider credential or private signing key.

## Run and publish separately

The following uses placeholder paths, approval root and peer. Replace them with
the release coordinator's reviewed public inputs; do not run the placeholders:

```sh
node tools/coupon_mac_admission_probe.mjs \
  --source-revision e82897cfb205b3e3da2204eaeb5e8bde89b43b23 \
  /absolute/approved-abalone-checkout \
  /absolute/reviewed-public-pin.json \
  /absolute/reviewed-public-approval.json \
  APPROVAL_ROOT_HEX PUBLIC_WSS_MULTIADDRESS > /tmp/mac-admission.json
```

On success it emits the existing Mac admission-report schema, including the
probe's own observation timestamp and explicit false coupon/provider-effect
flags. It does not report claim readiness, provider admission, independent nodes
or private custody. On any failure it exits 1 with a fixed message and emits no
report; it never prints upstream error bodies, input files or paths. The normal
client uses a 30-second admission timeout. Source-inspection Git calls have
5-second limits. This is not a hard whole-process deadline against arbitrary
code or a hung host; use the operator's process supervisor when one is required.

Only after a successful probe, normalize its output with
[`tools/mac_coupon_status.py`](../../tools/mac_coupon_status.py) and the matching
reviewed public deployment manifest. The [status runbook](status/README.md)
describes staging and atomic publication of `issuer.json`. A failed probe must
not be followed by normalizing an old report as if it were new. The Abalone
release coordinator retains live deployment and publication ownership.

## Offline checks and limits

```sh
node --test tools/test_coupon_mac_admission_probe.mjs
```

Tests use an explicit synthetic client in a temporary Git fixture. They check
source/policy refusal, bounded inputs, cleanup, generic errors and that the
wrapper invokes admission/close only. They do not verify fresh hardware,
network connectivity, production client dependencies or provider behavior.
The public wrapper supplies a reproducible report-producing entry point; an
actual fresh run against the selected epoch is still a separate qualification.
