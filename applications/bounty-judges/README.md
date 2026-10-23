# Multi-run acceptance join

`closure.py` implements the closed ten-stage acceptance join for a **new pilot
policy**: three independent test-generation runs, each suite evaluated against
base and candidate, plus the primary fixed review. It is application logic outside
the generic signed runner and base VM. It does not implement the original bounty's
three-Claude-5.5 terms or claim those terms were fulfilled.

The trusted application derives `expected` from the frozen admitted task profile
and its own request/nonce allocation. Never take this object from the submitter.
`join(original_canonical_results_bytes, expected, verify_original)` calls the
full genuine verifier separately for every stage. The callback must validate the
original retained evidence against the supplied independently expected request,
image, source, enrollment, challenge and replay state. It returns `VerifiedOutputs`
with an authenticated output manifest, exact original exported file bytes and
a normalized workload status bound to the original receipt/exit and trusted driver.
The callback must classify crashes/timeouts as infrastructure failure even when
a worker leaves an earlier successful checks file behind.
There is deliberately no network endpoint that accepts a worker's `verified:true`.

The application output manifest is canonical JSON with schema
`dsmack-bounty-output-manifest/1` and sorted `files` rows containing `name`, `size`
and `sha256`. This is a new application-level manifest, **not** the guest export
layout or full verifier's transport manifest. A trusted adapter must construct it
from authenticated outputs; do not reinterpret a transport manifest as this schema.

Generation outputs include `suite.json` and `checks.json`. CI checks bind the
same generated suite hash for base and candidate. Both runs must report every
generated suite test ID, in the same sorted order, with a terminal passed or
assertion-failed classification; skipped or missing tests refuse. The primary review requires all
four fixed browser baselines, four fixed logic baselines and six feature checks.
All checks must be emitted by the admitted trusted driver. Arbitrary generated
JavaScript cannot be trusted to grade its own assertions: use an admitted driver
with constrained declarative suites, or independently review/admit generated code.
The join itself cannot detect dishonesty inside an authorized checker.

Successful joining returns domain-separated acceptance-results and original
execution-closure digests. No payment signature, submission or broadcast occurs.
Missing evidence, incomplete stages, infrastructure failures, source/image swaps,
model mismatch, output substitution and failed candidate assertions refuse.

Run the synthetic adversarial contract controls with:

```sh
python3 -m unittest discover -s applications/bounty-judges -p 'test_*.py' -v
```

The [generator/driver contract](GENERATOR-DRIVER.md) now provides a bounded
three-judge generator recipe using fixed Claude Code 2.1.187 and an explicit
requested Opus 4.8 model ID, plus the strict declarative suite validator and
external Playwright driver. Generated JavaScript is never executed as checker
authority. Run its lightweight Node controls as well:

```sh
node applications/bounty-judges/test_browser_driver.mjs
```

These controls do not qualify real model generation, browser execution or VM
evidence. Remaining: independent review, actual model/CLI/settings qualification,
selected image builds and pins, trusted genuine-verifier adapter, immutable
stage-plan admission, durable orchestration, and live native qualification before
these digests may enter a settlement certificate. The original closure source
and tests are unchanged.
