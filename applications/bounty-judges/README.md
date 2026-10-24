# Bounty judges and acceptance join

This package decides whether a bounty submission is accepted under the Opus 4.8
pilot policy. Three judges each generate a browser test suite; each suite runs
against the base and the candidate; a primary review runs the fixed original
checks. [closure.py](closure.py) joins those ten stages into one acceptance
result. It is application logic outside the generic signed runner and base VM.

- [GENERATOR-DRIVER.md](GENERATOR-DRIVER.md): the three-judge generator (fixed
  Claude Code 2.1.187, requested model `claude-opus-4-8`), the declarative suite
  language and the external Playwright driver.
- [PRIMARY-REVIEW.md](PRIMARY-REVIEW.md): the 14-test primary review covering the
  original browser specs, all 80 original logic cases and six feature checks.

## The join

The application derives `expected` from the frozen admitted task profile and its
own request/nonce allocation, never from the submitter.
`join(original_canonical_results_bytes, expected, verify_original)` calls the
genuine verifier separately for every stage. The callback validates the retained
evidence against the expected request, image, source, enrollment, challenge and
replay state, and returns `VerifiedOutputs`: an authenticated output manifest,
the exact exported file bytes, and a workload status bound to the original
receipt/exit and trusted driver. It classifies crashes and timeouts as
infrastructure failures even if a worker left an earlier successful checks file
behind. No network endpoint accepts a worker's `verified:true`.

The output manifest is canonical JSON, schema `dsmack-bounty-output-manifest/1`,
with sorted `files` rows of `name`, `size` and `sha256`. It is an
application-level manifest, distinct from the guest export layout and the
verifier's transport manifest; a trusted adapter builds it from authenticated
outputs.

Generation outputs include `suite.json` and `checks.json`. Base and candidate CI
checks bind the same generated suite hash and report every suite test ID in the
same sorted order as passed or assertion-failed; skipped or missing tests are
rejected. The primary review requires all four fixed browser baselines, four
fixed logic baselines and six feature checks. All checks come from the admitted
trusted driver, which interprets constrained declarative suites, so generated
JavaScript never grades its own assertions. The join trusts the authorized
checker's output.

A successful join returns domain-separated acceptance-results and
execution-closure digests. It signs, submits and broadcasts nothing. Missing
evidence, incomplete stages, infrastructure failures, source/image swaps, model
mismatch, output substitution and failed candidate assertions are rejected.

## Tests

```sh
python3 -m unittest discover -s applications/bounty-judges -p 'test_*.py' -v
node applications/bounty-judges/test_browser_driver.mjs
node applications/bounty-judges/test_primary.mjs
```
