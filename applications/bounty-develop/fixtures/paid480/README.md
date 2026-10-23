# Offline paid480 constructor fixtures

These public task documents and the original bounty-arcade source projection let
the constructor tests run from this repository alone. SHA256.json records their
exact bytes. The original policy and source closures stay unchanged; policy.json
and terms.json select the separate prospective paid480 version.

The tests create explicitly synthetic claim IDs and nonces in memory. No private
claim capability, credential, operator state, attestation or payment receipt is
included. A passing offline test does not authorize execution or establish a
funded task, native VM qualification, acceptance or payment.

From the repository root, with Python 3 and no dependency installation:

```sh
python3 -B applications/bounty-develop/test_paid480_policy.py
python3 -B applications/bounty-develop/test_paid480_lowering.py
```

The optional --originals and --data flags allow an independently selected fixture
directory. Both commands run offline and create only temporary test files, which
they remove on exit.
