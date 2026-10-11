# Independent compatibility vectors

`uebelack-development.json` and the values in `uebelack-assertion.json` come from
[uebelack/node-app-attest](https://github.com/uebelack/node-app-attest/tree/f16c4bb71b737466872bc8b8a7dfd215364eaa83/test),
commit `f16c4bb71b737466872bc8b8a7dfd215364eaa83`, downloaded 2026-09-09.
See the accompanying MIT license. The assertion fixture extracts only the published
test's inputs. The enrollment fixture is unchanged.

These are independent historical fixtures, not captures from our lab. The enrollment
chains to Apple's pinned root and is checked at 2024-06-01, inside its certificate
validity period. A separate test verifies that it is rejected as a fresh 2026 proof.
The assertion fixture verifies ECDSA hash layering and Apple's legacy AT flag behavior.

Generated fixtures in `test_verifier.py` use a clearly named synthetic root and are
kept separate from these Apple-rooted fixtures. Neither establishes the second-
credential attack or fixed-code membership.
