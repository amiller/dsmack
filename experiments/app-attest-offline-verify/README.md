# App Attest offline verification

## Question

Given an App Attest attestation from a Mac, can a third party check, with no
network access, that it chains to Apple and binds a specific key, app and
client data?

## Answer

Yes. Five checks over the attestation object are enough. The included vector,
produced by a signed probe app on a Mac mini running macOS 27.0 on 15 September
2026, passes all five and was issued in Apple's production environment.

## Guides

Trust & admission: the first link of the evidence chain from Apple to an app's
keys. The production verifier is `verifier/core.py` (`verify_attestation`),
which adds assertion checks, policy and time handling.

## How it works

An app with the App Attest entitlement asks `DCAppAttestService` to generate a
Secure Enclave key, then to attest it over a 32-byte client data hash. Apple
returns a CBOR object (`fmt: apple-appattest`) holding a two-certificate chain
and authenticator data. `verify.py` checks:

1. the chain leads to the Apple App Attestation Root CA (`trust/apple-app-attestation-root.pem`);
2. the leaf's nonce extension (OID `1.2.840.113635.100.8.2`) ends with
   `sha256(authData ‖ clientDataHash)`;
3. `sha256` of the leaf's public key equals the key identifier;
4. the first 32 bytes of `authData` equal `sha256(teamID.bundleID)`;
5. the counter is zero and the credential ID equals the key identifier.

The AAGUID in `authData` names the environment: `appattest` for production,
`appattestdevelop` for development.

To bind another key to the attestation, put its hash in the client data. The
dsmack node does this for its own keys.

## Run

```sh
python3 verify.py vectors/mini-2026-09-16 DC9JH5DRMY.dev.dsmack.provider ../../trust/apple-app-attestation-root.pem
python3 -m pytest -q test_verify.py
```

Any machine with `cbor2` and `cryptography` (both in the repository's
requirements). Producing a new vector needs a Mac; see `probe/`.

## Recorded result

15 October 2026, Linux, Python 3, cryptography 43.0.3:

```
5 passed
{'issued': '2026-09-15T13:58:35+00:00', 'aaguid': 'appattest', 'public_key': '04c56279…71c25'}
```

The tests cover the genuine vector and four refusals: a different client data
hash, a different key identifier, a different app ID, and a self-made root with
Apple's subject name.

## Files

| File | Contents |
|---|---|
| `verify.py` | The five checks, about 40 lines |
| `test_verify.py` | Positive and negative tests against the vector |
| `vectors/mini-2026-09-16/` | `attestation.cbor`, `keyId.txt` (base64), `challenge.bin`, `clientDataHash.bin` (`sha256(challenge)`) |
| `probe/appattest-probe.swift` | The app that produced the vector: generate a key, attest it, write the files |
| `probe/build.sh` | Compile, bundle with a provisioning profile, and sign with the App Attest opt-in entitlement |

## Provenance

The vector and probe come from a Mac mini (probe built 16 September 2026).
`build.sh` is the original probe build script with the keychain path, keychain
password and signing identity moved to the `KEYCHAIN`,
`KEYCHAIN_PW` and `SIGN_ID` environment variables. The verifier was written for
this PoC on 15 October 2026.

## Limits

- Checks an attestation only, not later assertions or the code-hash
  (`CDhash`) commitment carried in assertions.
- Validity is checked at the leaf's issue time, not the current time.
- Running `probe/build.sh` needs a provisioning profile named
  `embedded.provisionprofile` for the app ID, and a GUI login session on the
  Mac.
