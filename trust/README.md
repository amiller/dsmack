# Apple trust anchor

`apple-app-attestation-root.pem` is Apple's App Attestation root, fetched over
HTTPS on 2026-09-09 from
https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem

Subject: `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`

DER SHA-256: `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`

`verifier/server.py` loads this file and compares its fingerprint with that
value; verdicts made under any other root, which only the Python test API can
supply, are labeled `synthetic_test_root`. The on-chain
[AppleEndorsements](../app-attest/contracts/src/AppleEndorsements.sol) contract
hardcodes the same root's P384 key.

Check the fingerprint:

```sh
openssl x509 -in trust/apple-app-attestation-root.pem -outform DER | sha256sum
```
