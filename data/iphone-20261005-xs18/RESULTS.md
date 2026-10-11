# iPhone XS, iOS 18.5: App Attest with the CDhash opt-in — 2026-10-05

**Answer.** On iOS 18.5 (build 22F75, from the leaf certificate's 1.2.840.113635.100.8.7), an app with
`com.apple.developer.devicecheck.app-attest-opt-in = [CDhash]` gets a `cdHash` map in both the
attestation object and the assertion, but **outside the signed data**:

- Attestation object keys: `fmt, cdHash, attStmt, authData`. The certificate nonce
  (1.2.840.113635.100.8.2) equals SHA256(authData || SHA256(challenge)). cdHash is not in it, and no
  certificate extension carries it (extensions: 8.5 app/environment, 8.7 OS version, 8.2 nonce; no 8.6).
- Assertion keys: `cdHash, signature, authenticatorData`. The signature verifies over
  SHA256(authenticatorData || SHA256(clientData)); cdHash is not covered.
- authData flags 0x40 in both (no extension data). On iOS 27 the hash is inside authData extensions
  (`apple_cd_hash_hash_01`, flags 0xc0) and covered by both signatures ([iOS 27 run](../iphone-20260923/RESULTS.md)).
- Value: `hash` = 20 bytes `ac87e01cdf32def28f6de978d7536f2b7c640edd`, `type` = 0x02 (SHA-256,
  truncated to 20 bytes, the CandidateCDHash form). Same value in attestation and assertion.

So on 18.5 the hash is reported but unauthenticated: the device or app could replace it without
breaking any signature. It cannot support a code-identity admission policy. iOS 27 moved it under
the signatures.

## Conditions
- iPhone XS (iPhone11,2), UDID REDACTED_DEVICE_IDENTIFIER, iOS 18.5 (22F75). XS cannot run iOS 26/27.
- TestFlight build 2 of App Store Connect app "AppAttest Lab dsmack" (id 6819392473), bundle
  `dev.dsmack.provider`, production environment, internal group "Lab". Same AppAttestLab source as the
  09-23 honest build plus an app icon and ITSAppUsesNonExemptEncryption=false. Apple re-signs TestFlight
  builds; the installed binary was not retrieved, so the 20 bytes were not matched to a computed CDHash.
- Verifier: laptop, identity-only policy; both accepted. Snapshot `captures/xs18-snapshot.sqlite` (sha256 7ea0443a2f435dc3…).

## Not tested
iOS 18.6–26.x; whether the 20 bytes equal the prefix of the installed binary's CDHash; a modified build.
