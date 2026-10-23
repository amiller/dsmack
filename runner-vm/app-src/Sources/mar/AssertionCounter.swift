// AssertionCounter.swift — honest recovery of the App Attest assertion counter
// from the EXACT assertion bytes the producer just generated (loop40-swift-repair1
// lane, 2026-10-22). SWIFT04 requires the run-result envelope and the pair
// evidence to carry launch_counter / result_counter; those values MUST come from
// the real assertion, never fabricated.
//
// The counter is bound by the assertion's authenticatorData (the verifier
// recovers it there — AppAttestVerify.verifyAssertion). DCAppAttestService
// returns the assertion as CBOR {"authenticatorData": bstr, "signature": bstr};
// authenticatorData is rpIdHash(32) ‖ flags(1) ‖ signCount(4, big-endian) ‖ …
// We decode the CBOR with the reviewed marAttest decoder (no bespoke CBOR here)
// and read signCount at offset 33..37, exactly as Authenticator.parse does. This
// is a READ of the producer's own output, so the value we record equals what any
// verifier recovers from the same assertion bytes.

#if canImport(Darwin)
import Foundation
import marAttest

/// Recover the App Attest signCount (counter) from an assertion CBOR blob.
/// Fail-closed: a malformed assertion or short authenticatorData throws rather
/// than yielding a guessed counter.
func assertionCounter(_ assertionCbor: Data) throws -> Int {
    let value = try AttestCBOR.decode(assertionCbor)
    guard let obj = value.asMap else { throw Fail("assertion: not a CBOR map") }
    guard let authData = obj[.str("authenticatorData")]?.asData, authData.count >= 37 else {
        throw Fail("assertion: authenticatorData missing or < 37 bytes (no signCount)")
    }
    let b = authData.startIndex
    // signCount: 4-byte big-endian at offset 33 (same offsets as
    // AppAttestVerify Authenticator.parse / attest_core.authenticator).
    let counter = Int(authData[b + 33]) << 24 | Int(authData[b + 34]) << 16
        | Int(authData[b + 35]) << 8 | Int(authData[b + 36])
    guard counter >= 1, counter <= 1 << 31 else {
        throw Fail("assertion: recovered counter \(counter) outside 1...2^31")
    }
    return counter
}
#endif
