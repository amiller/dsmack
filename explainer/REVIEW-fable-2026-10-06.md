# Review of explainer/template.html prose, 2026-10-06

Scope: intro, Background, figure caption, "What iOS 27 adds", plate intros A–G, footer. Checked against
the page's own data and against `iphone-20260923/RESULTS.md`, `iphone-20261005-xs18/RESULTS.md`,
`notes/appattest-cdhash-re-2026-10-05.md`, `tasks/cd-registry-gas-2026-10-05.md`,
`solidity/test/{CDRegistry,MacAppAttestV1}.t.sol` and `solidity/fixtures/`. Template not edited.

## 1. Diagnosis

1. **MRSIGNER and MRENCLAVE are used as if already defined.** Background ¶3 ends "In SGX terms it's
   MRSIGNER"; "What iOS 27 adds" opens "something more like MRENCLAVE". Neither term is introduced,
   and the hedge "something more like" is covering for the missing definition. Section 3 below supplies
   the passage and the placement.
2. **CDHash appears in the diagram and caption before the page says what it is.** The caption says "three
   developers sign the same code, so the three CDHashes differ"; the definition arrives in the next
   section, and the reason signing changes it arrives in plate E. The reader cannot make the inference
   the caption asks for.
3. **"Because of that last step, we can recognize the same code no matter who signed it"** (iOS 27 ¶1)
   is not earned. Per-page hashing alone does not imply signer-independence; that needs plate E's fact
   that the signature sits after `codeLimit`. The sentence asserts the conclusion three plates early.
4. **Plate F's test sentence overreaches the repo.** "A verifier built on this registry passes forge tests
   against real evidence from an iPhone on iOS 27 and a Mac on macOS 27; the cross-team case is tested
   with a synthetic second team." In `solidity/`: no `src/*.sol` references `CDRegistry`;
   `MacAppAttestV1.t.sol` loads `real-apple.json` / `fresh-apple.json`, both Mac captures (clientData
   experiment `20260916`), no iPhone fixture; the resign fixtures are all team `DC9JH5DRMY` or ad hoc
   with no team (`C-adhoc-otherid` changes the identifier only), and `synth()` exists for gas
   measurement, not a second team. The 5,383/5,384-slot Darkbloom comparison is a real second team but
   is a CodeDirectory comparison, not an attestation.
5. **"It keeps one approved build" never says approved by whom.** The reader's next question after
   "doesn't need to trust any signer" is who chose the build and how it changes. The page's answer
   (constructor argument; a change is a new deployment or an admission decision) is the liability point
   the MRENCLAVE passage makes, and the page should close the loop in one clause.
6. **Caption's trust rule contradicts the figure.** "Highlighted boxes are what a verifier has to trust",
   then "Apple signs every attestation in both": Apple is trusted in both panels and is not a box. Either
   draw Apple or say the rule is about trust beyond Apple.
7. **Caption claims peers "check each other's keys and counters there."** Nothing on the page shows the
   registry holding keys or counters; plate F says only that the CDHash check is a mapping lookup. The
   counter logic lives in `MacAppAttestV1.sol`, which the page never mentions.
8. **Plate G editorialises and repeats.** "lands in the wrong place" is a judgement; the next sentence
   then says "outside `authData` and outside anything Apple signs", which is the fact. And "anyone between
   the phone and the server can rewrite it" omits the case that matters for a peer network: the app
   itself (`iphone-20261005-xs18/RESULTS.md`: "the device or app could replace it").
9. **"assertions" is named only after it is used** (Background ¶1: "the app signs requests with the key.
   Each of these assertions carries a counter").
10. **"or a contract they all read"** (Background ¶4) names the contract before anything motivates it; the
    reader meets a registry in the figure with no reason yet to want one. Plate F is where it is forced.

Minor: plate G's 18.5 disassembly row is build 22F76 while the capture is 22F75 (RE note: match "not
verified"); the footer's "the same app" on the XS is a TestFlight build Apple re-signed, and its 20
bytes were never matched to a binary. Both are one-clause fixes, listed in §2.

## 2. Rewrites, before → after

### Background ¶1, naming assertions

Before:
> After that the app signs requests with the key. Each of these assertions carries a counter, and the server rejects any assertion whose counter has not gone up.

After:
> After that the app signs each request with the key; Apple calls the signed request an assertion. Each assertion carries a counter, and the server rejects any whose counter has not gone up.

### Background ¶3, where the new passage goes

Before:
> So the developer is trusted twice. The developer runs the only verifier. And the attestation names the app by App ID, a team ID plus a bundle ID, which is a signer identity: whoever controls the team's signing account can ship different code under the same App ID and the attestation looks the same. In SGX terms it's MRSIGNER. For a service guarding its own API that is fine, since the developer is the party being protected.

After:
> So the developer is trusted twice. The developer runs the only verifier. And the attestation names the app by App ID, a team ID plus a bundle ID, which is a signer identity: whoever controls the team's signing account can ship different code under the same App ID and the attestation looks the same.
>
> [§3 passage, paragraphs 1 and 2, go here]
>
> For a service guarding its own API, signer identity is fine, since the developer is the party being protected.

### Background ¶4, defer the contract

Before:
> In the peer network neither holds. The verifier is every peer, or a contract they all read, and the developer who signed some node's build is one more participant who might cheat.

After:
> In the peer network neither holds. The verifier is every peer, and the developer who signed some node's build is one more participant who might cheat.

(The figure's registry box then needs the caption to introduce it; see next item.)

### Figure caption

Before:
> Highlighted boxes are what a verifier has to trust. On the left the developer signs every copy and runs the only verifier. On the right three developers sign the same code, so the three CDHashes differ; each device enrolls its Apple attestation with a registry that admits all three as the approved code, and peers check each other's keys and counters there. Apple signs every attestation in both.

After:
> Apple signs every attestation in both panels; highlighted boxes are what a verifier trusts beyond Apple. On the left the developer signs every copy and runs the only verifier. On the right three developers sign the same code. Each signing produces a different code hash (plate E shows why), so the peers share one registry that records which hashes are the approved code; a device enrolls its attestation there, and a peer checks another peer's hash against it.

(If the registry does hold keys and counters, add a sentence in plate F saying so and keep "keys and counters" here; otherwise drop it.)

### "What iOS 27 adds" ¶1

Before:
> Starting with iOS 27 and macOS 27, an app can get something more like MRENCLAVE. Give it the entitlement `com.apple.developer.devicecheck.app-attest-opt-in` = `[CDhash]`, and the attestation carries the CDHash of the running executable inside the bytes Apple signs. The CDHash is a hash of the CodeDirectory, which is a list of hashes of every 16 KiB page of the executable. Because of that last step, we can recognize the same code no matter who signed it.

After:
> Starting with iOS 27 and macOS 27, an app can put a code measurement in the attestation. Give it the entitlement `com.apple.developer.devicecheck.app-attest-opt-in` = `[CDhash]`, and the attestation carries the CDHash of the running executable inside the bytes Apple signs. The CDHash is a hash of the CodeDirectory, which is mostly a list of hashes of every 16 KiB page of the executable. [§3 passage, paragraph 3, goes here.] Because the pages are hashed one at a time, a verifier can see exactly which pages two signers' builds disagree on; plate E shows that it is one page, and three fields of it.

### Plate C ¶1, first sentence

Before:
> The CodeDirectory is the blob inside the code signature that everything else hangs off.

After:
> The CodeDirectory is the blob inside the code signature that the signature itself is computed over.

### Plate F ¶1, who approves

Before:
> So a verifier doesn't need to trust any signer, and doesn't need a hand-curated list of CDHashes either. It keeps one approved build.

After:
> So a verifier doesn't need to trust any signer, and doesn't need a hand-curated list of CDHashes either. It keeps one approved build, fixed when the registry is deployed; moving to a new build is a decision the network makes, and no developer can make it alone.

### Plate F ¶2, the test sentence

Before:
> A verifier built on this registry passes forge tests against real evidence from an iPhone on iOS 27 and a Mac on macOS 27; the cross-team case is tested with a synthetic second team. No network nodes run on it yet.

After:
> Its forge tests run over twelve signings of the probe executable, the original and eleven re-signings: four are admitted, eight are rejected for ad hoc signing, dropped hardened runtime, an added `get-task-allow`, missing entitlements or a changed page, and a single flipped byte in page 0 is rejected as well. The attestation checks (Apple chain, nonce, counter) are a separate contract tested on the Mac captures and not yet joined to this registry. No attestation from a second Apple team has been captured, and no network nodes run on it yet.

(Counts from `test_resignedAcceptedOthersRejected`: ok = A, D, G, I; rejected = B, C, H, L, K, J, E, M; then D with byte 100 flipped. Adjust if the test file changes.)

### Plate G ¶1

Before:
> The same entitlement already does something on iOS 18.5, but the hash lands in the wrong place. It is a fourth top-level entry, `cdHash`, holding 20 bytes, outside `authData` and outside anything Apple signs. Anyone between the phone and the server can rewrite it.

After:
> The same entitlement already does something on iOS 18.5, but the hash lands outside anything Apple signs: a fourth top-level entry, `cdHash`, holding 20 bytes, next to `authData` rather than inside it. The app itself, or anyone between the phone and the server, can rewrite it without breaking a signature.

### Plate G table, row 2 "How we know"

Before:
> Apple's App Attest code in the dyld shared cache, disassembled

After:
> Apple's App Attest code in the dyld shared cache (18.5 build 22F76, 26.5 build 23F77), disassembled

### Footer

Before:
> one attestation from the same app on an iPhone XS running iOS 18.5, captured 2026-10-05 UTC.

After:
> one attestation from a TestFlight build of the same app on an iPhone XS running iOS 18.5, captured 2026-10-05 UTC; Apple re-signs TestFlight builds, and that build's 20-byte value has not been matched to its executable.

## 3. New passage: MRSIGNER and MRENCLAVE

Source for the SGX facts: Intel SGX Developer Guide, Linux 2.25 release PDF
(download.01.org/intel-sgx/sgx-linux/2.25/docs/Intel_SGX_Developer_Guide.pdf, fetched 2026-10-06),
the SIGSTRUCT field list and "Software Sealing Policies". Quoted phrases are from it.

Placement: paragraphs 1 and 2 replace "In SGX terms it's MRSIGNER." in Background ¶3 (see §2);
paragraph 3 replaces "something more like MRENCLAVE" in "What iOS 27 adds" ¶1.

> An SGX attestation carries two identities for an enclave, and a verifier chooses which to pin. MRENCLAVE is the measurement: a 256-bit hash of the code and initial data loaded into the enclave, "the expected order and position in which they are to be placed, and the security properties of those pages", computed by the CPU as the pages go in. MRSIGNER is a hash of the public key that signed the enclave file, recorded at initialization, so every enclave signed with the same key gets the same value. Intel's Developer Guide says why both exist: the hardware checks only the measurement when it loads an enclave, so "anyone can modify an enclave and sign it with his/her own key", and the verifier must check MRSIGNER before handing over secrets. Sealing offers the same pair. Data sealed to MRENCLAVE opens only for the identical build; data sealed to MRSIGNER opens for anything the author signs, which the guide recommends so the author can upgrade the enclave without resealing.
>
> The choice fixes what the developer can do and what they answer for. A verifier that pins MRSIGNER trusts a key. Whoever holds it can change the code at any time and still pass, so the key holder is the one vouching for whatever runs, and the key is what a thief or a subpoena goes after. A verifier that pins MRENCLAVE trusts a build. The developer who produced it cannot swap it, and is not vouching for it either, since anyone with the build can recompute the measurement. Moving to a new build means the verifier admits a new measurement, and that is the verifier's decision, not the developer's.
>
> App Attest before iOS 27 reports only the App ID, so the check it supports is a MRSIGNER check. With the opt-in on iOS 27 the attestation also carries the CDHash of the running executable, which plays the part of MRENCLAVE with one difference: the CDHash is a hash of the CodeDirectory, so it covers the executable's pages and the special slots (entitlements, Info.plist, requirements, resources) together, and a verifier that pins it pins all of those.

Self-check against the deslop list: no "it's not X, it's Y"; no hedges ("something like", "arguably");
no buzzwords; no em-dashes; no triads; the parallel "trusts a key / trusts a build" is each followed
by the concrete consequence it stands for; every quoted phrase is from the fetched guide; every claim
about the page's tests is from the test files read today.
