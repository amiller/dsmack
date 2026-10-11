# Open the app and receive a participant NFT

Observed on 7 October 2026 using the notarized `adda809` Mac candidate on Base
Sepolia. This is a real application run with real Apple App Attest. The seed and
participant ran as separate processes on the same Mac; a friend's second Mac
with Gatekeeper enabled is still an acceptance requirement.

![The running app after its automatic claim](../data/nft-base-live-20261007/participant-claimed.png)

This is the app's own AppKit status-image capture, not a mockup. It excludes
window chrome and the desktop. The participant did not press any app buttons,
create a wallet, supply gas, enter a developer account, or configure a network.
The only launch argument chose where to save this screenshot.

## What happened

1. The agent built source `adda809826358d2466b74a2f206c5921f75443a1` in a clean
   Mac checkout. Its unsigned app bytes matched independently built GitHub CI
   artifacts. The app was Developer ID signed, notarized, and stapler-validated;
   the executable payload matched the unsigned build after accounting for the
   signature's defined binary fields. See the `*-nft-compatibility.json` reports.
2. The agent admitted that exact signed CodeDirectory and activated only the
   separate NFT network. The original shared-key network remains available.
   A separate user-session launch agent keeps the NFT seed running on the Mac.
3. The agent opened the app using LaunchServices:

   ```sh
   open -n --stdout build/participant.jsonl --stderr build/participant.err \
     build/developer-id/notarized/Node.app --args \
     --capture-status "$PWD/build/participant-claimed.png"
   ```

4. The log recorded `connecting`, `attesting`, `enrolled`, `getting key`,
   `key verified`, `participating`, `badge preparing`, `badge claiming`, and
   `badge claimed`. From launch to confirmed claim took approximately **48 seconds**.
5. The agent independently read the contract and receipt. NFT #1 belongs to
   `0xAc089f563703F8811073C758d6E1E8aAD89C7cCD`, a participant-controlled account,
   rather than sponsor `0xe45C80da8A992447E9Da6d2d82Fe4b6Fa2d48C61`.
   The mint receipt succeeded and used 274,082 gas.

[Verified mint transaction](https://sepolia.basescan.org/tx/0x111c7b5e723dc290df0694c6bcc34c6cf4f1c8b04b321fee52391a08c4b56037).
The [event log](../data/nft-base-live-20261007/participant.jsonl) and
[independent ownership check](../data/nft-base-live-20261007/claim-verification.json)
contain the exact values. The app also verified a shared-key exchange receipt,
transaction `0x09f15495f6705b55879e7bc4a3a671b73dba59abdfe96ad2443df3b6e5f8ceff`.

## Reopening the release ZIP

The agent stopped only the participant, extracted the packaged ZIP with `ditto`,
verified its signature, and opened the extracted app. It restored NFT #1 at the
same account without submitting a mint. An independent read still returned
`nextId() == 2`. See the [restart log](../data/nft-base-live-20261007/participant-restart.jsonl)
and the restart section of the ownership-check JSON. Both seeds stayed running.

## Limits and remaining acceptance

The signing Mac has Gatekeeper disabled; notarization and ticket checks are
verified, but do not establish the experience on a clean friend's Mac. No
independent developer team has completed Level 2 yet. The Developer upgrade
button and handoff implementation are present; the [builder guide](builder-guide.md)
remains a preview until that real journey is verified. The original
[isolated-chain transcript](agent-transcript-nft.md) supplies earlier development
and rejection-test evidence, not a substitute for these acceptance tests.

The relay briefly returned HTTP 500 during its compatibility deployment, then
both endpoints passed verification. This happened before this participant run.
No first-run application failure was observed in the recorded claim journey.


## Post-upload readiness check, 7 October

After uploading iPhone build 5 (source `42a0beb`), the agent checked the existing
network without submitting transactions. The Mac seed launch agent remained
running and emitted recent `network reachable` events. At block 47821039, the
network was unpaused, Mac admission enabled, and iPhone admission disabled with
an empty baseline. Both `/nft/info` and `/ios/info` returned HTTP 200. The iPhone
registry's read-only `measure` call accepted the signed local build-5 export;
this does not prove the installed TestFlight executable or Apple attestation.
See [the exact snapshot](../data/ios-code-evidence-20261007/live-readiness.json).

The friend receipt was rechecked using:

```sh
python3 scripts/release/verify_badge_receipt.py \
  --account 0x6e250b3f230bD1912b9cFf13a8FD6209aFE5480b --token 2 \
  --mint-tx 0x07129281c2b87b9e38ba5ece13a30025a4b4b7619373bdbe3096eba086453379
```

The output matched `friend-level1-receipt.json`: verified mint/ownership, token 2
at the friend's account, and `nextId` 3. This does not prove a friend restart or
a second-team upgrade. Those captures and the actual iPhone run remain pending.
