# Earn the independent-builder NFT

**Preview status:** RC3 is the current Mac admission baseline. Its exact signed
release reconnected on Base Sepolia and restored the existing participant receipt
after restart. The independent-team upgrade is implemented, but a real second-team
acceptance run remains pending. Update the original app to RC3 before this flow.

You need a paid Apple Developer team different from the release publisher's,
a supported Mac, the pinned Xcode toolchain, and permission to sign for that team.
Keep Apple passwords, certificate private keys, and API keys in your own Xcode,
Keychain, or protected GitHub environment. The app never asks you to enter them.

## 1. Save your participant invitation

Open the original app and wait for your participant NFT to be confirmed. Choose
**Become an independent builder… → Save invitation…**. Keep the original app installed and
its Keychain identity intact until the handoff has confirmed.

The invitation contains public account/network information. It does not contain
your private key or authorize anyone to take control of the account.

## 2. Build and sign your own copy

Fork this repository and check out tag `v0.1.0-rc.3` (app build source
`6a3cca34f53a3cf8fe241aca4a8d8b3e0c76ef81`; see [release verification](v0.1.0-rc.3.json)). Keep executable source
unchanged so the network can recognize the code. Use the exact `bundleId` saved in your invitation and create a matching explicit
App ID and provisioning profile under your team. Set `APPLE_BUNDLE_ID` to that
value. The identifier includes your personal NFT account address; a generic
copy signed for somebody else cannot earn your builder badge.

Follow the [Mac signing and CI instructions](README.md#fork-and-build-with-github-resources).
The public Mac policy uses **Developer ID** signing (validation category 6).
An Apple Development signature is not an interchangeable substitute. The local
hardware test uses category 3 on its separate Anvil network only.

The unsigned build command is:

```sh
python3 scripts/release/build_mac.py --gui --version 0.1.0 --build-number 4 \
  --out build/my-unsigned \
  --bundle-id "$APPLE_BUNDLE_ID"
```

RC3 uses version `0.1.0` and build `4`. The current generic CI workflow defaults
to build `3`, so set the exact values above for full-bundle comparison. RC3
reproducibility was checked across two clean paths on one Mac, not independently
on GitHub. Compare
the unsigned executable with the release evidence. Your bundle identifier and
signing identity deliberately change bundle/signature metadata; the executable
payload must still match. Export/sign and notarize using the documented local
Xcode route or protected CI workflow. The certificate-based CI signing workflow
has not yet been independently demonstrated with a friend's credentials.

Signing requires actual certificates/profiles and authorization, not just a Team
ID string. If a capability or profile is unavailable, resolve that in your Apple
Developer account; do not turn off attestation or modify the app to bypass it.

## 3. Register the signed copy

After signing/notarization, register that exact app with the NFT-enabled relay:

```sh
export TESTNET_RELAY="https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft"
python3 scripts/release/register_mac_build.py \
  --app /path/to/AttestNode.app --relay "$TESTNET_RELAY"
```

The helper verifies the local code signature and sends only the CodeDirectory,
first code page, and sealed entitlements. It sends no provisioning profile or
private key. The sponsor pays testnet gas, and the contract checks that the code
matches the admitted baseline. Registration alone does not prove a valid Apple
signing account; opening the app and producing live App Attest evidence does.
The original root relay endpoint serves the older shared-key release. Use the
`/nft` endpoint above for this upgrade.

## 4. Link the independently signed copy

Open your signed app and let it connect. Choose **Become an independent builder… → Import
upgrade file…**, selecting the invitation from the original app. Save the request
it creates. The app verifies that its current signing team is admitted, differs
from the publisher, and signed the account-specific bundle identifier before
creating this request.

Return to the original app, choose **Import upgrade file…**, and select that
request. It checks the on-chain assertion, admitted code/team, account ownership,
request expiry, and new-key signature. Compare the new-key fingerprint with the
one shown by your independently signed copy, then choose **Approve handoff**.
Only approve the request you created yourself.

Keep both copies open during this step. A request expires in about 55 minutes;
a later peer exchange can supersede its assertion. If validation asks for a fresh
request, import the invitation in the new copy again and save a new request.
A rejected/expired request does not transfer control.

## 5. Confirm the builder NFT

After handoff confirmation, return to the independently signed app. It detects
that its personal key now controls the original account and automatically claims
the builder NFT, usually on its next retry (up to about one minute). Both the
original participant NFT and the builder NFT remain at the same account address.
The original app no longer controls that account.

The independently signed copy may already have created a separate participant
receipt when first opened. Linking the invitation selects your original account
for this upgrade; it does not merge or transfer unrelated receipts.

The badge proves that an independent team signed an admitted build for your
particular NFT account. It does not prove which human held the Apple credentials;
a team can delegate signing through a colleague or CI. It is a historical research
receipt, not a unique-human or unique-Mac credential. Level 2 permits one claim per verified independent developer team and
one upgrade per participant NFT. A team can represent several people. There is
no sponsor recovery backdoor: losing the controlling Keychain key before a
successful handoff loses control of the account.

If the builder claim is pending, keep the new app open and inspect **Show
technical details**. Network participation continues while the claim retries.
