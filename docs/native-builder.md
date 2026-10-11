# Independently signed participant handoff

The native app supports a handoff from a publisher-signed participant to a copy
signed by an independent Apple Developer team. Real second-team acceptance is
still required. Use the selected release's exact source, toolchain, network and
admission policy; the current source tree does not supply a live invitation or
historical relay endpoint as a supported service.

1. In the original app, wait for the participant receipt and choose
   **Become an independent builder… → Save invitation…**. Keep its installation
   and Keychain identity until handoff confirmation. The invitation contains
   public account/network information and no private key.
2. Build and sign the exact admitted executable under a different authorized
   Apple Developer team, using the invitation's account-specific bundle ID.
   Follow [Mac builds and signing](native-build.md). Compare executable hashes;
   bundle/signature metadata deliberately differs.
3. Register the exact signed copy with the selected NFT-enabled relay using
   `scripts/release/register_mac_build.py --app /path/to/Node.app --relay <URL>`.
   The helper sends the CodeDirectory, first code page and sealed entitlements;
   registration still needs live App Attest evidence to prove signing identity.
4. Open the signed copy, import the invitation and save its upgrade request.
   In the original app, import that request, compare the new-key fingerprint,
   and approve the handoff you created. Keep both copies open. Expired or
   superseded requests require a fresh request; rejection does not transfer control.
5. Confirm that the independently signed copy controls the original account and
   receives the builder receipt. The original app then loses control of that account.

The handoff preserves the original participant account; it does not merge unrelated
receipts. A team can represent several people or delegate signing. The badge is
a research receipt for an independently signed admitted build, rather than a
unique-human or unique-Mac credential. Losing the controlling Keychain key before
successful handoff loses account control; there is no sponsor recovery backdoor.

Inspect **Show technical details** for pending claims. Qualify this path separately
from the coupon friend journey described in [release acceptance](release.md).
