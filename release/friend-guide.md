# Try AttestNode

Download [AttestNode for Mac](https://github.com/amiller/apple-attest-p2p/releases/download/v0.1.0-rc.3/AttestNode-macOS27-arm64-v0.1.0-rc.3.zip).
The [release page](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3)
and source are public; no GitHub account is needed.

You need **Apple silicon, macOS 27, Full Security, and System Integrity Protection
(SIP) enabled**. SIP alone does not establish Full Security. Joining does not need
Xcode, an Apple Developer account, a wallet, or gas.

1. Download and extract the ZIP. If you have an older copy, choose **Quit peer**
   in its Testnet menu, then replace the app with this release. Keep your saved
   app data and Keychain entries; the update should reuse your account.
2. Open **Node.app** and complete the normal macOS confirmation if it appears.
   Do not change Gatekeeper settings to make it open.
3. Let the app work. It verifies the app, finds a peer, checks the shared key,
   and claims or restores your participant receipt automatically. **You’re in.**
   means your peer is connected; the separate **Participant / #… confirmed**
   line means your NFT receipt is ready.
4. Choose **View your NFT ↗** to inspect the receipt. Closing the window keeps
   the connected peer running; **Quit peer** stops it. Reopening should restore
   the same account and receipt rather than create another claim.

A slow NFT claim can remain pending while your peer is connected. The app tells
you which step is still waiting. If a step fails or stays stuck, choose
**Save diagnostic report…**, review the file, and send it to your coordinator.
The report keeps useful event details while redacting known sensitive fields and
configured RPC credentials. It can still contain public account identifiers.
Do not delete saved identity or Keychain entries to retry.

## Your receipt and Fold

The research receipt has no monetary value. The main artwork collection currently
contains Fold sculptures for the two existing participants, preserving their
original token numbers and owners. The app displays the matching image for those
two receipts. New participants receive a receipt first; automatic artwork for
later receipts is not yet available. The app says **ARTWORK NOT LOADED** when no
bundled image matches; it does not show someone else’s Fold.

[View the main Fold collection](https://sepolia.basescan.org/token/0xc3da5f4d5013dD6fB4a16EF3ace0C0F9e1F8C1Ed).
The original receipt contract still handles enrollment and account policy.

## The optional builder step

Choose **Become an independent builder…** and follow the
[builder guide](builder-guide.md). This requires your own paid Apple Developer
team, different from the publisher, and a signed copy of the admitted code. Keep
the original app and its Keychain until the handoff is confirmed. The production
invitation export/check functions have been tested, but the complete independent
second-team handoff and builder NFT still await an acceptance run.

Your personal NFT key stays in your Mac’s Keychain, separate from the shared
network key. There is no sponsor recovery for a lost personal key. These receipts
do not prove a permanently unique physical Mac or human owner.

## What was checked

The exact signed/notarized RC3 ZIP reconnected on the live Base Sepolia network,
verified the current shared key, and restored the operator’s existing NFT after
restart. Both original NFT owners stayed unchanged and no new receipt was minted
by that restart. The network now admits RC3; older RC2 copies must be updated.
Maintenance and concurrent requests caused retryable errors during testing;
joining is automatic, not guaranteed to be instant or retry-free.

The observed run used the signing Mac, whose Gatekeeper assessment is disabled.
A clean friend first-open capture and the independent-team builder journey remain
unverified. See [release verification](v0.1.0-rc.3.json) for exact hashes and checks.
