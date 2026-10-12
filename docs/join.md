# Join the network

You need an Apple silicon Mac on macOS 27 with Full Security and System
Integrity Protection enabled. You do not need Xcode, an Apple Developer
account, a wallet or gas.

1. Download `Dsmack Node` from the
   [latest release](https://github.com/amiller/dsmack/releases) and extract the ZIP.
2. Open `Dsmack Node` and accept the normal macOS prompt. Do not change
   Gatekeeper settings to make it open. The app enrolls with App Attest, finds a
   peer and fetches the shared network key. It says **You’re in.** when it holds
   the current key epoch.
3. Choose **Share in public node directory…** and find your node on the
   [node dashboard](https://amiller.github.io/dsmack/nodes/).

Closing the window leaves the node running; **Quit peer** stops it. Reopening
restores the same account. Keep Application Support and Keychain data when you
replace the app with a newer release.

## Troubleshooting

**It never says You’re in.** The app shows which step is waiting. Joining needs
a live seed or another node that holds the current key, so a seed outage blocks
new nodes until it recovers. Choose **Share diagnostic report**, read the file,
and attach it to an [issue](https://github.com/amiller/dsmack/issues). The report
redacts known secrets and RPC credentials but still contains public account
identifiers. Do not delete saved identity or Keychain entries to retry; that
creates a new account instead of fixing the old one.

**macOS refuses to open it.** Check that you downloaded the ZIP from the release
page and that its SHA-256 matches `SHA256SUMS`, then open it again and accept
the prompt. Do not disable Gatekeeper, SIP or Full Security.

**My node is not on the dashboard.** Directory sharing starts off. Turn it on
with **Share in public node directory…**. Quitting removes the entry; an
interrupted entry expires on its own.

**The receipt has no artwork.** Each node gets a participation receipt on Base
Sepolia. It has no monetary value and does not prove a unique person or Mac.
Only the first two receipts have Fold artwork; the app shows
**ARTWORK NOT LOADED** for the rest.

[Node details](node-details.md) covers updates and checking a release before
you open it. [What the network is and is not](../README.md#what-the-network-is-and-is-not)
explains what admission proves and what the operators can still do.
