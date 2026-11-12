---
status: proposed
date: 2026-11-12
builds-on: 0007
---

# A Mac lists itself; App Attest decides whether the listing counts

## Context

Change 1 of 0007 moves the Mac list on chain. The page already has an on-chain fallback, `TunnelIndex`, and it shows what the naive version costs.

Each Mac writes one signed list with a row per live guest:

```
{ url: "wss://aaron-pulled-gas-colin.trycloudflare.com/",  // quick tunnel to the Mac's relay
  relayPeer: "12D3KooWPXeq…",                               // the relay's libp2p id, from relay.key
  guestPeer: "12D3KooWD9CW…",                               // one guest, reached through the relay
  expiresAt: <at most 1 h ahead> }
```

On 2026-11-12 the production list held 7 rows: 4 serving guests and their overlapping replacements.

The writes are frequent even though the content barely changes. The production and staging pools sent 329 publications in the 24 h before 2026-11-12, about 14 an hour, at ~160k gas and 1.3 KB each. Four things cause them:
- guests rotate about hourly per slot, and each new guest adds a row;
- the one-hour expiry forces a refresh even when nothing changed;
- the quick-tunnel hostname is random and changes on every pool restart;
- pool events republish.

Only the relay's peer id never changes.

`TunnelIndex` also has a single owner, and the page pins that one address (the "publisher") in its config. So only one Mac can be listed.

The directory does not have to be trusted for integrity. The page already checks the Mac's App Attest key, the guest's measurement and its UsageEscrow class before it uses a guest. A false entry fails at dial time. The one thing the directory must provide is completeness: nobody should be able to hide a Mac.

## Decision

A Mac lists itself. There is no pinned publisher. One key per Mac (or per operator) signs its own entry, and the key can live anywhere: it is outside the TCB, and the page trusts nothing it says.

- **On chain: a roster that rarely changes.** A Mac writes its relay peer id and a dial hint once, and again only when the hint changes. There is no expiry on chain. Entries are stored per (sender, Mac id), so one key can list several Macs without overwriting them.
- **Liveness and guests: over p2p.** The page dials each listed relay, asks it for its current guests, and fetches each guest's attestation over libp2p (`direct-attestation.mjs`). A Mac that does not answer is offline. The relay has no guest-listing call today; the Mac pool already knows its guests (`directory.json`) and would serve them over a small libp2p protocol on the relay.
- **App Attest is the gate, checked by the page.** An entry counts only if the Mac behind it passes App Attest and its guest matches a registered class. Anyone can write an entry; junk costs its writer gas and the page drops it when verification fails.
- **A stable dial hint.** The hint only stops churning if the Mac has a stable address. Public libp2p circuit relays give one (`/dns4/<relay>/…/p2p-circuit/p2p/<relayPeer>`). Relays only carry bytes, so they can fail to connect but cannot forge a Mac. One can run on portaroute.
- **The page reads the roster through Helios**, like other chain reads (0006).

## Consequences

- Chain writes drop from about 14 an hour per Mac to one per address change, because guests leave the chain. Cost then matters little on Base mainnet.
- Several Macs and operators can be listed. `classesByPublisher` and the pinned `chainDirectory.publisher` go away.
- The page cannot see whether a Mac is busy before dialing it; the guest refuses when full (as in 0007).
- Reachability depends on public relays or the Mac's own address. A relay can deny service but not forge.
- Spam is bounded by gas and by how many entries the page is willing to dial. The page should cap that.

## Open questions

1. Is a public libp2p relay (or the DHT) acceptable for reachability?
2. Should writing an entry also be gated on chain, e.g. only by operators with a registered class, or only with an App Attest proof (the verifier exists, but enrolling costs ~14M gas)? The page checks App Attest anyway, so this only keeps the list clean.
3. Does this need to run on Base mainnet soon?
