# Main collection: Fold

The main collection keeps the name **Attest Testnet Research Badges** (ATTEST).
There is no version label. `ResearchCollection` adds the porcelain-and-vermilion
Fold artwork to the existing research receipts.

Each token has exactly its original receipt number and owner. The original
`ResearchBadges` contract remains the attestation, consent and replay-protection
engine; its address remains pinned in existing personal accounts. Reissuing art
does not rotate keys, replace accounts, or require another enrollment. Historical
receipts remain visible on chain and are linked from the new metadata.

Artwork is derived from the source receipt's chain, contract and token number,
so moving the presentation to a new collection does not change the sculpture.
The publisher registers a PNG URI, its SHA-256 and the renderer source SHA-256.
Any caller can then issue the token to its original owner; the caller cannot
redirect it. Both collections are non-transferable. Level 2 retains its existing
independent-team and parent-receipt checks in the original receipt engine.

Image URLs use immutable Git commit paths. The artwork registration can be
updated by the collection owner until explicitly frozen. Freezing makes the URI
and hashes immutable, not the availability of an external image host. Images
are not stored on chain. Tokens cannot be issued before their art is registered.

## Live collection

[Main collection on Base Sepolia](https://sepolia.basescan.org/token/0xc3da5f4d5013dD6fB4a16EF3ace0C0F9e1F8C1Ed)

Tokens 1 and 2 have been issued to their original owners. Gabe's
[token 2](https://sepolia.basescan.org/token/0xc3da5f4d5013dD6fB4a16EF3ace0C0F9e1F8C1Ed?a=2)
contains the image below in its on-chain metadata. He does not need to claim again.
See the [deployment and verification record](main-collection-deployment.json).
Artwork is not frozen, allowing refinement without another contract replacement.

![Gabe's Fold, generated from receipt 2](../artwork/fold/gabe-token-2.png)

## Publication procedure

1. Run `forge test --root contracts` and render/inspect artwork from public receipt
   identities. Commit images and renderer manifests; use full-commit image URLs.
2. Prepare an artwork array with `tokenId`, `manifest` (repository-relative) and
   `image` (public HTTPS URL). Run `scripts/release/publish_collection.py` with
   `--network`, `--artworks`, and `--out`. This is read-only by default and verifies
   live receipt policy, owners, public image bytes and renderer identity.
3. Pause sponsor writes on the relay and drain pending transactions. Broadcast
   with `--broadcast --relay <NFT relay URL>` and the dedicated testnet publisher
   key supplied through `PRIVATE_KEY`. Preserve the transaction journal if any
   step fails; reconcile its hashes before retrying. Never run two publishers.
4. Verify the resulting metadata, owners and explorer links, then restore relay
   sponsor writes. Save the public deployment record; the private journal records
   exact signed transactions for recovery.
5. Promote the new collection links in the handoff. Keep the old receipt and
   account-factory addresses as claim-policy configuration.

## Integration status

The main collection is deployed and both existing tokens have artwork; the
[verification record](main-collection-deployment.json) records the checked block. RC3 displays the matching bundled image and opens the main artwork collection
for original receipts 1 and 2. Other receipts still open their original receipt
page. The original receipt policy and factory remain unchanged. The RC3 measured
code is now the admitted Mac baseline; RC2 users need to update.

Future claimants also need artwork rendered, published and issued. The helper's
`--collection` mode supports additional receipts. A continuously operated render
worker and app “Preparing your artwork” state are not yet implemented; do not
promise instant artwork delivery for future claims. Original network joining
and receipt claiming continue to work independently of artwork publication.
