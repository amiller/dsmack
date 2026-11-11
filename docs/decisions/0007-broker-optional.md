---
status: proposed
date: 2026-11-11
builds-on: 0002, 0006
---

# The private agent works without the broker

## Context

Today the page cannot run a stay without the relay-broker. It is in the path for five things:

1. **Finding Macs.** The page asks `GET /nodes`. Guests register there every 25 s, and the broker checks each registration against the chain.
2. **Grants.** A guest only serves a browser that shows an Ed25519 grant from `BROKER_KEY`, which is pinned in the measured compose (`peer/engine.go:65-91`). The broker issues it from `POST /agent/open` once the wallet has credit.
3. **Credit.** Deposits go on-chain into UsageEscrow. Metering is an off-chain ledger in the broker: guest receipts debit it, and the broker signs the weekly `Claim` that operators submit. Starter credit is broker-ledger only.
4. **Model calls.** The broker holds the NEAR AI key and forwards the browser's E2EE ciphertext.
5. **Ownership.** MacLink records live at the broker's `/fleet/ownership`.

On 2026-11-11 the broker's chain reads used up the Cloudflare Worker's daily quota. Registrations then failed and the demo went down while every Mac was healthy.

Much of the broker-free path already exists:
- The page verifies a Mac's attestation itself (`sandbox.verifyNode`).
- It can fetch that attestation from the guest over libp2p (`direct-attestation.mjs`).
- It can read the Mac list from the `TunnelIndex` contract (`chain-directory.mjs`), and uses that as a fallback when `/nodes` fails.

The fallback still calls `/agent/open`, because nothing but the broker can make a grant.

## Decision

The page runs a stay with no broker. The broker stays as an optional convenience: starter credit, a hosted NEAR AI key, shared Apps links and workspace sync. Three changes get there, and each one ships on its own.

### 1. Mac list on chain (page only, no guest rebuild)

- Replace the single-owner `TunnelIndex` with a `MacDirectory`. Any operator registered as a class in UsageEscrow publishes its own entry:
  - its tunnel entries (url, relayPeer, guestPeer, expiresAt);
  - its MacLinks (kid → operator).

  The page reads only operators that UsageEscrow knows. Spam therefore costs a registered operator gas, and costs the page nothing.
- The Mac publishes only when its entry set changes. That already happens at most once a minute (`mac-pool.py:381`).
- The page:
  - reads the directory through Helios;
  - fetches each guest's attestation over libp2p;
  - runs `verifyNode` as it does now;
  - finds out whether a Mac is busy by dialing it. The guest refuses when it is full.
- `/nodes`, `/fleet/ownership` and `/network` become unused by the page.

### 2. Grants and credit on chain (guest rebuild, escrow change)

- **Channels.** The user's deposit is opened as a channel to one operator: `open(operator, amount)` in a new escrow version. It can be withdrawn after the existing 14-day exit delay.
- **Payment and admission.**
  - During a stay the page's wallet signs a cumulative EIP-712 voucher `{user, operator, runId, amount}` every 60 s. The page holds its own key, so this needs no prompts.
  - The guest admits the browser if a fresh voucher for its own runId comes with a channel balance that covers it, and stops when vouchers stop.
  - The guest's unused EIP-712 verifier (`payments/guest/payments.go:198-225`) is the starting point.
- **Settlement.** The operator settles with the newest voucher: `claim(user, operator, amount, sig)` pays from the channel. The broker signs no grants, NodeBindings or Claims.
- **Guest changes.** The compose drops `BROKER_KEY` and the broker URL. The guest reads channel balances from the chain. An unverified read only risks the operator's own payment, so the guest can use the operator's chosen RPC.
- **Starter credit.** Without a broker there is no free starter credit. An operator who wants it funds the channels of new wallets directly, which is open to Sybil abuse. The hosted broker can keep offering it.

### 3. NEAR AI key in the browser

- The user pastes their own NEAR AI key. The page calls `cloud-api.near.ai` directly; its CORS allows this origin (checked 2026-11-11).
- The page runs the same model verification as today (`evidence.mjs`: TDX quotes, GPU evidence, model key) and the same E2EE.
- The existing own-key path (`model-provider.mjs`) skips that verification. The NEAR path must not.
- NEAR AI is paid on its own dashboard. NEAR Intents cannot top it up. #166 funds the Mac side only.

## Consequences

- **Order.** Change 1 is the cheapest and removes the broker's heaviest chain load. Change 3 needs no Mac change. Change 2 needs a new escrow, a guest image and a page change together.
- **What the page loses.** Without the broker there is no busy/free view before dialing, no free starter credit, and no shared Apps links.
- **Metering.** It moves from broker-checked guest receipts to user-signed vouchers. A user can underpay by up to one voucher interval, and the guest stops there.
- **Channels.** Money in a channel is tied to one operator. Moving it to another Mac takes a new channel or waiting out the exit delay.
