---
status: accepted
date: 2026-11-02
builds-on: 0001
---

# Chats live in the browser and sync encrypted under the wallet

## Context

Users move between devices, and the operator should not hold readable chats.

## Decision

Sessions are stored in the browser's IndexedDB. Cross-device sync uploads each
session encrypted under a key held with the wallet, and an on-chain anchor records
the latest head per wallet (`chat-sync.mjs`). Device links and recovery methods
hand the wallet and that key to a new browser.

## Consequences

Losing every device and recovery method loses the chats. The operator cannot read
traces, so debugging a failure needs the user to share one from their browser.
