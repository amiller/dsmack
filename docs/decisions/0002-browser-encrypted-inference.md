---
status: accepted
date: 2026-11-02
builds-on: 0001
---

# Model calls are encrypted in the browser to a NEAR TEE model

## Context

The broker pays for inference and meters credit, but should not read prompts or
replies.

## Decision

The page encrypts each request to the NEAR model TEE and decrypts the reply. The
broker forwards ciphertext and meters it (`/inference/quote` reports
`mode: broker-e2ee`, `provider: near`).

## Consequences

Users need no API key. Other providers can be added as an option the user turns
on, but the page has to say that such a provider sees the conversation.
