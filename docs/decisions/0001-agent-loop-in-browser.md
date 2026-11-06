---
status: accepted
date: 2026-11-02
---

# The agent loop runs in the browser; the guest only runs tools

## Context

The private agent needs a model, a conversation and a place to run commands. The
Mac guest is attested and disposable; the browser is the user's own device.

## Decision

The Pi agent loop, the conversation and the model calls run in the page. The guest
exposes Pi's `bash`, `read`, `write` and `edit` tools over MCP on an attested libp2p
stream (`applications/compute-node`). A conversation claims a guest on its first
tool call and releases it after five idle minutes.

## Consequences

The operator never holds the conversation, and a guest can be replaced mid-chat
while its workspace is restored from an encrypted save. The page carries most of
the logic, so phone backgrounding and dropped requests show up as agent failures.
