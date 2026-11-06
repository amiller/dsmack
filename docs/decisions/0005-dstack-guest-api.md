---
status: accepted
date: 2026-11-02
---

# The Mac guest offers dstack's guest API

## Context

Apps written for dstack CVMs should run on a Mac guest without a second key API.

## Decision

The guest serves dstack's guest API v1 (`/v1/GetKey`, `/v1/Attest`, `/v1/Info`,
`/v1/Version`) on `/var/run/dstack.sock` (`dstack-compat/`). Keys derive from a
grant minted by a dstack app, using dstack's v1 KDF. Where dstack has already
decided something, Dsmack follows it unless there is a Mac-specific reason.

## Consequences

One compose file runs on both. A worker key verifies to the dstack KMS root
through its grant and never verifies as a coordinator key.
