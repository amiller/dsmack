---
status: accepted
date: 2026-11-02
builds-on: 0003
---

# Failure reports never carry conversation content

## Context

Testers hit failures we cannot see, and the broker only logs request outcomes.

## Decision

Broker logs and any page error report use a closed set of fields: event, time,
reference, error code, HTTP status, duration and sizes. No message text, model
output, tool output or wallet. The reference shown with a page error matches the
broker's log line. A trace leaves the browser only when the user shares it.

## Consequences

Most failures can be matched to a log line by reference. Failures that never reach
the broker leave no record unless the user exports their trace.
