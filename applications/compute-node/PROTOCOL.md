# Attested Pi tools over MCP

The browser runs Pi's agent loop and sends model requests encrypted to the NEAR
model TEE. It exposes exactly Pi's `bash`, `read`, `write`, and `edit` tools.
The guest runs Pi 1.4.0 tool factories using local filesystem/process operations.

## Establish the connection

The browser selects a node from `/nodes` and verifies its App Attest proof,
measured compose and image, and bound libp2p PeerId and receipt key using the
included policy. `/sandbox/nodes/PEER/attestation` supplies the node evidence.
It then signs `/agent/open` with its wallet, naming the conversation, guest,
and browser's Noise PeerId. The broker reserves guest seconds from that wallet's
existing chat-credit account and issues its existing signed seconds grant.

The browser dials the attested guest through the published Mac WebSocket circuit
relay and checks the connection's remote PeerId. It opens
`/dsmack/agent-mcp/1.0.0` and sends the existing admission control object
`{job_id: grant.grant_id, grant}` as a four-byte big-endian length and UTF-8 JSON.
The guest checks the broker signature, target, Noise owner, expiry and exclusive
claim, and returns a similarly framed `{status:"ready"}` or refusal. This
admission exchange establishes the authenticated transport.

## MCP messages

After ready, the stream carries exclusively newline-delimited UTF-8 JSON-RPC,
with no length prefixes. Both endpoints use the official TypeScript MCP SDK's
split packages 2.4.0, pinned to protocol 2026-07-28. Its discovery, per-request
version/capabilities metadata, progress notifications and cancellation apply.
The Go daemon only bridges these bytes to the measured Node Unix socket.

`tools/list` returns the factory schemas and descriptions. `tools/call` executes
those tools; bash progress uses `notifications/progress`. Errors appear in the
MCP result and Pi conversation. File paths and symlinks are workspace confined;
commands run as uid 1000 in a read-only container with a writable `/workspace`.
The `agent-sandbox-v1` base-runtime profile keeps the coordinator's attestation
socket under `/root` and restricts bootstrap capabilities. The measured firewall
and CONNECT proxy enforce outbound network policy.

`resources/read` exposes `dsmack://environment` for actual runtime facts and
`dsmack://workspace/patch` for a binary Git diff. Importing a repository uses the
same write/bash tools and commits a baseline before the first model tool call.

## Meter and release

Guest time starts when the signed grant is admitted. The guest's attested
receipt key signs monotonic checkpoints to `/agent/receipt`, charging seconds
from the same account as model tokens. Original receipts remain in guest
artifacts. Browser-signed `/agent/status` reads its own lease and usage;
`/agent/end` requests release. Five minutes without a tool call also releases
it. On release the guest retires, so another conversation receives a fresh
workspace. A missing final receipt retains its unresolved credit reservation
until the original signed evidence is recovered.
