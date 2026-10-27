# Compute jobs over libp2p

Protocol `/dsmack/job/1` uses a Noise-authenticated libp2p stream through a circuit
relay. Every message is a four-byte unsigned big-endian byte length followed by
UTF-8 JSON. Control frames are at most 4096 bytes; bundle/result frames at most
48 MiB. JSON used for hashes or signatures has recursively sorted keys, no
whitespace, literal UTF-8, and integer numbers. Hex is lowercase without `0x`.

## Discover and verify before releasing inputs

`GET /nodes` on the broker lists compute registrations. For compatibility with
relay grants, their address fields are `relay_peer` and `relay_maddr`; `kind` is
`compute`. A node returns the same registration JSON on `/dsmack/attest/1`
(unframed JSON, EOF terminated). Fields: `kind`, `relay_peer`, `relay_maddr`,
`secret_key` (P-256 x||y, 64-byte hex), `receipt_key` (Ed25519, 32-byte hex),
`attestation` (hex VersionedAttestation), `manifest_sha256`, `os_image_hash`,
`cdhash`. Clients verify the Apple assertion, enrolled key, approved build,
canary burns, expected compose/image/model, caller `node`, and report_data:

`SHA256(UTF8("dsmack-compute-node/1") || PeerId_multihash_bytes || secret_key_bytes || receipt_key_bytes) || zero[32]`.

Broker discovery adds verification metadata in `attestation` and keeps the raw
assertion hex in `proof`. The node stream uses `attestation` for that raw hex.

The node creates all three keys at boot. Never accept the broker's verification
label as a substitute for client verification.

## Signed grant request

`POST /grant` takes `{client_peer, relay_peer, unit, amount, nonce, sig}`.
`unit` is `seconds` for compute, `bytes` for a relay (default `bytes`). `nonce`
is 16 random bytes in hex. `sig` is the client's libp2p Ed25519 signature over
canonical `{amount,client_peer,nonce,relay_peer,unit}`. The inline Ed25519 key in
the client PeerId authenticates it. A reused nonce is refused. Byte clients may
use `bytes` in place of `amount`, but sign the normalized `amount` object.

A grant is canonical `{client_peer,expires_at,grant_id,relay_peer,seconds,unit,v,sig}`
for compute; a relay has `bytes` in place of `seconds`. `v=1`; `grant_id` is
16-byte hex; `sig` signs the object without `sig` with the pinned broker
Ed25519 key. The budget and expiry apply across jobs using that grant.

## Job exchange

1. Client sends control `{job_id,grant}`. `job_id` is 16 random bytes in hex.
   Node verifies broker signature, unit, authenticated client, target node,
   expiry, remaining seconds, replay, and availability. It reserves the job ID
   for this boot even if subsequent upload/decryption/execution fails.
2. Node sends `{status:"ready"}` or `{status:"refused",error:CODE}` and closes.
   Codes: `grant`, `replay`, `busy`, `bundle`, `execution`, `attestation`.
   The client sends no bundle before `ready`.
3. Client sends one frame `{epk,iv,ct}` in `dstack-compat/secret_box.py` format:
   P-256 ephemeral-static ECDH; epk is x||y hex; HKDF-SHA256 with zero salt and
   info `UTF8("dsmack.secret-release/1") || epk || recipient || UTF8(job_id)`;
   AES-256-GCM, 12-byte IV, ciphertext followed by 16-byte tag, no AAD.
   Plaintext is canonical `{job_id,grant_id,credential,repo_tar,prompt,output_pub}`.
   `credential` is the `claude-subscription/1` JSON object (project the local
   credential store to the validator’s `ACCEPTED_OAUTH_FIELDS` before sealing), `repo_tar` is base64 tar,
   `prompt` is text, `output_pub` is 64-byte P-256 x||y hex. Both IDs must agree
   with the control frame/grant. The pinned compose fixes the agent configuration.
4. Node writes credential to tmpfs `/run/dsmack/credential`, runs one pinned
   `agent-turns/find.py` edit turn with repo and outputs in tmpfs, and removes
   the credential and work directory before accepting another job.
5. Node sends `{status:"complete",outputs,statement,attestation,receipt}`.
   `outputs` maps `patch`, `transcript`, `verdict` to independent secret_box
   envelopes sealed to `output_pub`, with task IDs `job_id + "/" + name`.
   `statement` is `{job_id,bundle_sha256,outputs,grant_id,seconds_used}` where
   `outputs` maps those names to SHA256 of the plaintext bytes, `bundle_sha256`
   hashes canonical encrypted input envelope, and `seconds_used` is positive
   elapsed wall time rounded up, at most the admitted remaining budget.
   The per-job `attestation` is hex; report_data is SHA256(canonical statement)
   followed by 32 zero bytes. Receipt is canonical
   `{client_peer,node_peer,run,report_sha256,grant_id,job_id,seconds_used,sig}`;
   `sig` is Ed25519 over the receipt without `sig`.

Verify the per-job assertion, same run/measurements/caller as discovery,
statement report_data, receipt key/signature, both IDs, input envelope hash,
and decrypted output hashes before accepting a patch. Failed jobs consume
elapsed seconds and retain the job ID; a timeout kills the agent process group.
Only public registration and usage metadata may go to result artifacts/console.
