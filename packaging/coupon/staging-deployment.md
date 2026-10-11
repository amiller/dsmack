# Coupon staging replacement packet (template — not a deploy approval)

This documents the reviewed procedure for replacing an existing stopped
coordinator-class node with the coupon debug-staging service. It is a
**template**: concrete identifiers, saved state and rollback evidence live in
the operator's ignored `local-data/` packet next to this checkout and never in
commits. Nothing here authorizes deployment. Any live mutation requires the
complete delta to pass independent review and explicit root approval first.

The staging profile is debug-only: `private_issuance_qualified` and
`rollback_qualified` stay false, no settlement receipt is emitted, and the
approval root baked into the image is a development staging authority, never a
production authority.

## 1. Prerequisites (all must be recorded in the ignored packet before use)

1. **Reviewed image** built from this source with the staging authority public
   key baked at build time:

   ```sh
   docker build --platform linux/amd64 \
     --build-arg COUPON_APPROVAL_PUBLIC_KEY=<staging authority public key hex> \
     -f packaging/coupon/Dockerfile -t <reviewed-tag> <exported-package>
   ```

   The committed `packaging/coupon/approval-root.json` stays `null`; only the
   build argument writes the root into the measured image. An image built
   without it cannot admit any signed control file.
2. **Development staging authority** generated once into an ignored directory
   (`tools/coupon_staging_authority.py generate --dir local-data/coupon-staging-authority`).
   The private seed never leaves that directory, never enters argv, logs,
   exports or the image. Only `public-key` output is recorded.
3. **Signed control files** produced by the same tool from payloads the
   operator binds to the probe measurements (`sign-approval`, then `sign-config`
   with the signed approval payload). The worker re-verifies both against the
   baked root before any credential exists.
4. **Saved replacement evidence**: exact old compose (by content hash), old
   encrypted environment, and old retained state of the target node, plus the
   old image digest. Replacement is refused if any of these was not captured.
5. **Root approval** of the complete delta (source, image, key attribution,
   this packet) on record.

## 2. Replacement procedure

1. Keep the target node stopped. Confirm the shared staging webhost project is
   not the target and stays untouched throughout.
2. Snapshot, into the ignored packet: current compose and its content hash,
   encrypted environment values, durable state volumes, image digest. Verify
   the saved compose hash matches the running-config commitment observed in the
   inventory before proceeding.
3. Install the reviewed image and the compose from
   `packaging/coupon/staging-compose.yaml` with concrete values from the
   packet. The coupon service must use a **distinct state namespace and volume**
   and a distinct operator directory; it must never mount or overwrite the old
   coordinator state. The guest dstack socket mount must be verified present
   (positive socket/key/quote evidence) before first start.
4. **State volume ownership precondition (before first start).** A freshly
   created named volume is root-owned, but the image runs as the unprivileged
   `node` user (uid/gid 1000) and the launcher/worker require the operator
   directory to be owned by the process uid with mode 0700 — those checks are
   deliberately not relaxed. Initialize the volume once, as root, from the
   reviewed image itself and record the verification in the packet:

   The image ENTRYPOINT is the coupon node launcher (`node node/coupon-node.mjs`),
   which accepts no `install`/`stat` words — a one-shot maintenance command must
   override the entrypoint so it runs the image's coreutils directly (the same
   pattern as `packaging/coupon/README.md`):

   ```sh
   docker run --rm --user root --entrypoint install \
     -v <COUPON_STAGING_STATE_VOLUME_PLACEHOLDER>:/operator/coupon-staging \
     <reviewed-tag> -d -o 1000 -g 1000 -m 0700 /operator/coupon-staging
   docker run --rm --entrypoint stat \
     -v <COUPON_STAGING_STATE_VOLUME_PLACEHOLDER>:/operator/coupon-staging \
     <reviewed-tag> -c '%u %g %a' /operator/coupon-staging   # expect: 1000 1000 700
   ```

   Mode 0700 owned by the runtime uid also preserves private staging
   visibility: no other local account can read operator state.
5. First start uses `bootstrap-staging` over the protected operator pipe:
   the process prints public SDK metadata (`bootstrap_metadata`), the operator
   signs approval/config against exactly those measurements, then pipes the two
   signed envelopes back on the same pipe. Compose and image do not change
   between phases.
   Keep the authenticated private attach/controller channel open for later
   operator frames; closing stdin stops the node. Provision responses contain
   the bearer coupon and belong only on that protected channel. The compose
   explicitly disables container logging (`logging.driver: none`); disable
   public Phala logs as well (`--no-public-logs` on the reviewed deployment
   command). Do not collect this stream with `docker logs`, a general log sink
   or a public dashboard. Sign against the actual compose observed during this
   bootstrap, including its logging configuration, rather than reusing a prior
   compose hash.
6. Verify readiness exactly: environment `private-debug-staging`, the issuer
   peer id derived from the published noise seed, the recorded
   `approval_sha256`, listener on loopback (or an explicitly reviewed private
   route), `private_issuance_qualified: false`, `rollback_qualified: false`.
7. Private routing: the launcher defaults to loopback. Any peer/dashboard
   exposure, tunnel or management route must be an explicit reviewed entry in
   the ignored packet; a public gateway URL alone never reclassifies this
   staging service.
8. Record the new compose commitment, image digest, approval hash and authority
   public key in the packet.

## 3. Rollback procedure

1. Stop the coupon staging service. Issuance jobs are terminated with the
   process group; any interrupted job is deliberately left in
   `reconciliation_required` — rollback does not resume or retry effects.
2. Restore the saved compose, encrypted environment and state volumes from the
   packet snapshot; verify the restored compose content hash equals the
   recorded old commitment before restarting.
3. Restart the original image (recorded digest) and verify the node's own
   health endpoint answers as before the replacement.
4. Coupon state from the staging period is retained read-only in the packet
   for reconciliation accounting; it is never merged into the restored node.

## 4. Limitations that survive this packet

- Disk rollback cannot un-consume a coupon whose guard transaction confirmed;
  live memory cloning/rollback to mint new coupon identities remains a staging
  limitation.
- Aggregate caps are local and durable; they are not a settlement statement.
- Operator secret custody, provider account-owner retrieval and sponsor
  self-claim remain unqualified.
- The host clock is a declared assumption of this staging profile.
- **Approval `generation` is coordination metadata only — it is not a rollback
  protection mechanism.** The worker validates the field's shape and expiry but
  never enforces monotonicity against persisted state: rollback protection for
  *existing* state comes solely from the `staging_binding` pin of
  `approval_sha256`, and a **fresh** state directory admits any unexpired,
  validly-signed approval regardless of its generation. Under the disclosed
  host/disk rollback assumptions above, a locally persisted generation counter
  proves nothing (it rolls back with the disk). The operator treats
  `generation` as out-of-band coordination: record the generation of every
  admitted approval in the ignored packet and compare it against that record
  before each start; a reused or lower generation is an operational stop, not a
  worker-enforced one.
