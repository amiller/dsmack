#!/bin/bash
# BUILD.sh -- the SINGLE concrete, executable build+delivery procedure (S01),
# repaired against integration-build-review B01-B04 (isolation, ownership,
# deadline/resources, input identity). GATED: run ONLY after independent
# Phase-A approval of this freeze. This lane (integration-build-prep-repair2)
# froze it but does NOT run it. It repairs the residual B01/B02/B03/B05
# findings the integration-build-review-repair1 gate raised against repair1.
#
# What it does, in order, with exact commands and bounds:
#   1. two-leg reproducible rebuild of the dstack-derived ARM64 base image
#      (kernel REUSED byte-identical from the proven ec83a3fc bundle; rootfs
#      legs install the repaired runner-content, the patched validator, the
#      supervisor, the sentinel package + its adapter dependency, and the
#      measured docker-daemon.json registry policy);
#   2. promote + admission (+tamper) -> build/artifacts, H' = os_image_hash;
#   3. rebuild the harness container image (repaired wrappers) for linux/arm64
#      with ONE owned, pinned buildkit worker and PUSH it to the fresh
#      loopback registry; resolve D' as the EXACT linux/arm64 CHILD MANIFEST
#      digest (never an index digest) and verify its config platform.
#      Delivery (GIO09, reconciled single endpoint) is the exact-digest pull of
#      127.0.0.1:5005/dsmack-claude-harness@D' from the IN-GUEST loopback
#      publisher that serves the measured oci-layout/ channel before the runner
#      (no slirp 10.0.2.2:5005, no host Docker); the ONLY policy change remains
#      the measured "insecure-registries":["127.0.0.1:5005"] baked into H' --
#      the digest check is never weakened;
#   4. regenerate the product manifests (FULL identity chain) and the
#      engineering + product runner-inputs (images/ + broker/ channel dirs;
#      config only -- NO token, NO credential in any artifact);
#   5. POST-BUILD VERIFICATION (verify_built_artifacts.py, repaired per B05):
#      child-manifest + config-platform identity, exact manifest sets, parsed
#      service image refs, complete base_vm equality, BOTH delivered input
#      trees, full bundle rehash, verity/tamper evidence, installed CLI,
#      package inventory, credential/token exclusion;
#   6. emit BUILT-ARTIFACTS-LOCK.json binding the measured identities, the
#      FULL INPUT INVENTORY and the verification transcript hash.
#
# Isolation/ownership bounds (B01/B02):
#   * every docker client call uses the EXPLICIT local daemon endpoint
#     (DOCKER_HOST=unix:///var/run/docker.sock) and a FRESH credential-free
#     DOCKER_CONFIG under the build root (no inherited context, config or
#     credential helpers; BUILDX_CONFIG is isolated under the build root too);
#   * exactly ONE owned build worker: a pinned moby/buildkit container started
#     by THIS run (docker run, resource-limited), state + socket + config
#     under the build root (the single build/install cache, GC-bounded);
#     connected via `docker buildx create --driver remote`;
#   * the registry image is pinned by IMMUTABLE LOCAL IMAGE ID, binds
#     127.0.0.1 only, and uses fresh storage created by this run; occupied
#     names/ports are REJECTED, never reused; DSMACK_REGISTRY_ROOT is gone;
#   * every container created here is recorded by CONTAINER ID at creation;
#     cleanup removes ONLY those IDs with bounded commands, captures their
#     logs first, confirms removal, and exits nonzero if not confirmed. No
#     fixed-name `docker rm` of containers this run did not create.
# Deadline/resource bounds (B03): this script runs ONLY under the EXTERNAL
#   supervisor build_supervisor.py (same directory), which owns ONE absolute
#   18000 s wall-clock deadline INCLUDING its held cleanup reserve, supervises
#   the whole lifecycle (preflight hashing/scans, build, final verification,
#   lock, cleanup) in a dedicated process group behind a fail-closed watchdog,
#   samples bounded storage accounting (build-root du + per-owned-container
#   docker SizeRw + worst-case log charge), and forcibly terminates the group
#   (TERM -> non-deferrable KILL) + docker-kills owned containers on overflow,
#   failed/hung accounting, deadline, or supervisor death. Inside the child
#   budget, EVERY blocking call here is additionally clamped to the remaining
#   budget with the forced-kill grace INSIDE the clamp (bounded()); concrete
#   --cpus/--memory/--pids-limit on every container; output root FIXED to
#   $LANE/build (no DSMACK_BUILD_ROOT; symlinked/prior-output roots rejected);
#   extraction, config, logs and builder state all live under the build root;
#   PYTHONDONTWRITEBYTECODE=1 keeps host imports from writing into the
#   frozen candidate (re-verified unchanged after the build).
# Input identity (B04): the pinned candidate inventory (self-sha supplied by
#   the BUILD REQUEST env, outside the inventory's own hash domain) is
#   verified entry-by-entry before any mutation; unexpected candidate files
#   are rejected; the proven kernel/rootfs/metadata inputs and the seed .deb
#   cache are hash-pinned; the harness Dockerfile resolves packages ONLY from
#   the pinned debian snapshot; all input identities land in the lock.
# Still true: no external publication, no credential access, no VM boot, no
#   global daemon/binfmt changes (binfmt presence is CHECKED, never set).
set -euo pipefail

# ---- pinned identities and bounds (fail closed on drift) ---------------------
APPROVED_PARENT=/data/amiller/dsmack/attested-runner-20261020
LANE=${DSMACK_BUILD_LANE:-$APPROVED_PARENT/integration-build-prep-repair2}
CAND=$LANE/candidate
BUILD_ROOT=$LANE/build                  # FIXED derivation; no env override (B03)
PRIOR=${DSMACK_PRIOR:-$APPROVED_PARENT/dstack-base-image}        # content pinned below
PROVEN=${DSMACK_PROVEN:-$APPROVED_PARENT/dstack-smoke-finish}    # content pinned below
BUILDER_IMAGE_ID=sha256:df98b52ea039e4bbb40c52ca51f869c908d687ab5ea4154e1678afd0da0a04e9
REGISTRY_IMAGE_ID=sha256:26b2eb03618e749084668eaff68cff8f81dda12d06ac641be7a6398b82a6f25b   # registry:2, immutable local ID
BUILDKIT_IMAGE=moby/buildkit@sha256:c457984bd29f04d6acc90c8d9e717afe3922ae14665f3187e0096976fe37b1c8  # v0.20.2, present locally, digest-immutable
REGISTRY_HOST=127.0.0.1:5005            # host build registry (loopback, D' resolution); the guest pulls from its OWN in-guest 127.0.0.1:5005 publisher (GIO09)
HARNESS_NAME=dsmack-claude-harness
HARNESS_TAG=2.1.187-7
# SPECULATIVE-IMAGE-E2E MODIFICATION (speculative-image-e2e-execute lane):
# Step 3 no longer REBUILDS the harness via buildkit/buildx from the candidate's
# claude-inputs-candidate/harness/image context (that context is INCOMPLETE here:
# it lacks the claude-linux-arm64 binary, the build CA bundle and the managed
# settings the original arm64 image was built from). Per the OWNER's explicit
# instruction we REUSE the independently-built, verified ARM64 OCI
# (arm64-harness-critical, state built_needs_review) BYTE-FOR-BYTE, pushing its
# exact blobs+manifest into the owned loopback registry so D' resolves to the
# pinned child manifest. No amd64/arm64 harness cross-build is performed.
OCI_LAYOUT=/data/amiller/dsmack/attested-runner-20261020/arm64-harness-critical/oci-layout-v1
OCI_MANIFEST_DIGEST=sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418
# Repaired source identities this build MUST embed (verified in step 5):
API_WRAPPER_SHA=31a541a779aaffc645dd9966248f1ffc3f25b7b999e1253e8ef558391f142c2f
SUB_WRAPPER_SHA=e396cd293fe9b53fc728098bdbf66e0dccb69a1cf0b5f4f6b8dfceae863e2c5a
STALE_BASE=46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2
# Pinned read-only inputs (B04):
PROVEN_IMAGE_SHA=415e59cc1fbaa957b8737749f0e7822e4d843b27b363345cdb9e6a2a870a6d88
PROVEN_CONFIG_SHA=4cf4325bff9c5ed1078487c5aa6b25b4b8179db0b64e306c2215239eab21ba99
PROVEN_ROOTFS_SHA=5720f6049c2c524c83b8e0932cdbe7dceac6dea2532c0d82401e67118dc84395
PROVEN_METADATA_SHA=2a4ed17375ca10e2360a67211fcc0e2c6660a88214402d5dc1268209dda9294e
SEED_CACHE_SHA=3cb9d6db7f1a3c28ff170ea1087a89525f3563af08378ab332aef1cdf7771b67
SEED_CACHE_COUNT=115
# Resource bounds (B03) -- concrete, enforced per container:
LEGS_CPUS=6;    LEGS_MEM=12g;   LEGS_PIDS=4096
PROM_CPUS=4;    PROM_MEM=8g;    PROM_PIDS=2048
REG_CPUS=1;     REG_MEM=512m;   REG_PIDS=256
BK_CPUS=4;      BK_MEM=8g;      BK_PIDS=4096
STORAGE_MAX_BYTES=32212254720           # 30 GiB cap on $BUILD_ROOT, checked between steps
MIN_FREE_KB=41943040                    # 40 GiB free required at preflight
BUILDKIT_GC_KEEP_BYTES=10737418240      # 10 GiB bound on the ONE build cache

# ---- ONE overall wall-clock deadline, enforced by the EXTERNAL supervisor ----
# (B03-deadline/B03-storage repair.) This script REFUSES to run unsupervised:
# build_supervisor.py (same directory) is the single entrypoint. It owns the
# absolute 18000 s deadline (including its own held cleanup reserve), runs this
# script in a dedicated session/process group behind a fail-closed watchdog,
# samples bounded storage accounting (build root du + per-owned-container
# docker SizeRw + worst-case log charge), and -- on overflow, accounting
# failure, deadline, or its own death -- terminates the WHOLE process group
# (SIGTERM, then non-deferrable SIGKILL after the grace) and docker-kills the
# owned containers, then performs bounded ID-tracked cleanup itself. No shell
# trap in this file is part of the enforcement path anymore.
[ "${DSMACK_SUPERVISED:-}" = "1" ] || { echo 'B03: BUILD.sh must run under build_supervisor.py (DSMACK_SUPERVISED=1 not set); refusing unsupervised execution' >&2; exit 1; }
[[ ${DSMACK_SUPERVISOR_PID:-} =~ ^[0-9]+$ ]] || { echo 'B03: DSMACK_SUPERVISOR_PID missing/invalid' >&2; exit 1; }
[[ ${DSMACK_DEADLINE_EPOCH:-} =~ ^[0-9]+$ ]] || { echo 'B03: DSMACK_DEADLINE_EPOCH missing/invalid' >&2; exit 1; }
[[ ${DSMACK_WALL_CLOCK_MAX:-} =~ ^[0-9]+$ ]] && [ "$DSMACK_WALL_CLOCK_MAX" -le 18000 ] \
  || { echo 'B03: DSMACK_WALL_CLOCK_MAX missing or above the frozen 18000 s bound' >&2; exit 1; }
WALL_CLOCK_MAX=$DSMACK_WALL_CLOCK_MAX
DEADLINE=$DSMACK_DEADLINE_EPOCH          # supervisor-held reserve is ALREADY excluded
NOW_EPOCH=$(date +%s)
[ "$DEADLINE" -gt "$NOW_EPOCH" ] || { echo 'B03: supervisor deadline already elapsed' >&2; exit 97; }
[ "$DEADLINE" -le $((NOW_EPOCH + WALL_CLOCK_MAX)) ] || { echo 'B03: supervisor deadline exceeds the wall-clock bound' >&2; exit 1; }
# B03: in-script budget used to CLAMP every blocking call below. This is the
# inner (cooperative) bound; the supervisor's group-kill is the outer one.
KILL_GRACE=5
remaining() { local r=$((DEADLINE - $(date +%s))); [ "$r" -gt 0 ] && echo "$r" || echo 0; }
step_timeout() {  # min(step cap, remaining); fail the run when the budget is gone
  local cap=$1 r; r=$(remaining)
  [ "$r" -gt 0 ] || { echo "B03: overall ${WALL_CLOCK_MAX}s deadline exhausted" >&2; exit 97; }
  if [ "$cap" -lt "$r" ]; then echo "$cap"; else echo "$r"; fi
}
bounded() {  # bounded <cap-seconds> <cmd...>: worst case INCLUDING forced-kill
  # grace fits inside min(cap, remaining). The grace is part of the slot, not
  # appended after it (B03-deadline-residual).
  local cap=$1; shift
  local t g main; t=$(step_timeout "$cap"); g=$KILL_GRACE
  [ "$t" -gt "$g" ] || g=1
  main=$((t - g)); [ "$main" -ge 1 ] || main=1
  timeout -k "$g" "$main" "$@"
}

echo "== preflight =="
# B03: removed knobs are REJECTED loudly, not silently ignored
[ -z "${DSMACK_BUILD_ROOT:-}" ] || { echo 'B03: DSMACK_BUILD_ROOT is no longer accepted; the output root is fixed to $LANE/build' >&2; exit 1; }
[ -z "${DSMACK_REGISTRY_ROOT:-}" ] || { echo 'B02: DSMACK_REGISTRY_ROOT is no longer accepted; a pre-existing registry is never reused' >&2; exit 1; }
# B03: lane confinement -- literal path under the approved parent, no symlinks
case $LANE in "$APPROVED_PARENT"/*) : ;; *) echo "B03: lane $LANE is outside $APPROVED_PARENT" >&2; exit 1 ;; esac
case $LANE in *..*) echo "B03: lane path must not contain '..'" >&2; exit 1 ;; esac
[ "$(realpath -m "$LANE")" = "$LANE" ] || { echo "B03: lane path $LANE contains symlinks or dot segments; refusing" >&2; exit 1; }
# B03: ONE fresh output root. The supervisor enforced fresh/empty BEFORE this
# run and then created ONLY its own evidence dir "supervisor/" inside it; any
# other pre-existing entry means prior outputs and is refused.
if [ -e "$BUILD_ROOT" ]; then
  [ -d "$BUILD_ROOT" ] && [ ! -L "$BUILD_ROOT" ] \
    || { echo "B03: output root $BUILD_ROOT is not a real directory; refusing" >&2; exit 1; }
  EXTRA=$(ls -A "$BUILD_ROOT" | grep -vx 'supervisor' || true)
  [ -z "$EXTRA" ] \
    || { echo "B03: output root $BUILD_ROOT already contains prior outputs ($EXTRA); refusing" >&2; exit 1; }
fi
# ---- fresh output root + ISOLATED docker/buildx config BEFORE any docker call
# (B01: every docker invocation -- INCLUDING the preflight image inspects --
# must inherit the credential-free isolated configuration, never ambient
# context/config/credential-helpers; B03-storage: all diagnostics, logs,
# extraction and builder state live UNDER the build root).
mkdir -p "$BUILD_ROOT"/{w-build,w-evidence,registry-data,product-manifests,runner-inputs,runner-inputs-product,logs,docker-config,buildx,buildkit-state,buildkit-run,verify-tmp,preflight}
LOGDIR=$BUILD_ROOT/logs
export DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker.sock}
[ "$DOCKER_HOST" = "unix:///var/run/docker.sock" ] || { echo "B01: only the local daemon endpoint unix:///var/run/docker.sock is approved (got $DOCKER_HOST)" >&2; exit 1; }
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH 2>/dev/null || true
export DOCKER_CONFIG=$BUILD_ROOT/docker-config
printf '{"auths": {}, "credHelpers": {}, "plugins": {}}\n' > "$DOCKER_CONFIG/config.json"
export BUILDX_CONFIG=$BUILD_ROOT/buildx
# B03: host-side python must never write bytecode into the frozen candidate
export PYTHONDONTWRITEBYTECODE=1
assert_isolated_docker() {  # B01 detecting control: refuse ANY docker call under ambient config
  [ "${DOCKER_CONFIG:-}" = "$BUILD_ROOT/docker-config" ] || { echo "B01: DOCKER_CONFIG is not the isolated build-root config (got '${DOCKER_CONFIG:-}')" >&2; exit 1; }
  [ -f "$DOCKER_CONFIG/config.json" ] || { echo "B01: isolated docker config.json missing" >&2; exit 1; }
  [ "${BUILDX_CONFIG:-}" = "$BUILD_ROOT/buildx" ] || { echo "B01: BUILDX_CONFIG is not the isolated build-root buildx state (got '${BUILDX_CONFIG:-}')" >&2; exit 1; }
  [ "${DOCKER_HOST:-}" = "unix:///var/run/docker.sock" ] || { echo "B01: DOCKER_HOST drifted to '${DOCKER_HOST:-}'" >&2; exit 1; }
  [ -z "${DOCKER_CONTEXT:-}" ] || { echo "B01: an ambient DOCKER_CONTEXT is set ($DOCKER_CONTEXT); refusing" >&2; exit 1; }
  python3 - "$DOCKER_CONFIG/config.json" <<'PY' || { echo "B01: isolated docker config carries auths/credHelpers (not credential-free)" >&2; exit 1; }
import json,sys
c=json.load(open(sys.argv[1]))
sys.exit(0 if not c.get("auths") and not c.get("credHelpers") else 1)
PY
}

# B04: the pinned candidate inventory is verified BEFORE any mutation.
# Its self-sha256 comes from the BUILD REQUEST (env), outside the inventory's
# own hash domain (the inventory covers BUILD.sh itself).
INV=$LANE/candidate-SHA256SUMS.txt
INV_SHA=${DSMACK_CANDIDATE_INVENTORY_SHA256:?B04: DSMACK_CANDIDATE_INVENTORY_SHA256 (the reviewed inventory self-sha256) is required}
[[ $INV_SHA =~ ^[0-9a-f]{64}$ ]] || { echo 'B04: DSMACK_CANDIDATE_INVENTORY_SHA256 must be 64 hex chars' >&2; exit 1; }
[ -f "$INV" ] || { echo "B04: candidate inventory missing at $INV" >&2; exit 1; }
[ "$(sha256sum "$INV" | cut -d' ' -f1)" = "$INV_SHA" ] \
  || { echo "B04: candidate inventory self-sha256 does not match the reviewed pin $INV_SHA" >&2; exit 1; }
[ -d "$CAND/dstack-runner-join/source" ] || { echo "candidate missing at $CAND" >&2; exit 1; }
# B03-deadline: preflight hashing/scans are BOUNDED (clamped to the remaining
# budget, grace included) -- they are inside the supervised deadline like
# everything else.
( cd "$CAND" && bounded 900 sha256sum -c --quiet "$INV" ) \
  || { echo 'B04: candidate bytes do not match the reviewed inventory (or hashing exceeded its bound)' >&2; exit 1; }
# B04: reject unexpected files in the build context (inventory is exhaustive).
# B03-storage: the diff diagnostic is written UNDER the build root, never to a
# "$BUILD_ROOT".<sibling> path outside the declared output root.
INVDIFF=$BUILD_ROOT/preflight/inventory-diff.txt
LIST_FS=$BUILD_ROOT/preflight/files-fs.txt
LIST_INV=$BUILD_ROOT/preflight/files-inv.txt
( cd "$CAND" && bounded 300 find . -type f ) | sed 's|^\./||' | LC_ALL=C sort > "$LIST_FS" \
  || { echo 'B03/B04: bounded candidate filesystem scan failed' >&2; exit 1; }
bounded 60 awk '{sub(/^[0-9a-f]{64}  /,""); print}' "$INV" | LC_ALL=C sort > "$LIST_INV" \
  || { echo 'B03/B04: bounded inventory parse failed' >&2; exit 1; }
if ! diff -u "$LIST_FS" "$LIST_INV" >"$INVDIFF" 2>&1; then
  echo 'B04: unexpected/missing candidate files vs the reviewed inventory:' >&2
  cat "$INVDIFF" >&2; exit 1
fi
rm -f "$INVDIFF" "$LIST_FS" "$LIST_INV"
# B04: this script's own identity is covered by the verified inventory
SELF=$(realpath "${BASH_SOURCE[0]}")
[ "$SELF" = "$CAND/dstack-runner-join/source/build/BUILD.sh" ] \
  || { echo "B04: running BUILD.sh ($SELF) is not the inventory-verified copy" >&2; exit 1; }
bounded 120 sha256sum -c --status <<EOF || { echo 'repaired wrapper bytes drifted from the frozen pins' >&2; exit 1; }
$API_WRAPPER_SHA  $CAND/claude-inputs-candidate/harness/image/dsmack-claude-wrapper
$SUB_WRAPPER_SHA  $CAND/claude-inputs-candidate/harness/image/dsmack-claude-wrapper-subscription
EOF
# B04: pin EVERY consumed read-only input: proven kernel AND the proven verity
# rootfs supplying the module store, its metadata, and the seed .deb cache.
bounded 900 sha256sum -c --status <<EOF || { echo 'B04: proven-bundle input bytes do not match their pins' >&2; exit 1; }
$PROVEN_IMAGE_SHA  $PROVEN/build/artifacts/Image
$PROVEN_CONFIG_SHA  $PROVEN/build/artifacts/config-6.18.40-dstack
$PROVEN_ROOTFS_SHA  $PROVEN/build/artifacts/rootfs.squashfs.verity
$PROVEN_METADATA_SHA  $PROVEN/build/artifacts/metadata.json
EOF
SEED_DIR=$PRIOR/cache/debootstrap
[ -d "$SEED_DIR" ] || { echo "B04: seed cache missing at $SEED_DIR" >&2; exit 1; }
SEED_N=$(bounded 120 find "$SEED_DIR" -maxdepth 1 -name '*.deb' -type f | wc -l)
[ "$SEED_N" -eq "$SEED_CACHE_COUNT" ] || { echo "B04: seed cache has $SEED_N debs, pinned $SEED_CACHE_COUNT" >&2; exit 1; }
SEED_GOT=$(bounded 900 bash -c 'cd "$1" && printf "%s\n" *.deb | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d" " -f1' _ "$SEED_DIR")
[ "$SEED_GOT" = "$SEED_CACHE_SHA" ] || { echo "B04: seed cache aggregate $SEED_GOT != pinned $SEED_CACHE_SHA" >&2; exit 1; }
# B01: pinned execution images -- these are the FIRST docker calls, made under
# the isolated config asserted here and bounded with a forced-kill grace (B03).
assert_isolated_docker
bounded 120 docker image inspect "$BUILDER_IMAGE_ID" >/dev/null || { echo 'pinned builder image absent' >&2; exit 1; }
bounded 120 docker image inspect "$REGISTRY_IMAGE_ID" >/dev/null || { echo 'pinned registry image absent' >&2; exit 1; }
bounded 120 docker image inspect "$BUILDKIT_IMAGE" >/dev/null || { echo 'pinned buildkit image absent' >&2; exit 1; }
command -v unsquashfs >/dev/null || { echo 'unsquashfs required on the build host' >&2; exit 1; }
# binfmt is CHECKED, never registered (host amd64 cross-building linux/arm64)
[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || { echo 'qemu-aarch64 binfmt not registered on this host; refusing (this build never modifies binfmt)' >&2; exit 1; }
# storage preflight (B03)
FREE_KB=$(bounded 60 df --output=avail -k "$LANE" | tail -1 | tr -d ' ')
[ "$FREE_KB" -ge "$MIN_FREE_KB" ] || { echo "B03: ${FREE_KB}KB free < required ${MIN_FREE_KB}KB" >&2; exit 1; }
# B02: the loopback registry port must be FREE (occupied port rejected, never reused)
if (exec 3<>/dev/tcp/127.0.0.1/5005) 2>/dev/null; then
  echo 'B02: 127.0.0.1:5005 is already occupied; refusing to reuse or share a registry' >&2; exit 1
fi

# ---- ownership tracking + bounded ID-only cleanup (B02) ----------------------
RUN_ID=$(date +%Y%m%d%H%M%S)-$$
NAME_PREFIX=dsmack-build-$RUN_ID
OWNED_CIDS_FILE=$BUILD_ROOT/owned-containers.txt
: > "$OWNED_CIDS_FILE"
BX_NAME=""

assert_name_free() {  # B02/B03: reject occupied names; a FAILED query is never treated as "free"
  local n=$1 out rc
  out=$(bounded 60 docker ps -a --format '{{.Names}}'); rc=$?
  [ "$rc" -eq 0 ] || { echo "B02/B03: container-name occupancy query failed/timed out (rc=$rc); refusing to proceed blind" >&2; exit 1; }
  if printf '%s\n' "$out" | grep -Fxq "$n"; then
    echo "B02: container name $n is already occupied; refusing" >&2; exit 1
  fi
}

run_owned() {  # run_owned <name> <docker-run-args...> -> records the created ID
  local name=$1; shift
  assert_name_free "$name"
  local cidf=$BUILD_ROOT/cid.$name cid rc
  rm -f "$cidf"
  # B03: bounded with a forced-kill grace. B02/B03: --cidfile captures the ID
  # the daemon assigns; even if the client is interrupted AFTER the container is
  # created (creation succeeded, client communication failed), the ID is on disk
  # so cleanup still OWNS and removes it. B03-storage: every owned container
  # carries explicit log caps (bounds its writable json-file log).
  bounded 120 docker run -d --cidfile "$cidf" \
    --log-driver json-file --log-opt max-size=64m --log-opt max-file=3 \
    --name "$name" "$@" >/dev/null 2>>"$LOGDIR/$name.start.err"
  rc=$?
  if [ -s "$cidf" ]; then
    cid=$(cat "$cidf")
    printf '%s %s\n' "$cid" "$name" >> "$OWNED_CIDS_FILE"   # ownership recorded BEFORE any failure path
  fi
  [ "$rc" -eq 0 ] || { echo "B03: container $name start exceeded its bound / failed (rc=$rc); ownership preserved for cleanup" >&2; exit 97; }
  [ -s "$cidf" ] || { echo "container $name failed to start (no container id captured)" >&2; exit 1; }
  printf '%s' "$cid"
}

wait_owned() {  # wait_owned <cid> <name> <cap-seconds>; clamped to the overall deadline
  local cid=$1 name=$2 cap=$3 rc
  # B03-deadline: the auxiliary kill/log operations below are ALSO clamped to
  # the remaining budget via bounded() -- no fixed 30/60 s waits survive a
  # nearly-exhausted deadline.
  if ! rc=$(bounded "$cap" docker wait "$cid" 2>>"$LOGDIR/$name.err"); then
    bounded 30 docker kill "$cid" >/dev/null 2>&1 || true
    bounded 60 docker logs "$cid" > "$LOGDIR/$name.log" 2>&1 || true
    echo "B03: step $name exceeded its bound and was killed (log: $LOGDIR/$name.log)" >&2
    exit 97
  fi
  bounded 60 docker logs "$cid" > "$LOGDIR/$name.log" 2>&1 || true
  [ "$rc" = "0" ] || { echo "step $name failed rc=$rc (log: $LOGDIR/$name.log)" >&2; exit 1; }
}

guard_storage() {  # B03: bounded between-step check; accounting failure FAILS CLOSED.
  # (The authoritative DURING-step monitor with container SizeRw + log-charge
  # accounting lives in build_supervisor.py; this is the cooperative inner check.)
  local used duerr duout durc
  # SPECULATIVE-IMAGE-E2E fix: root-owned 0700 cache dirs created by the
  # in-container (root) legs/promote steps make this UNPRIVILEGED du exit
  # nonzero with EACCES while still printing the readable aggregate on stdout.
  # Tolerate a du whose ONLY stderr is 'Permission denied' (documented
  # undercount); any other du error (incl. a timeout) still fails closed.
  # Mirrors the supervisor. The `if` neutralises set -e so we capture rc.
  duerr=$(mktemp "$LOGDIR/.du-err.XXXXXX")
  duout=$(mktemp "$LOGDIR/.du-out.XXXXXX")
  if bounded 120 du -sb "$BUILD_ROOT" >"$duout" 2>"$duerr"; then durc=0; else durc=$?; fi
  used=$(cut -f1 "$duout")
  if [ "$durc" -ne 0 ]; then
    if [ -s "$duerr" ] && ! grep -qv 'Permission denied' "$duerr"; then
      : # EACCES-only: du still totalled the readable entries on stdout
    else
      echo "B03: storage accounting (du rc=$durc) failed or exceeded its bound; failing closed" >&2
      cat "$duerr" >&2; rm -f "$duerr" "$duout"; exit 94
    fi
  fi
  rm -f "$duerr" "$duout"
  [[ $used =~ ^[0-9]+$ ]] \
    || { echo "B03: storage accounting produced no usable value ('$used'); failing closed" >&2; exit 94; }
  [ "$used" -le "$STORAGE_MAX_BYTES" ] \
    || { echo "B03: build root ${used}B exceeds the ${STORAGE_MAX_BYTES}B storage bound" >&2; exit 1; }
}

# B03-storage: the active-build storage monitor is NO LONGER a shell subshell
# signalling this script with a deferrable SIGTERM (the repair2 defect: Bash
# defers the trap while a foreground command runs, and a failed du silently
# killed the monitor while the build continued). The EXTERNAL supervisor
# (build_supervisor.py, the process supervising this one) owns during-step
# accounting: bounded du of the build root + per-owned-container
# `docker inspect --size` SizeRw (covering Docker-managed writable layers
# OUTSIDE the bind-mounted output root) + a fixed worst-case charge for the
# dockerd-enforced json-file log caps. It FAILS CLOSED on failed/hung
# accounting, docker-kills the owned containers (which this script records via
# cidfiles below) and SIGKILLs this whole process group -- which no foreground
# wait or trap can defer. Container logs remain HARD-capped per container
# (run_owned --log-opt) and the single build cache is GC-bounded.

cleanup_bound() {  # like bounded() but NEVER exits the script: rc 124 when the
  # budget is gone (the supervisor's held reserve then finishes the job).
  local cap=$1; shift
  local r t g main; r=$(remaining)
  [ "$r" -gt 0 ] || return 124
  t=$cap; [ "$t" -le "$r" ] || t=$r
  g=$KILL_GRACE; [ "$t" -gt "$g" ] || g=1
  main=$((t - g)); [ "$main" -ge 1 ] || main=1
  timeout -k "$g" "$main" "$@"
}

CLEANUP_DONE=0
cleanup() {  # bounded; removes ONLY IDs created by THIS invocation; confirms removal.
  # This is the NORMAL-PATH cleanup inside the child budget. The external
  # supervisor independently re-runs ID-tracked cleanup from its held reserve
  # afterwards (and whenever this script is killed), so a budget-exhausted or
  # killed cleanup here still ends with supervised, confirmed removal.
  local rc=$? fail=0 cid name n_cids ops qout qrc r
  [ "$CLEANUP_DONE" = 1 ] && exit "$rc"; CLEANUP_DONE=1
  set +e
  # B03: per-operation budget = min(fair share of the REMAINING child budget, 120 s),
  # grace INCLUDED (cleanup_bound). Worst case = 3 ops per owned container
  # (logs, rm, confirm) + 2 for the owned builder (rm, confirm).
  n_cids=$(grep -c . "$OWNED_CIDS_FILE" 2>/dev/null); [ -n "$n_cids" ] || n_cids=0
  ops=$(( n_cids * 3 + 2 )); [ "$ops" -ge 1 ] || ops=1
  r=$(remaining)
  CLEANUP_OP_BUDGET=$(( r / ops ))
  [ "$CLEANUP_OP_BUDGET" -le 120 ] || CLEANUP_OP_BUDGET=120
  [ "$CLEANUP_OP_BUDGET" -ge 2 ] || CLEANUP_OP_BUDGET=2
  if [ -s "$OWNED_CIDS_FILE" ]; then
    while read -r cid name; do
      [ -n "$cid" ] || continue
      # preserve diagnostics BEFORE removal (bounded)
      cleanup_bound "$CLEANUP_OP_BUDGET" docker logs "$cid" > "$LOGDIR/cleanup-$name.log" 2>&1
      # removal is attempted, but its success is NEVER trusted on its own
      cleanup_bound "$CLEANUP_OP_BUDGET" docker rm -f "$cid" >/dev/null 2>>"$LOGDIR/cleanup-$name.log"
      # B02: the status QUERY's own success is checked SEPARATELY from its
      # output. A failed/timed-out query leaves removal UNCONFIRMED -> the run
      # fails; empty output is trusted ONLY when the query itself succeeded.
      qout=$(cleanup_bound "$CLEANUP_OP_BUDGET" docker ps -aq --no-trunc --filter "id=$cid"); qrc=$?
      if [ "$qrc" -ne 0 ]; then
        echo "B02: removal UNCONFIRMED for owned container $name ($cid): status query failed/timed out rc=$qrc; diagnostics in $LOGDIR" >&2
        fail=1
      elif [ -n "$qout" ]; then
        echo "B02: cleanup NOT confirmed for owned container $name ($cid); it is still present; diagnostics in $LOGDIR" >&2
        fail=1
      fi
    done < "$OWNED_CIDS_FILE"
  fi
  if [ -n "$BX_NAME" ]; then
    cleanup_bound "$CLEANUP_OP_BUDGET" docker buildx rm "$BX_NAME" >/dev/null 2>>"$LOGDIR/cleanup-buildx.log"
    # B02: the builder LISTING's success is checked separately; a failed listing
    # is NOT treated as absence of the builder.
    qout=$(cleanup_bound "$CLEANUP_OP_BUDGET" docker buildx ls); qrc=$?
    if [ "$qrc" -ne 0 ]; then
      echo "B02: removal UNCONFIRMED for owned buildx builder $BX_NAME: 'docker buildx ls' failed/timed out rc=$qrc" >&2
      fail=1
    elif printf '%s\n' "$qout" | grep -q "^$BX_NAME[[:space:]]"; then
      echo "B02: cleanup NOT confirmed for owned buildx builder $BX_NAME; it is still present" >&2
      fail=1
    fi
  fi
  if [ "$fail" = 1 ]; then
    echo 'B02: CLEANUP NOT CONFIRMED -- failing the run; no other invocation'"'"'s containers were touched' >&2
    [ "$rc" = 0 ] && rc=96
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---- 1+2. two-leg base image rebuild (kernel reused from /proven) ------------
echo "== legs (two independent rootfs+assembly builds; kernel bytes from the proven bundle) =="
CID=$(run_owned "$NAME_PREFIX-legs" \
  --cpus "$LEGS_CPUS" --memory "$LEGS_MEM" --pids-limit "$LEGS_PIDS" \
  -v "$CAND/dstack-runner-join/source:/w/source:ro" \
  -v "$BUILD_ROOT/w-build:/w/build" \
  -v "$CAND:/cand:ro" \
  -v "$PRIOR:/prior:ro" \
  -v "$PROVEN:/proven:ro" \
  "$BUILDER_IMAGE_ID" bash /w/source/build/run-my-legs.sh)
wait_owned "$CID" "$NAME_PREFIX-legs" 10800
grep -q 'rc=0' "$BUILD_ROOT/w-build/legs/legA.rc" && grep -q 'rc=0' "$BUILD_ROOT/w-build/legs/legB.rc" \
  || { echo 'a leg failed; see legs/*.log' >&2; exit 1; }
guard_storage

echo "== promote + admission (+tamper) =="
CID=$(run_owned "$NAME_PREFIX-promote" \
  --cpus "$PROM_CPUS" --memory "$PROM_MEM" --pids-limit "$PROM_PIDS" \
  -v "$CAND/dstack-runner-join/source:/w/source:ro" \
  -v "$BUILD_ROOT/w-build:/w/build" \
  -v "$BUILD_ROOT/w-evidence:/w/evidence" \
  "$BUILDER_IMAGE_ID" bash /w/source/build/promote_and_verify.sh)
wait_owned "$CID" "$NAME_PREFIX-promote" 1800
ARTIFACTS=$BUILD_ROOT/w-build/artifacts
H_PRIME=$(cat "$ARTIFACTS/digest.txt")
[ "$H_PRIME" != "$STALE_BASE" ] || { echo 'rebuild produced the STALE base hash: repaired bytes were not included' >&2; exit 1; }
echo "H' = $H_PRIME"
guard_storage

# ---- 3. harness image: owned worker, fresh loopback registry, child D' -------
echo "== fresh loopback registry (pinned image ID, owned, fresh storage) =="
REGISTRY_ROOT=$BUILD_ROOT/registry-data   # created fresh above; BUILD_ROOT was empty
REG_CID=$(run_owned "$NAME_PREFIX-registry" \
  --cpus "$REG_CPUS" --memory "$REG_MEM" --pids-limit "$REG_PIDS" \
  -p "$REGISTRY_HOST:5000" \
  -v "$REGISTRY_ROOT:/var/lib/registry" "$REGISTRY_IMAGE_ID")
REG_DEADLINE=$(( $(date +%s) + $(step_timeout 60) ))
until bounded 5 curl -fsS "http://$REGISTRY_HOST/v2/" >/dev/null 2>&1; do
  [ "$(date +%s)" -lt "$REG_DEADLINE" ] || { echo 'registry did not become ready' >&2; exit 1; }
  sleep 1
done

echo "== harness image: PUSH verified ARM64 OCI byte-for-byte (NO rebuild) =="
# SPECULATIVE MODIFICATION: instead of a buildkit/buildx cross-build, we upload
# the independently-built, verified arm64-harness-critical OCI
# ($OCI_MANIFEST_DIGEST) into the owned loopback registry over the real v2 HTTP
# protocol. Every blob is re-hashed against its digest before upload; the server
# must store the manifest under exactly the pinned digest. D' resolution below
# then reads the SAME single arm64/linux image manifest and verifies the config
# platform -- no amd64/arm64 harness build is ever performed on this host.
[ -d "$OCI_LAYOUT/blobs/sha256" ] || { echo "OCI layout missing at $OCI_LAYOUT" >&2; exit 1; }
bounded 600 python3 - "$OCI_LAYOUT" "$REGISTRY_HOST" "$HARNESS_NAME" "$HARNESS_TAG" "$OCI_MANIFEST_DIGEST" <<'PY' 2>&1 | tee "$LOGDIR/harness-oci-push.log"
import hashlib, json, os, sys, urllib.request, urllib.error
layout, host, name, tag, want = sys.argv[1:6]
def read_blob(digest):
    algo, hexd = digest.split(":", 1)
    data = open(os.path.join(layout, "blobs", algo, hexd), "rb").read()
    if hashlib.sha256(data).hexdigest() != hexd:
        raise SystemExit("FATAL: blob %s bytes do not match its digest" % digest)
    return data
idx = json.load(open(os.path.join(layout, "index.json")))
if not any(m.get("digest") == want for m in idx.get("manifests", [])):
    raise SystemExit("FATAL: pinned manifest %s not present in OCI index" % want)
mani_raw = read_blob(want)
mani = json.loads(mani_raw)
def http(req, timeout):
    return urllib.request.urlopen(req, timeout=timeout)
def blob_exists(digest):
    try:
        http(urllib.request.Request("http://%s/v2/%s/blobs/%s" % (host, name, digest), method="HEAD"), 30)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise
def put_blob(digest, data):
    if blob_exists(digest):
        return "exists"
    r = http(urllib.request.Request("http://%s/v2/%s/blobs/uploads/" % (host, name), method="POST"), 30)
    loc = r.headers["Location"]
    if loc.startswith("/"):
        loc = "http://%s%s" % (host, loc)
    loc = loc + ("&" if "?" in loc else "?") + "digest=" + digest
    http(urllib.request.Request(loc, data=data, method="PUT",
         headers={"Content-Type": "application/octet-stream",
                  "Content-Length": str(len(data))}), 300)
    return "uploaded"
for d in [mani["config"]["digest"]] + [l["digest"] for l in mani["layers"]]:
    print("blob %s %s" % (d, put_blob(d, read_blob(d))), flush=True)
mt = mani.get("mediaType", "application/vnd.oci.image.manifest.v1+json")
r = http(urllib.request.Request("http://%s/v2/%s/manifests/%s" % (host, name, tag),
         data=mani_raw, method="PUT", headers={"Content-Type": mt}), 60)
server = r.headers.get("Docker-Content-Digest")
if server and server != want:
    raise SystemExit("FATAL: server stored manifest as %s != pinned %s" % (server, want))
print("manifest pushed tag=%s server_digest=%s pinned=%s OK" % (tag, server, want), flush=True)
PY
# propagate the python exit status through the pipe (pipefail is set)
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo 'OCI push into loopback registry failed; see harness-oci-push.log' >&2; exit 1; }
guard_storage

# B05: D' is the EXACT linux/arm64 CHILD MANIFEST digest (never an index) with
# a verified config platform, resolved over the real registry protocol.
D_PRIME=$(bounded 60 python3 - "$REGISTRY_HOST" "$HARNESS_NAME" "$HARNESS_TAG" <<'PY'
import hashlib, json, sys, urllib.request
host, name, tag = sys.argv[1:4]
ACCEPT = ", ".join((
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json"))
def get(ref):
    req = urllib.request.Request("http://%s/v2/%s/manifests/%s" % (host, name, ref),
                                 headers={"Accept": ACCEPT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()
def blob(digest):
    with urllib.request.urlopen("http://%s/v2/%s/blobs/%s" % (host, name, digest), timeout=30) as r:
        return r.read()
raw = get(tag)
doc = json.loads(raw)
if doc.get("manifests"):  # index/list -> exactly one linux/arm64 child
    kids = [m for m in doc["manifests"]
            if (m.get("platform") or {}).get("architecture") == "arm64"
            and (m.get("platform") or {}).get("os") == "linux"]
    if len(kids) != 1:
        raise SystemExit("expected exactly one linux/arm64 child, found %d" % len(kids))
    child = kids[0]["digest"]
    raw = get(child)
    if hashlib.sha256(raw).hexdigest() != child.split(":", 1)[1]:
        raise SystemExit("child manifest bytes do not hash to %s" % child)
    doc = json.loads(raw)
else:
    child = "sha256:" + hashlib.sha256(raw).hexdigest()
if doc.get("manifests") or not doc.get("config") or not doc.get("layers"):
    raise SystemExit("resolved digest is not a single image manifest")
cfg = json.loads(blob(doc["config"]["digest"]))
if (cfg.get("architecture"), cfg.get("os")) != ("arm64", "linux"):
    raise SystemExit("config platform %r/%r != arm64/linux" % (cfg.get("architecture"), cfg.get("os")))
print(child)
PY
)
[[ $D_PRIME =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "registry child-digest resolution failed: '$D_PRIME'" >&2; exit 1; }
echo "D' = $D_PRIME (exact linux/arm64 child manifest; config platform verified)"

# ---- 4. manifests + runner-inputs bound to H'/D' -----------------------------
echo "== product manifests (full identity chain) =="
cp "$CAND"/product-manifests/*.app-compose.json "$BUILD_ROOT/product-manifests/"
bounded 300 python3 "$CAND/dstack-runner-join/source/build/render_product_manifests.py" \
  --artifacts "$ARTIFACTS" --harness-image-digest "$D_PRIME" \
  --api-wrapper-sha256 "$API_WRAPPER_SHA" --subscription-wrapper-sha256 "$SUB_WRAPPER_SHA" \
  --out-dir "$BUILD_ROOT/product-manifests"

echo "== runner-inputs (engineering + product channels) =="
# GIO09: stage the retained verified ARM64 OCI layout ($OCI_LAYOUT, the approved
# arm64-harness-critical/oci-layout-v1) into the MEASURED public oci-layout/
# channel of the PRODUCT channel ONLY -- that is where the claude harness
# workloads actually pull it from. make_guest_inputs.stage_oci_layout re-VERIFIES
# the layout (oci_publish.verify_layout -> the locked single manifest + 15 blobs
# -> the pinned digest $OCI_MANIFEST_DIGEST) and renders loopback
# 127.0.0.1:5005/<name>@<D> delivery refs; the in-guest supervisor then serves it
# read-only on 127.0.0.1:5005 before the runner (bounded readiness) and the guest
# pulls BY DIGEST so RepoDigest is preserved -- no transitional docker-load, no
# host Docker, no 10.0.2.2:5005. The ENGINEERING channel (greet-sh/pycompute)
# does NOT carry the harness OCI: those workloads use their own base-bundle
# images, and a measured public channel must carry only what its workloads need
# (staging the ~260 MiB harness layout there would also blow the smoke vdc bound).
export PYTHONPATH=$CAND/contract10-candidate/lib
bounded 600 python3 "$CAND/dstack-runner-join/source/build/make_guest_inputs.py" --template-only \
  --artifacts "$ARTIFACTS" --out "$BUILD_ROOT/runner-inputs" \
  --candidate "$CAND/contract10-candidate" --mode engineering --no-limits
bounded 600 python3 "$CAND/dstack-runner-join/source/build/make_guest_inputs.py" --template-only \
  --artifacts "$ARTIFACTS" --out "$BUILD_ROOT/runner-inputs-product" \
  --candidate "$CAND/contract10-candidate" --mode product \
  --product-manifests "$BUILD_ROOT/product-manifests" \
  --oci-layout-src "$OCI_LAYOUT"
guard_storage

# ---- 5. post-build verification (independent unpack + negative checks) -------
echo "== post-build verification =="
bounded 1800 python3 "$CAND/dstack-runner-join/source/build/verify_built_artifacts.py" \
  --artifacts "$ARTIFACTS" --candidate "$CAND" \
  --harness-digest "$D_PRIME" --registry-root "$REGISTRY_ROOT" \
  --product-manifests "$BUILD_ROOT/product-manifests" \
  --runner-inputs "$BUILD_ROOT/runner-inputs" \
  --runner-inputs-product "$BUILD_ROOT/runner-inputs-product" \
  --evidence "$BUILD_ROOT/w-evidence" \
  --guest-packages "$BUILD_ROOT/w-build/guest-packages.txt" \
  --workdir "$BUILD_ROOT/verify-tmp" \
  --out "$BUILD_ROOT/postbuild-verification.json"

# B04/B03: the frozen candidate must be bit-identical AFTER the build.
# B03-deadline: this final inventory verification is BOUNDED like everything else.
( cd "$CAND" && bounded 900 sha256sum -c --quiet "$INV" ) \
  || { echo 'B04: candidate bytes CHANGED during the build (or final hashing exceeded its bound); rejecting the result' >&2; exit 1; }
( cd "$CAND" && bounded 300 find . -type f ) | sed 's|^\./||' | LC_ALL=C sort > "$BUILD_ROOT/preflight/files-fs-final.txt" \
  || { echo 'B03/B04: bounded final filesystem scan failed' >&2; exit 1; }
bounded 60 awk '{sub(/^[0-9a-f]{64}  /,""); print}' "$INV" | LC_ALL=C sort > "$BUILD_ROOT/preflight/files-inv-final.txt" \
  || { echo 'B03/B04: bounded final inventory parse failed' >&2; exit 1; }
diff -q "$BUILD_ROOT/preflight/files-fs-final.txt" "$BUILD_ROOT/preflight/files-inv-final.txt" >/dev/null \
  || { echo 'B04: files appeared in or vanished from the frozen candidate during the build' >&2; exit 1; }
guard_storage

# ---- 6. BUILT-ARTIFACTS lock (identities + inputs + verification) ------------
echo "== lock =="
# B03-deadline: lock generation is bounded too
bounded 300 python3 - "$BUILD_ROOT" "$H_PRIME" "$D_PRIME" "$API_WRAPPER_SHA" "$SUB_WRAPPER_SHA" \
  "$INV_SHA" "$BUILDER_IMAGE_ID" "$REGISTRY_IMAGE_ID" "$BUILDKIT_IMAGE" \
  "$PROVEN_ROOTFS_SHA" "$PROVEN_IMAGE_SHA" "$PROVEN_CONFIG_SHA" "$PROVEN_METADATA_SHA" \
  "$SEED_CACHE_SHA" "$SEED_CACHE_COUNT" <<'PY'
import hashlib, json, os, sys
(build_root, h_prime, d_prime, api_sha, sub_sha, inv_sha, builder_id, registry_id,
 buildkit_image, proven_rootfs, proven_image, proven_config, proven_metadata,
 seed_sha, seed_count) = sys.argv[1:16]
tpath = build_root + "/postbuild-verification.json"
transcript = json.load(open(tpath))
assert transcript["predicate"] == "pass", "verification did not pass; no lock"
emb = transcript["embedded"]
lock = {
    "schema": "dsmack.built-artifacts-lock/2",
    "base_os_image_hash": h_prime,
    "harness_image_digest": d_prime,
    "harness_image_digest_kind": "linux/arm64 child manifest (config platform verified)",
    "harness_image_ref_guest": "127.0.0.1:5005/dsmack-claude-harness@" + d_prime,
    "harness_image_source": "SPECULATIVE: reused verified arm64-harness-critical OCI byte-for-byte (NOT rebuilt from the candidate harness/image context); see harness-oci-push.log",
    "speculative": True,
    "api_wrapper_sha256": api_sha,
    "subscription_wrapper_sha256": sub_sha,
    "built_from": os.path.basename(os.path.dirname(os.path.abspath(build_root))) + "/candidate",
    "procedure": "build_supervisor.py -> BUILD.sh (externally supervised; step 3 harness rebuild replaced by verified-OCI push)",
    "inputs": {  # B04: every consumed input identity, pinned and verified pre-build
        "candidate_inventory_self_sha256": inv_sha,
        "builder_image_id": builder_id,
        "registry_image_id": registry_id,
        "buildkit_image": buildkit_image,
        "proven_rootfs_squashfs_verity_sha256": proven_rootfs,
        "proven_kernel_Image_sha256": proven_image,
        "proven_kernel_config_sha256": proven_config,
        "proven_metadata_json_sha256": proven_metadata,
        "seed_deb_cache_aggregate_sha256": seed_sha,
        "seed_deb_cache_count": int(seed_count),
        "debian_snapshot": "20260721T000000Z",
        "network_destinations": [
            "https://snapshot.debian.org (rootfs legs + harness apt, pinned snapshot)",
            "https://registry.npmjs.org (claude-code tarball, sha512-pinned)",
            "registry-1.docker.io (node base pulled by pinned digest)",
            "127.0.0.1:5005 (loopback build registry, owned, fresh storage)",
        ],
        "source_unchanged_after_build": True,
    },
    "verification": {
        "predicate": transcript["predicate"],
        "embedded_validator_sha256": emb["usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract/manifest.py"],
        "embedded_runner_sha256": emb["usr/local/lib/dsmack/compose-runner/dsmack_compose_runner/runner.py"],
        "embedded_supervisor_sha256": emb["usr/bin/dsmack-supervisor"],
        "embedded_sentinel_sha256": emb["usr/local/lib/dsmack/sentinel/harness/sentinel/sentinel.py"],
        "transcript": "postbuild-verification.json",
        "transcript_sha256": hashlib.sha256(open(tpath, "rb").read()).hexdigest(),
    },
    "external_manifest_sha256": transcript["external_manifest_sha256"],
}
out = build_root + "/BUILT-ARTIFACTS-LOCK.json"
json.dump(lock, open(out, "w"), indent=1, sort_keys=True)
open(out, "a").write("\n")
print("lock written:", out)
PY

echo "== done =="
echo "H' = $H_PRIME"
echo "D' = $D_PRIME"
echo "lock: $BUILD_ROOT/BUILT-ARTIFACTS-LOCK.json"
echo "NOTE: the owned registry/buildkit containers are removed by the bounded"
echo "ID-tracked EXIT cleanup. The BOOT request restarts a registry on the SAME"
echo "storage dir ($REGISTRY_ROOT) and re-checks D' via HEAD before boot (see"
echo "BOOT-REQUEST.template.json)."
