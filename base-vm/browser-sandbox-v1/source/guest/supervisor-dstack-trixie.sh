#!/bin/busybox sh
# DSMACK trusted guest supervisor — dstack-derived Debian trixie ARM64 variant,
# runner-join edition.
# Owned adaptation of dstack-smoke-finish/source/guest/supervisor-dstack-trixie.sh
# (prior lane read-only; that lane inherited arm64-compatibility /
# base-vm-foundation logic). Documented deltas for THIS lane — everything else,
# including all fail-closed checks, the rootcontrol trust boundary and the
# vdc-tar + SHA256SUMS external-workload gate, is the prior logic unchanged:
#   R1. vdd is the OWNED EXPORT DISK (fresh ext4 made by the launcher): the
#       runner's receipts/summaries/exported artifacts are written there and
#       survive poweroff. Fail-closed mount (fail 8).
#   R2. Guest network is configured statically for the VERIFIED upstream
#       gvproxy v0.8.9 unconfigured NAT (192.168.127.2/24, gw 192.168.127.1,
#       DNS 192.168.127.1 -- gvproxy's resolver binds only to the gateway IP):
#       the compose runner resolves the pinned child images against the LIVE
#       daemon and pulls missing ones BY DIGEST (the dstack in-guest pull path;
#       the smoke never needed outbound). Fail-closed (fail 9) — a runner pull
#       cannot succeed without it.
#   R3. RUNNER PHASE: instead of composing /run/appcompose/compose.yaml
#       directly, the supervisor invokes the APPROVED runner CLI
#       (/usr/local/bin/dsmack-compose-runner, measured-rootfs bytes) once per
#       external manifest delivered under /run/appcompose/manifests/. Each run:
#       `validate` (contract gate marker), optional `validate-inputs` (when an
#       envelope is delivered), then `run` with the explicit root-only control
#       socket, per-run workspace/control dirs under /run, the delivered base
#       bundle + external admission document, and receipt/summary/artifact
#       paths on the export disk. Per-manifest DSMACK_RUNNER_* markers; the
#       legacy compose.yaml path is NOT used here (the legacy block was
#       replaced by the runner phase — the compose form check above stays as
#       tool evidence).
#   R4. Boundary probe reuses the digest-pinned alpine child the runner
#       already resolved (no floating tag pull), same assertion.
B=/bin/busybox
CLOSURE_FAILED=0
# All shell-interpolated status values are escaped before reaching console.
# Raw closure framing is reserved to the final measured helper alone.
echo() { printf '%s\n' "$*" | python3 -c 'import sys; b=sys.stdin.buffer.read(); sys.stdout.buffer.write(b[:-1].replace(b"\\",b"\\\\").replace(b"\r",b"\\r").replace(b"\n",b"\\n").replace(b"\x00",b"\\0")+b"\n")'; }
diag() { if [ "$#" -gt 0 ]; then python3 -m dsmack_guest_io.closure diagnostic <"$1"; else python3 -m dsmack_guest_io.closure diagnostic; fi; }
# Fixed measured install locations, shared with the installed CLI wrappers.
# Do not inherit caller or workload Python module search paths.
export PYTHONPATH=/usr/local/lib/dsmack/guest-io:/usr/local/lib/dsmack/compose-runner:/usr/local/lib/dsmack/compose-runner/lib
export PYTHONDONTWRITEBYTECODE=1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Module entrypoints consume only measured installed libraries, matching the CLI wrappers.
export PYTHONPATH=/usr/local/lib/dsmack/guest-io:/usr/local/lib/dsmack/compose-runner:/usr/local/lib/dsmack/compose-runner/lib
export DOCKER_HOST=unix:///run/rootcontrol/docker.sock
# No external command error stream inherits the raw console.
exec 2>/run/dsmack-supervisor.stderr
# GIO02: fail() previously `exec poweroff -f` directly, bypassing the shell EXIT
# trap, so ANY fail-closed exit AFTER the private-input disk was extracted left
# the owned 0700/0600 private tree (envelope/broker values) behind. fail() now
# invokes the owned-copy + sentinel + publisher teardown EXPLICITLY before
# poweroff (guarded by command -v so the early mount fails -- before any teardown
# function or private tree exists -- stay silent and safe). The teardown
# functions and the EXIT trap are installed BEFORE the extraction below, so a
# death/cancellation anywhere after extraction is covered on every path.
fail() {
  echo "DSMACK_SUPERVISOR_FAIL $1"
  command -v stop_scratch_probe >/dev/null 2>&1 && stop_scratch_probe
  command -v stop_oci >/dev/null 2>&1 && stop_oci
  command -v stop_broker >/dev/null 2>&1 && stop_broker
  command -v cleanup_private >/dev/null 2>&1 && cleanup_private
  dmesg 2>/dev/null | tail -5 | diag
  exec $B poweroff -f
}
echo "DSMACK_SUPERVISOR_START $(uname -r) $(uname -m)"
mem() { grep MemAvailable /proc/meminfo | awk '{print $2}' | sed 's/^/DSMACK_MEM '"$1"'_MemAvailable_kB /'; }

# /proc, /sys and /dev (with its child mounts) arrive PRE-MOUNTED from the
# initramfs (init mounts them and mount --move's the tree before
# switch_root); mounting over them again returns EBUSY (observed smoke
# try3). Skip only what /proc/mounts already shows mounted; a real mount
# failure is still fail-closed.
mounted() { $B grep -q " $2 " /proc/mounts 2>/dev/null; }
mounted proc /proc || $B mount -t proc proc /proc || fail 1
mounted sysfs /sys || $B mount -t sysfs sysfs /sys || fail 2
mounted devtmpfs /dev || $B mount -t devtmpfs devtmpfs /dev || fail 3
$B mkdir -p /dev/pts /dev/shm
mounted devpts /dev/pts || $B mount -t devpts devpts /dev/pts || fail 4
$B mount -t tmpfs -o mode=1777,size=64M tmpfs /dev/shm || fail 5
$B mkdir -p /sys/fs/cgroup
$B mount -t cgroup2 none /sys/fs/cgroup || fail 6
echo "DSMACK_SUPERVISOR_MOUNTS_OK cgroup2=$(grep cgroup2 /proc/filesystems >/dev/null && echo yes)"
# R5 (try2 root cause): the runner's workload containers carry resource limits
# (cpus/memory) — writing cpu.max/memory.max/pids.max requires the controllers
# to be enabled in the parent's cgroup.subtree_control. A bare cgroup2 mount
# leaves subtree_control EMPTY: unlimited containers (the smoke's) ran fine,
# limited containers failed at runc start ("shim disconnected"). Enable every
# available controller; fail closed if cpu/memory/pids are not then enabled.
for c in $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null); do
  echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
done
enabled=$(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null)
echo "DSMACK_CGROUP_INFO controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null) subtree_enabled=$enabled"
for need in cpu memory pids; do
  echo "$enabled" | grep -qw "$need" || fail 19
done
mem mounts_ok

# Ephemeral docker data: fresh scratch disk (vdb), mkfs'd by the launcher for THIS run.
# The verity squashfs root stays read-only; all docker/container state lives on vdb.
$B mkdir -p /var/lib/docker
$B mount -t ext4 -o noatime /dev/vdb /var/lib/docker || fail 7
echo "DSMACK_SUPERVISOR_SCRATCH_OK $(grep vdb /proc/mounts)"

# R1: owned export disk (vdd): runner receipts/summaries/artifacts (fresh ext4
# per run). The mountpoint must be on the WRITABLE tmpfs /run — the squashfs
# root is read-only, so a new top-level /export directory cannot be created
# (measured: try1 fail 8 "mount: mounting /dev/vdd on /export failed: No such
# file or directory" — the mkdir on the ro root silently did not create it).
EXPORT=/run/export
$B mkdir -p /run/export
$B mount -t ext4 -o noatime /dev/vdd "$EXPORT" || fail 8
echo "DSMACK_SUPERVISOR_EXPORT_OK $(grep vdd /proc/mounts)"

# Container-stack kernel support is built-in in this profile; verify presence,
# do not pretend modules were loaded.
echo "DSMACK_SUPERVISOR_KERNEL_FEATURES overlay=$(grep -w overlay /proc/filesystems | wc -l) ext4=$(grep -w ext4 /proc/filesystems | wc -l) squashfs=$(grep -w squashfs /proc/filesystems | wc -l) cgroup2=$(grep cgroup2 /proc/filesystems >/dev/null && echo yes)"
ip link set lo up 2>/dev/null

# R2 + PORTABLE NETWORKING (guest-io-integration): static network config for
# the digest pulls. The values come from a MEASURED network-profile declaration
# installed in the image (/usr/local/lib/dsmack/net/guest-network.env); its
# values are exactly the VERIFIED upstream gvproxy v0.8.9 unconfigured NAT
# profile (subnet 192.168.127.0/24, gateway + DNS 192.168.127.1), the
# user-pinned transport for BOTH the Zed external-client path and the native
# Mini path. The native backend owns the virtio-net device/transport
# (native-v3-backend ABI); the Zed path attaches QEMU -netdev stream to the
# gvproxy external-client socket. The inline defaults below are a fallback that
# matches the installed profile byte-for-byte; the profile file, when present,
# is sourced and wins. NO egress claim is made here -- this only configures the
# interface the backend provides.
# /etc is read-only, so resolv.conf is a file-over-file bind from /run.
GUEST_NET_PROFILE=/usr/local/lib/dsmack/net/guest-network.env
GUEST_IP_CIDR=192.168.127.2/24; GUEST_GW=192.168.127.1; GUEST_DNS=192.168.127.1; GUEST_IFACE=eth0
if [ -f "$GUEST_NET_PROFILE" ]; then
  . "$GUEST_NET_PROFILE"
  echo "DSMACK_GUEST_NET_PROFILE $GUEST_NET_PROFILE iface=$GUEST_IFACE"
fi
if ip link show "$GUEST_IFACE" >/dev/null 2>&1; then
  # GIO09: do NOT suppress address/route failures with `|| true`. Attempt the
  # add, then VERIFY the resulting state (idempotent: a pre-assigned address or
  # route is fine; a genuinely unconfigured interface fails closed). The check
  # is on the OBSERVED state, not the add command's exit alone.
  ip addr add "$GUEST_IP_CIDR" dev "$GUEST_IFACE" 2>/dev/null
  ip link set "$GUEST_IFACE" up || fail 9
  ip route add default via "$GUEST_GW" 2>/dev/null
  GUEST_IP_ONLY=${GUEST_IP_CIDR%/*}
  ip -4 addr show "$GUEST_IFACE" | grep -qw "$GUEST_IP_ONLY" || {
    echo "DSMACK_GUEST_NET_FAIL_NO_ADDR interface $GUEST_IFACE has no $GUEST_IP_ONLY after configuration"; fail 9; }
  ip route show default | grep -qw "$GUEST_GW" || {
    echo "DSMACK_GUEST_NET_FAIL_NO_ROUTE no default route via $GUEST_GW after configuration"; fail 9; }
  printf 'nameserver %s\n' "$GUEST_DNS" > /run/resolv-guest.conf
  $B mount --bind /run/resolv-guest.conf /etc/resolv.conf || fail 9
  echo "DSMACK_GUEST_NET_OK $(ip -4 addr show "$GUEST_IFACE" | grep inet) gw=$GUEST_GW dns=$GUEST_DNS resolv=$(cat /etc/resolv.conf)"
else
  # No NIC present (e.g. the current native path). Fail closed: the runner's
  # digest pulls cannot succeed without a configured interface -- never a
  # silent "ran without network" success.
  echo "DSMACK_GUEST_NET_FAIL_NO_IFACE interface $GUEST_IFACE absent (native NIC pending; see NATIVE-NETWORK-INTEGRATION)"
  fail 9
fi

# Rootcontrol: dockerd socket + pidfiles live here, mode 0700 root-only. The
# untrusted workload runs inside containers and never sees this path/socket.
$B mkdir -p /run/rootcontrol
chmod 0700 /run/rootcontrol

echo "DSMACK_GUEST_TOOLS_BEGIN"
dockerd --version || fail 10
docker --version || fail 11
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"; echo "DSMACK_COMPOSE_FORM plugin"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"; echo "DSMACK_COMPOSE_FORM binary"
else
  fail 12
fi
$COMPOSE version || fail 12
runc --version | head -2 || fail 13
containerd --version | head -2 || fail 14
python3 --version || fail 17
dsmack-compose-runner --help >/dev/null 2>&1 || fail 18
echo "DSMACK_GUEST_TOOLS_END"

# GIO03: default daemon log level (NOT debug). Debug logging can embed private
# rendered configuration/endpoints; the console stays on tmpfs /run/rootcontrol
# and is NEVER copied to the result disk vdd (see the poweroff path).
dockerd --host=$DOCKER_HOST --data-root=/var/lib/docker \
  --pidfile=/run/rootcontrol/docker.pid --exec-root=/run/rootcontrol \
  --storage-driver=overlay2 --iptables=true --ip-forward=true --ip-masq=true \
  --log-level=info >/run/rootcontrol/dockerd.console 2>&1 &
echo "DSMACK_DOCKERD_PID $!"

i=0
until docker version >/dev/null 2>&1; do
  i=$((i+1)); [ $i -le 360 ] || { echo "DSMACK_DOCKERD_TIMEOUT"; tail -20 /run/rootcontrol/dockerd.console | diag; tail -20 /run/rootcontrol/dockerd.log 2>/dev/null | diag; fail 15; }
  $B usleep 500000
done
echo "DSMACK_DOCKERD_READY"
mem dockerd_ready
docker info 2>/dev/null | grep -E 'Server Version|Storage Driver|Cgroup|Kernel Version|Operating System|Total Memory|CPUs' | diag
docker version --format 'DSMACK_DOCKER_VERSION client={{.Client.Version}} server={{.Server.Version}} os={{.Server.Os}} arch={{.Server.Arch}}' || fail 16

# External workload: vdc is a raw disk holding an uncompressed tar at offset 0.
# APP is the public workload root; it is assigned HERE, before the OCI block
# below that references "$APP/oci-layout" (GIO09: it was previously evaluated
# before APP was set, so a normal launch checked /oci-layout).
APP=/run/appcompose
$B mkdir -p /run/appcompose
cd /run/appcompose || fail 20
# GIO03: ADMIT the vdc archive table-of-contents BEFORE extracting a single
# byte -- the prior `tar xf` extracted the whole archive (as root) with NO
# admission, so a forged vdc could have written a symlink/hardlink/device or an
# absolute/.. path into the tree before any check ran. The admission now reads
# the EXACT member names and typeflags from the tar HEADERS via the MEASURED
# guest-io admitter (dsmack_guest_io.public_toc) instead of text-parsing
# `tar tvf` with `awk '{print $NF}'` -- awk's last field mis-splits a member
# name CONTAINING WHITESPACE and cannot reliably recover dot-prefixed (hidden)
# entries, so a forged name could slip past the text admission yet still be
# extracted by `tar xf`. The structured admitter refuses any non-regular/
# non-dir member, any absolute/.. path, and any top-level segment outside the
# public-channel allowlist (whitespace + hidden entries handled exactly).
GUESTIO=/usr/local/bin/dsmack-guest-io   # measured guest-io CLI (re-affirmed in the OCI/private blocks)
"$GUESTIO" admit-public-toc /dev/vdc >/run/vdc-toc.out 2>&1 || { diag /run/vdc-toc.out; fail 25; }
diag /run/vdc-toc.out
$B tar xf /dev/vdc -C /run/appcompose || fail 21
[ -f SHA256SUMS ] || fail 22
sha256sum -c SHA256SUMS >/dev/null 2>&1 || fail 23
# I/O-CONTINUITY (GIO03): REJECT private channels at the actual guest vdc
# boundary -- defense in depth independent of the host packer. The measured
# public workload must carry NO envelopes/ or broker/ channel; a vdc that
# does (an alternate/forged image whose own SHA256SUMS self-verifies) is
# refused as a WHOLE-channel violation, not merely one credential pathname.
# The ONLY source of private runtime inputs/credentials is the unmeasured vde.
if [ -d /run/appcompose/envelopes ] || [ -d /run/appcompose/broker ]; then
  echo "DSMACK_WORKLOAD_PRIVATE_ON_VDC a private channel (envelopes/ or broker/) is present on the measured vdc; refusing"
  fail 25
fi
if $B grep -Eq '(^|  )(envelopes|broker)/' /run/appcompose/SHA256SUMS 2>/dev/null; then
  echo "DSMACK_WORKLOAD_PRIVATE_IN_INVENTORY the public inventory names a private channel; refusing"
  fail 25
fi
# GIO03: enforce a COMPLETE admitted public-channel inventory at the guest
# boundary -- not merely the ABSENCE of the two reserved private names. Every
# top-level entry on vdc must be one of the known public channels (or the two
# top-level marker files); an unexpected top-level entry (a smuggled channel
# whose own SHA256SUMS self-verifies) is refused as a whole-channel violation.
# GIO03: COMPLETE admitted inventory of the EXTRACTED tree, including
# dot-prefixed (hidden) entries which the prior `for entry in .../*` glob
# missed, and rejecting any symlink/special file ANYWHERE in the tree (link
# types). The dot-globs below enumerate hidden top-level entries; the find
# refuses symlinks/block/char/fifo/socket nodes defense-in-depth (the TOC
# admission already refused them pre-extraction).
if $B find /run/appcompose -mindepth 1 \( -type l -o -type b -o -type c -o -type p -o -type s \) 2>/dev/null | $B head -1 | $B grep -q .; then
  echo "DSMACK_WORKLOAD_NONREGULAR_ENTRY the extracted vdc tree contains a symlink/special file; refusing"; fail 25
fi
for entry in /run/appcompose/* /run/appcompose/.[!.]* /run/appcompose/..?*; do
  [ -e "$entry" ] || continue
  bn=$($B basename "$entry")
  case "$bn" in
    manifests|admission|base-bundle|images|commitments|oci-layout|closure-context|public-inputs|WORKLOAD|SHA256SUMS) ;;
    *) echo "DSMACK_WORKLOAD_UNADMITTED_CHANNEL unexpected public-channel entry '$bn' on the measured vdc; refusing"; fail 25 ;;
  esac
done
echo "DSMACK_WORKLOAD_VERIFIED"
cat /run/appcompose/WORKLOAD 2>/dev/null | diag
CLOSURE_STATE=/run/dsmack-closure-state.json
python3 -m dsmack_guest_io.closure prepare "$CLOSURE_STATE" "$APP/closure-context/context.json" "$APP/manifests" || fail 30
ls -la /run/appcompose | diag

# EXTERNAL-PROVENANCE-JOIN-DECISION: guest component/metadata/mode identities
# are admitted recorded claims, NOT independent measurement of preboot bytes.
# Actual live cmdline and running-root -> active dm-verity geometry/root/device
# remain mandatory. BOTH external verifier and checker must compare the original
# receipt's full boot object to authenticated native facts + external expected
# facts. The guest record alone never proves consumption. Frozen v4 unchanged.
VM_OBS=/run/dsmack-boot-observation.json
VM_OBS_ARG=""
# The current profile records the weakest held-fd mode claim. It is accepted
# externally only when actual authenticated native facts match exactly; never
# upgraded to owned-copy here. No fw_cfg device/kernel support is required.
cp /proc/cmdline /run/live-cmdline.txt 2>/dev/null || true
# Live dm-verity state: dmsetup table carries the active verity target's root
# hash; veritysetup status is a fallback. Captured for the observer's liveness 2.
dmsetup table --target verity > /run/verity-table.txt 2>/dev/null || fail 29
dmsetup info -c --noheadings -o name,major,minor --separator : > /run/dm-info.txt 2>/dev/null || fail 29
diag /run/verity-table.txt
diag /run/dm-info.txt
if "$GUESTIO" boot-observe "$APP/base-bundle" \
     --live-cmdline /run/live-cmdline.txt --verity-table /run/verity-table.txt \
     --loader-mode held-fd \
     --mountinfo /proc/self/mountinfo --dm-info /run/dm-info.txt --out "$VM_OBS" >/run/vm-obs.out 2>&1
then
  diag /run/vm-obs.out
  VM_OBS_ARG="--environment vm --boot-observations $VM_OBS"
else
  diag /run/vm-obs.out
  echo "DSMACK_VM_OBS_FAIL could not gather a real VM boot observation from live kernel state; refusing to fabricate one"
  fail 29
fi

# I/O-CONTINUITY (GIO09): PORTABLE OFFLINE DIGEST-PRESERVING OCI DELIVERY.
# `docker load` + retag is insufficient -- a loaded image has NO RepoDigest, so
# real pull-by-digest / RepoDigest verification cannot be satisfied. When the
# measured vdc carries a content-addressed OCI layout ($APP/oci-layout), the
# MEASURED guest publisher (dsmack_guest_io.oci_publish) verifies it under
# bounds, serves it read-only on loopback, and the guest dockerd pulls BY DIGEST
# so the RepoDigest D is preserved -- no host Docker, no public upload, and no
# caller-provided helper from vdc is ever executed. The same measured code runs
# on Zed and Mini (reconciled endpoint = 127.0.0.1:<port>, not 10.0.2.2:5005).
GUESTIO=/usr/local/bin/dsmack-guest-io
SCRATCH_PROBE_PID=""
stop_scratch_probe() {
  [ -n "$SCRATCH_PROBE_PID" ] || return 0
  kill -TERM "$SCRATCH_PROBE_PID" 2>/dev/null
  i=0
  while kill -0 "$SCRATCH_PROBE_PID" 2>/dev/null; do
    i=$((i+1)); [ $i -le 40 ] || { kill -KILL "$SCRATCH_PROBE_PID" 2>/dev/null; CLOSURE_FAILED=1; break; }
    $B usleep 100000
  done
  wait "$SCRATCH_PROBE_PID"
  SCRATCH_PROBE_EXIT=$?
  SCRATCH_PROBE_PID=""
  if python3 -c 'import json; d=json.load(open("/run/rootcontrol/scratch-probe.json")); assert d["schema"]=="dsmack.scratch-samples/1" and d["termination"]=="stopped" and d["device_bytes"]==1073741824 and d["samples"]>0'; then
    diag /run/rootcontrol/scratch-probe.json
    echo "DSMACK_SCRATCH_STATS_OK sampled-not-instantaneous"
  else
    echo "DSMACK_SCRATCH_STATS_UNAVAILABLE exit=$SCRATCH_PROBE_EXIT"
    [ ! -f /run/rootcontrol/scratch-probe.err ] || diag /run/rootcontrol/scratch-probe.err
  fi
}
python3 -m dsmack_guest_io.scratch_probe >/run/rootcontrol/scratch-probe.json 2>/run/rootcontrol/scratch-probe.err &
SCRATCH_PROBE_PID=$!
OCI_PID=""
OCI_LAYOUT="$APP/oci-layout"
stop_oci() {
  [ -n "$OCI_PID" ] || return 0
  kill -TERM "$OCI_PID" 2>/dev/null
  i=0
  while kill -0 "$OCI_PID" 2>/dev/null; do
    i=$((i+1)); [ $i -le 40 ] || { kill -KILL "$OCI_PID" 2>/dev/null; break; }
    $B usleep 250000
  done
  if kill -0 "$OCI_PID" 2>/dev/null; then CLOSURE_FAILED=1; else wait "$OCI_PID" 2>/dev/null; fi
  echo "DSMACK_OCI_PUBLISHER_TORNDOWN $OCI_PID"; OCI_PID=""
}
if [ -f "$OCI_LAYOUT/index.json" ]; then
  echo "DSMACK_OCI_DELIVERY layout=$OCI_LAYOUT (measured offline publisher)"
  # Bounded verification BEFORE serving; fail closed on refusal.
  "$GUESTIO" oci-verify "$OCI_LAYOUT" >/run/oci-verify.out 2>&1 || { diag /run/oci-verify.out; fail 26; }
  diag /run/oci-verify.out
  OCI_READY=/run/oci.ready; rm -f "$OCI_READY"
  # Loopback publisher on 5005 (reconciled endpoint; workload refs render
  # 127.0.0.1:5005/<name>@<digest>, GIO09).
  "$GUESTIO" oci-serve "$OCI_LAYOUT" --host 127.0.0.1 --port 5005 --ready-file "$OCI_READY" >/run/oci-serve.err 2>&1 &
  OCI_PID=$!
  i=0
  until [ -f "$OCI_READY" ]; do
    i=$((i+1)); [ $i -le 120 ] || { echo "DSMACK_OCI_PUBLISHER_FAIL not-ready"; tail -5 /run/oci-serve.err | diag; stop_oci; fail 26; }
    kill -0 "$OCI_PID" 2>/dev/null || { echo "DSMACK_OCI_PUBLISHER_FAIL exited-early"; tail -5 /run/oci-serve.err | diag; OCI_PID=""; fail 26; }
    $B usleep 250000
  done
  OCI_HOSTPORT=$(cat "$OCI_READY")
  echo "DSMACK_OCI_PUBLISHER_READY $OCI_HOSTPORT"
  # Pull every ref BY DIGEST and confirm the RepoDigest is preserved exactly.
  grep '^DSMACK_OCI_REF ' /run/oci-verify.out | while read -r _tag name digest; do
    ref="$OCI_HOSTPORT/$name@$digest"
    echo "DSMACK_SCRATCH_BEFORE_PULL"
    df -Pk /var/lib/docker
    echo "DSMACK_OCI_PULL $ref"
    docker pull "$ref" >/run/oci-pull.out 2>&1 || { echo "DSMACK_OCI_PULL_FAIL $ref"; exit 24; }
    got=$(docker image inspect "$ref" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null | grep "@$digest" | head -1)
    [ -n "$got" ] || { echo "DSMACK_OCI_REPODIGEST_FAIL $ref (RepoDigest $digest not preserved)"; exit 24; }
    echo "DSMACK_SCRATCH_AFTER_PULL"
    df -Pk /var/lib/docker
    echo "DSMACK_OCI_REPODIGEST_OK $got"
    python3 -m dsmack_guest_io.oci_identity "$ref" >/run/oci-runner-identity.json 2>/run/oci-runner-identity.err || { echo "DSMACK_OCI_RUNNER_IDENTITY_FAIL"; exit 24; }
    echo "DSMACK_OCI_RUNNER_IDENTITY_OK $ref"
  done || fail 24
  # GIO09 (repair3): DO NOT stop the publisher here. The rendered product
  # manifests resolve 127.0.0.1:5005/dsmack-claude-harness@<D> (the SAME
  # repository the staged index annotation is normalized to, and the SAME the
  # pre-pull above fetched), and the guest daemon may pull BY DIGEST during the
  # runner's run phase. The loopback publisher MUST stay available until the
  # runner has resolved every image; it is torn down AFTER the runner loop and,
  # unconditionally on any exit path, via the EXIT trap. Both reviewer-accepted
  # conditions now hold together: the exact required repository@digest is
  # pre-pulled AND the publisher is kept alive until the runner resolves.
  echo "DSMACK_OCI_PUBLISHER_KEPT_ALIVE pid=$OCI_PID through-runner-phase"
else
  # TRANSITIONAL fallback ONLY (honestly labeled): a plain docker-load path for
  # images delivered as *.tar. This does NOT establish RepoDigest and is NOT the
  # product delivery -- the real build ships the OCI layout above. Kept so the
  # current Zed path still functions until the layout is produced.
  echo "DSMACK_OCI_DELIVERY_ABSENT no $OCI_LAYOUT; using transitional docker-load (NO RepoDigest preserved)"
  for img in /run/appcompose/images/*.tar; do
    [ -e "$img" ] || continue
    echo "DSMACK_DOCKER_LOAD_TRANSITIONAL $img"
    docker load -i "$img" >/run/oci-load.out 2>&1 || fail 24
  done
fi

# R3: RUNNER PHASE — the approved runner CLI over the delivered external
# manifests (image pulls by exact digest happen inside the guest daemon).
RUNNER=/usr/local/bin/dsmack-compose-runner
# R02/S03: the per-run credential sentinel is guest-root/broker-side userland
# (NOT the workload, NOT the signed app). It is MEASURED rootfs bytes installed
# by the build (JOIN-4); there is NO ambient executable override — the prior
# DSMACK_SENTINEL env override is removed so an attacker-controlled environment
# cannot substitute the credential-holding process.
SENTINEL=/usr/local/lib/dsmack/sentinel/harness/sentinel/sentinel.py
# APP was assigned earlier (before the OCI block); re-affirm for readability.
mkdir -p /run/dsmack-runs /run/dsmack-control
# PRIVATE DIAGNOSTICS OFF THE RESULT DISK: the runner/sentinel verbose
# stdout/stderr (status JSON, value-free error codes, sentinel errors) are
# captured under tmpfs /run, NOT on the exported result disk vdd. Only the
# AUTHORITATIVE results -- receipt.json, summary.json and the complete output
# export tree (stdout/stderr + artifact bytes + EXPORT-COMPLETE) -- are written
# to $EXPORT. This keeps any incidental diagnostic bytes off the result image.
DIAG=/run/dsmack-diag
mkdir -p "$DIAG"; chmod 0700 "$DIAG"

# I/O-CONTINUITY DELTA (guest-io-integration): the default-uncommitted runtime
# envelopes (env/files/stdin/user_config) and the per-run broker channel
# (broker-config + 0600 credential) travel on the OPTIONAL UNMEASURED
# private-input disk vde -- NEVER on the measured vdc public workload. vde is a
# bounded ustar image; a REAL safe parser (MEASURED guest bytes,
# dsmack_guest_io.private_transport) admits the WHOLE transport before writing a
# byte, then extracts into a FRESH 0700 private tree with O_EXCL 0600 files.
# This is NOT `tar xf` and NOT a root tar extraction; there is NO
# measured-private fallback (the supervisor NEVER reads envelopes/broker from
# $APP/vdc). vde is optional (credential-free, uncommitted runs carry none); a
# PRESENT-but-malformed vde fails CLOSED (fail 28), never a silent skip.
GUESTIO=/usr/local/bin/dsmack-guest-io
PRIV=/run/dsmack-private
# GIO02: CHECKED cleanup of the private-input owned copies on EVERY exit
# (success, failure, cancellation) -- not a success-path-only unchecked `rm`.
# After removal the tree's ABSENCE is verified; a residue is reported with a
# fail marker (never a silent success). Idempotent: safe to call more than once
# (the EXIT trap, fail() and the normal path all call it). DEFINED + TRAPPED
# HERE, BEFORE the extraction below -- the trap was previously installed AFTER
# extraction, so a failure between extraction and the trap leaked the private
# tree; fail()'s `exec poweroff` also bypassed the EXIT trap entirely (fail()
# now calls cleanup_private explicitly, guarded by command -v).
PRIVATE_CLEAN_FAILED=0
cleanup_private() {
  [ -n "$PRIV" ] || return 0
  [ -e "$PRIV" ] || return 0
  rm -rf "$PRIV" 2>/dev/null
  if [ -e "$PRIV" ]; then
    PRIVATE_CLEAN_FAILED=1
    echo "DSMACK_PRIVATE_INPUT_CLEAN_FAIL owned private-input copies could not be removed ($PRIV); result not confirmed residue-free"
  else
    echo "DSMACK_PRIVATE_INPUT_CLEANED owned private-input copies removed (verified absent)"
  fi
}
# R02/GIO02: never leak a sentinel, an OCI publisher OR a private-input tree if
# the supervisor dies mid-run. stop_oci is defined above; stop_broker is defined
# with the broker helpers below (both resolved when the trap fires).
trap 'stop_oci; stop_broker; cleanup_private' EXIT
if [ -b /dev/vde ]; then
  rm -rf "$PRIV"
  "$GUESTIO" extract-private /dev/vde "$PRIV" > /run/private-extract.out 2>&1 || fail 28
  echo "DSMACK_PRIVATE_INPUT_MOUNTED vde (unmeasured; owned 0700/0600 copies)"
else
  PRIV=""
  echo "DSMACK_PRIVATE_INPUT_ABSENT no vde (credential-free/uncommitted runs only)"
fi
runner_rc_total=0; runner_n=0
BROKER_PID=""; BROKER_ENDPOINT=""

# R02: does this manifest REQUIRE a credential broker? (credentials.required)
broker_required() {
  python3 - "$1" <<'PY'
import json,sys
try:
    m=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(2)
sys.exit(0 if (m.get("credentials") or {}).get("required") else 1)
PY
}

# R02/S03: launch the per-run sentinel AUTHORIZED BY THE VALIDATED MANIFEST,
# derive the workload-reachable endpoint, and set BROKER_ENDPOINT. Broker
# inputs are delivered on the PRIVATE vde disk under $PRIV/broker/<name>/ (a
# 0600 credential file + broker-config.json binding listen_port/workload_host/
# provider_route/ca_bundle/auth_mode — NO token: the per-run capability token
# is freshly generated HERE). The broker-config AND the credential are OFF the
# measured vdc; the credential NEVER reaches the runner or the workload, and is
# NEVER listed in any public checksum inventory. Honest explicit dependency: if
# a credential is REQUIRED but not delivered (no vde, or missing entry), emit
# DSMACK_BROKER_MISSING and return nonzero (does NOT block credential-free
# manifests).
start_broker() {  # $1=name $2=validated-manifest-path
  BROKER_ENDPOINT=""; BROKER_PID=""
  if [ -z "$PRIV" ]; then
    echo "DSMACK_BROKER_MISSING $1 (no vde private-input disk; credential is a live dependency)"
    return 1
  fi
  bdir="$PRIV/broker/$1"; cfg="$bdir/broker-config.json"
  if [ ! -f "$cfg" ] || [ ! -f "$bdir/credential" ]; then
    echo "DSMACK_BROKER_MISSING $1 (no delivered broker inputs on vde; credential is a live dependency)"
    return 1
  fi
  # S03: AUTHORIZATION TARGET is the VALIDATED manifest (the runner has already
  # validated these bytes rc=0): the sentinel may only receive the credential
  # for exactly the provider route + credential profile the admitted manifest
  # declares, over the MEASURED image CA bundle. Comparing broker-config to
  # itself establishes nothing; comparing it to the manifest establishes that
  # a substituted HTTPS route can never be handed this run's credential.
  mroute=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["credentials"]["adapter"]["provider_route"])' "$2" 2>/dev/null) \
    || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 manifest-route-unreadable"; return 1; }
  mprofile=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["credentials"]["adapter"]["profile"])' "$2" 2>/dev/null) \
    || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 manifest-profile-unreadable"; return 1; }
  case "$mprofile" in
    claude-subscription/1) mmode=claude-subscription ;;
    claude-api-key/1)      mmode=api-key ;;
    *) echo "DSMACK_BROKER_POLICY_MISMATCH $1 unsupported-profile"; return 1 ;;
  esac
  port=$(python3 -c 'import json,sys;print(int(json.load(open(sys.argv[1]))["listen_port"]))' "$cfg" 2>/dev/null) || return 1
  route=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["provider_route"])' "$cfg" 2>/dev/null) || return 1
  ca=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ca_bundle"])' "$cfg" 2>/dev/null) || return 1
  whost=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["workload_host"])' "$cfg" 2>/dev/null) || return 1
  mode=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("auth_mode","api-key"))' "$cfg" 2>/dev/null) || mode=api-key
  [ "$route" = "$mroute" ] || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 route-not-manifest-route"; return 1; }
  [ "$mode" = "$mmode" ] || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 auth-mode-not-manifest-profile"; return 1; }
  [ "$ca" = "/etc/ssl/certs/ca-certificates.crt" ] || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 ca-not-measured-image-bundle"; return 1; }
  # S03: the staged config must NOT carry a capability token, and the
  # credential bytes must NOT appear in the public checksum inventory.
  python3 -c 'import json,sys;sys.exit(1 if "token" in json.load(open(sys.argv[1])) else 0)' "$cfg" \
    || { echo "DSMACK_BROKER_POLICY_MISMATCH $1 staged-config-carries-token"; return 1; }
  if grep -q "broker/$1/credential" "$APP/SHA256SUMS" 2>/dev/null; then
    echo "DSMACK_BROKER_POLICY_MISMATCH $1 credential-listed-in-checksum-inventory"; return 1
  fi
  # S03: FRESH per-run capability token, generated here at run scope — never
  # staged, never reused across runs, dies with the sentinel instance.
  token=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))') || return 1
  ready="/run/broker-$1.ready"; rm -f "$ready"
  # --broker-config re-binds route+CA to the staged config (sentinel refuses a
  # mismatch); the supervisor has ALREADY bound that config to the validated
  # manifest above, so the chain is manifest -> config -> sentinel arguments.
  # Credential read once from a 0600 file; teardown on SIGTERM.
  python3 "$SENTINEL" --run-id "guest-$1-$$" --token "$token" \
    --listen-host 0.0.0.0 --listen-port "$port" \
    --provider-route "$route" --ca-bundle "$ca" --auth-mode "$mode" \
    --credential-file "$bdir/credential" --broker-config "$cfg" \
    --ready-file "$ready" >"$DIAG/$1.sentinel.err" 2>&1 &
  BROKER_PID=$!
  i=0
  until [ -f "$ready" ]; do
    i=$((i+1)); [ $i -le 120 ] || { echo "DSMACK_BROKER_FAIL $1 sentinel-not-ready"; kill "$BROKER_PID" 2>/dev/null; BROKER_PID=""; return 1; }
    kill -0 "$BROKER_PID" 2>/dev/null || { echo "DSMACK_BROKER_FAIL $1 sentinel-exited-early"; BROKER_PID=""; return 1; }
    $B usleep 250000
  done
  BROKER_ENDPOINT="http://$whost:$port/$token"
  echo "DSMACK_BROKER_READY $1 port=$port auth_mode=$mode"
  return 0
}

# R02: teardown — credential + token die with the instance (SIGTERM, then KILL).
stop_broker() {
  [ -n "$BROKER_PID" ] || return 0
  kill -TERM "$BROKER_PID" 2>/dev/null
  i=0
  while kill -0 "$BROKER_PID" 2>/dev/null; do
    i=$((i+1)); [ $i -le 40 ] || { kill -KILL "$BROKER_PID" 2>/dev/null; break; }
    $B usleep 250000
  done
  if kill -0 "$BROKER_PID" 2>/dev/null; then CLOSURE_FAILED=1; else wait "$BROKER_PID" 2>/dev/null; fi
  echo "DSMACK_BROKER_TORNDOWN $BROKER_PID"
  BROKER_PID=""; BROKER_ENDPOINT=""
}
# GIO02: cleanup_private + the EXIT trap are installed EARLIER (before the
# private-input extraction) so a failure/cancellation anywhere after extraction
# is covered on every path, including fail()'s exec-poweroff path.

for mf in $APP/manifests/*.app-compose.json; do
  [ -e "$mf" ] || fail 27
  name=$(basename "$mf" .app-compose.json)
  python3 -c 'from dsmack_guest_io.closure import selector; import sys; selector(sys.argv[1])' "$name" || fail 30
  runner_n=$((runner_n+1))
  echo "DSMACK_RUNNER_BEGIN $name manifest_sha256=$(sha256sum "$mf" | awk '{print $1}')"
  $RUNNER validate "$mf" >"$DIAG/$name.validate.out" 2>&1
  vrc=$?
  echo "DSMACK_RUNNER_VALIDATE $name rc=$vrc"
  [ $vrc -eq 0 ] || { runner_rc_total=1; echo "DSMACK_RUNNER_EXIT $name rc=$vrc phase=validate"; continue; }
  ENVELOPE_ARG=""
  # Versioned measured public data for credential-free browser preset only.
  # The helper rejects competing private input, arbitrary public env/broker data,
  # unknown channel entries and invalid manifest/envelope binding before launch.
  PUBLIC_ENVELOPE=$(python3 -m dsmack_guest_io.public_inputs "$APP/public-inputs" "$mf" "$PRIV") || fail 28
  if [ -n "$PUBLIC_ENVELOPE" ]; then
    ENVELOPE_ARG="--envelope $PUBLIC_ENVELOPE"
    $RUNNER validate-inputs "$mf" "$PUBLIC_ENVELOPE" >"$DIAG/$name.validate-inputs.out" 2>&1
    irc=$?
    echo "DSMACK_RUNNER_VALIDATE_PUBLIC_INPUTS $name rc=$irc"
    [ $irc -eq 0 ] || { runner_rc_total=1; echo "DSMACK_RUNNER_EXIT $name rc=$irc phase=validate-public-inputs"; continue; }
  elif [ -n "$PRIV" ] && [ -f "$PRIV/envelopes/$name.envelope.json" ]; then
    ENVELOPE_ARG="--envelope $PRIV/envelopes/$name.envelope.json"
    $RUNNER validate-inputs "$mf" "$PRIV/envelopes/$name.envelope.json" >"$DIAG/$name.validate-inputs.out" 2>&1
    irc=$?
    echo "DSMACK_RUNNER_VALIDATE_INPUTS $name rc=$irc"
    [ $irc -eq 0 ] || { runner_rc_total=1; echo "DSMACK_RUNNER_EXIT $name rc=$irc phase=validate-inputs"; continue; }
  fi
  # R02: credential-required manifests get a per-run sentinel + --broker-endpoint.
  BROKER_ARG=""
  if broker_required "$mf"; then
    if start_broker "$name" "$mf"; then
      BROKER_ARG="--broker-endpoint $BROKER_ENDPOINT"
    else
      # Honest explicit dependency: let the runner fail closed (broker-unavailable)
      # for THIS manifest; the credential-free manifests are unaffected.
      echo "DSMACK_RUNNER_BROKER_UNAVAILABLE $name"
    fi
  fi
  RUNID="guest-$name-$$"
  # I/O-CONTINUITY (GIO04): --export-outputs is the SHARED result-image ROOT
  # ($EXPORT). The runner writes the CANONICAL guest layout the smoke consumer
  # consumes DIRECTLY: <root>/<name>/receipt.json and
  # <root>/<name>/outputs/{index.json,streams/<s>,artifacts/<name>,
  # EXPORT-COMPLETE} with the per-selector marker written LAST. The selector is
  # the MANIFEST NAME, so each manifest writes its OWN <name>/ subtree under
  # the one shared root (multi-selector completion). The exporter is the SOLE
  # writer of the result disk; the receipt/summary/legacy-artifact copies go to
  # $DIAG (tmpfs, OFF the result disk) so they cannot collide with the
  # exporter's canonical tree or leak diagnostics onto vdd.
  $RUNNER run "$mf" $ENVELOPE_ARG $BROKER_ARG $VM_OBS_ARG \
    --run-id "$RUNID" \
    --daemon-endpoint unix:///run/rootcontrol/docker.sock \
    --workspace-root /run/dsmack-runs \
    --control-dir /run/dsmack-control \
    --base-bundle "$APP/base-bundle" \
    --admission "$APP/admission/base-admission.json" \
    --receipt-out "$DIAG/$name.receipt.json" \
    --summary-out "$DIAG/$name.summary.json" \
    --export-artifacts "$DIAG/$name.artifacts" \
    --export-outputs "$EXPORT" >"$DIAG/$name.run.out" 2>"$DIAG/$name.run.err"
  rrc=$?
  # R02: tear the per-run sentinel down immediately after the run (success OR fail).
  stop_broker
  [ $rrc -eq 0 ] || runner_rc_total=1
  echo "DSMACK_RUNNER_EXIT $name rc=$rrc phase=run"
  # R06: record the receipt the EXPORTER actually wrote on the result disk
  # (acceptance checks exactly these canonical bytes).
  if [ $rrc -eq 0 ] && [ -f "$EXPORT/$name/receipt.json" ]; then
    echo "DSMACK_RECEIPT_WRITTEN $name sha256=$(sha256sum "$EXPORT/$name/receipt.json" | awk '{print $1}')"
  fi
  # I/O-CONTINUITY (GIO05): a rc=0 run MUST have produced the per-selector
  # outputs/EXPORT-COMPLETE marker with the EXACT marker bytes
  # (dsmack-export/1\n, 16 bytes). A command-substitution comparison strips the
  # trailing newline, so we compare BYTE-EXACTLY (cmp against the printf'd
  # expected bytes). A missing/wrong-byte marker means the output export did
  # not durably finish and is reported as a FAIL marker so machine-enforced
  # acceptance rejects (no false complete).
  if [ $rrc -eq 0 ]; then
    marker="$EXPORT/$name/outputs/EXPORT-COMPLETE"
    marker_expect=/run/dsmack-export-marker.expect
    printf 'dsmack-export/1\n' > "$marker_expect"
    if [ -f "$marker" ] && $B cmp -s "$marker" "$marker_expect"; then
      idxsha=$(sha256sum "$EXPORT/$name/outputs/index.json" | awk '{print $1}')
      # Only a successful actual exporter may contribute closure facts.
      python3 -m dsmack_guest_io.closure collect "$CLOSURE_STATE" "$EXPORT" "$name" "$RUNID" || runner_rc_total=1
      echo "DSMACK_EXPORT_COMPLETE $name index_sha256=$idxsha"

    else
      runner_rc_total=1
      echo "DSMACK_EXPORT_FAIL_INCOMPLETE $name missing/invalid outputs/EXPORT-COMPLETE marker (output export did not finish)"
    fi
  fi
done
[ $runner_n -gt 0 ] || fail 27
echo "DSMACK_RUNNER_DONE manifests=$runner_n failures=$runner_rc_total"
mem runner_done
# GIO09 (repair3): the runner has resolved every image; the loopback OCI
# publisher is no longer needed, so tear it down now (it is also torn down
# unconditionally by the EXIT trap). Keeping it alive only through the runner
# phase keeps the delivery path reachable exactly when the daemon pulls.
stop_oci

# Trusted-side check that the socket works (docker version already proved it); untrusted-side
# check that a container cannot see it. The container gets no bind mounts, so /run/rootcontrol
# does not exist in its mount namespace.
# F08: the boundary probe is a REQUIRED acceptance check, NEVER a silent skip.
# Reuse a digest-pinned child the runner already resolved (no floating-tag
# pull): prefer alpine, else any @sha256:-pinned image present. If NO pinned
# child is available, or the probe container cannot execute, emit a FAIL
# marker so machine-enforced acceptance fails closed (boundary_ok=false).
PROBE_PIN=$(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep '^alpine@sha256:' | head -1)
[ -n "$PROBE_PIN" ] || PROBE_PIN=$(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep '@sha256:' | grep -v '^<none>' | head -1)
echo "DSMACK_BOUNDARY_PROBE_BEGIN"
if [ -n "$PROBE_PIN" ]; then
  # R06: capture the ACTUAL `docker run` exit status. Piping straight into sed
  # masks the Docker exit code (the pipeline reports sed's status), so a probe
  # container that failed to execute would have looked clean. Redirect to a
  # file, read $? BEFORE the sed, and fail closed on a nonzero docker rc.
  #
  # TRUSTED-ENTRYPOINT (guest-io-integration): a harness/child image may define
  # its OWN ENTRYPOINT, which would otherwise PREPEND to our `sh -c ...` and
  # swallow the probe (the real test never runs, yet the container can exit 0 ->
  # a FALSE clean). We force a KNOWN trusted shell with an explicit
  # `--entrypoint /bin/sh` so the probe script is what actually executes, and we
  # require a per-run EXEC-PROOF token in the output: if `/bin/sh` is missing or
  # the script did not actually run, we fail CLOSED (never a silent skip).
  PROBE_OUT=/run/boundary-probe.out
  PROBE_TOKEN="DSMACK_BOUNDARY_PROBE_EXEC_OK_$$"
  docker run --rm --network none --entrypoint /bin/sh "$PROBE_PIN" -c \
    'echo '"$PROBE_TOKEN"'; if [ -e /run/rootcontrol/docker.sock ]; then echo DSMACK_BOUNDARY_FAIL_SOCKET_VISIBLE; else echo DSMACK_BOUNDARY_OK_untrusted_container_cannot_see_rootcontrol_socket; fi; ls /run 2>&1 | head -5' >"$PROBE_OUT" 2>&1
  prc=$?
  diag "$PROBE_OUT"
  echo "DSMACK_BOUNDARY_PROBE_RC $prc"
  if [ $prc -ne 0 ]; then
    echo 'DSMACK_BOUNDARY_FAIL_PROBE_EXEC the boundary probe container exited nonzero (trusted shell missing or run failed)'
  elif ! grep -qx "$PROBE_TOKEN" "$PROBE_OUT"; then
    # The container exited 0 but our trusted-shell script never produced its
    # exec-proof token -- an image ENTRYPOINT (or absent /bin/sh) swallowed it.
    echo 'DSMACK_BOUNDARY_FAIL_PROBE_NOEXEC the trusted shell did not execute the probe (exec-proof token absent)'
  elif grep -qx DSMACK_BOUNDARY_OK_untrusted_container_cannot_see_rootcontrol_socket "$PROBE_OUT" && ! grep -q DSMACK_BOUNDARY_FAIL "$PROBE_OUT"; then
    echo 'DSMACK_BOUNDARY_OK_verified'
  else
    echo 'DSMACK_BOUNDARY_FAIL_SOCKET_VISIBLE_OR_INVALID'
  fi
else
  echo 'DSMACK_BOUNDARY_FAIL_NO_PINNED_CHILD no digest-pinned child available for the boundary probe'
fi
echo 'DSMACK_BOUNDARY_PROBE_END'

echo "DSMACK_SUPERVISOR_DONE runner_failures=$runner_rc_total"
cd /
# I/O-CONTINUITY DELTA: explicit cleanup of the private-input owned copies
# (envelope/broker values). They are retained NOWHERE -- never copied to the
# result disk vdd and never echoed to the console. The vde disk itself is
# UNMEASURED and read-only; destroying the owned 0700 tree removes the only
# writable copy inside the guest before poweroff.
# GIO02: CHECKED private-tree cleanup (verifies absence; fail marker on
# residue). The EXIT trap also calls this, so death/cancellation mid-run is
# covered too; calling it here makes the success-path cleanup explicit and
# checked rather than a bare unchecked `rm`.
cleanup_private
# Private diagnostics (tmpfs) are destroyed too; they never reached vdd.
if [ -d "$DIAG" ]; then
  rm -rf "$DIAG"
  [ ! -e "$DIAG" ] || runner_rc_total=1
fi
[ "$PRIVATE_CLEAN_FAILED" -eq 0 ] || runner_rc_total=1
stop_oci
stop_broker
stop_scratch_probe
docker ps -a 2>/dev/null | diag
# GIO03: the daemon console may embed private rendered values -- it is NEVER
# copied to the result disk vdd (the prior "$EXPORT/RESULT-dockerd.console"
# copy is removed). It stays on tmpfs (/run/rootcontrol) and dies at poweroff.
# GIO05: CHECKED synchronization + UNMOUNT of the result disk before poweroff.
# sync then unmount vdd; an unmount failure means the result image may not be
# durably/cleanly closed, so we do NOT power off reporting success -- we emit a
# fail marker (acceptance fails closed; no false "complete export").
cd /
# Failure is permanently latched, including surviving-marker cases.
[ "$CLOSURE_FAILED" -eq 0 ] || runner_rc_total=1
if [ "$runner_rc_total" -eq 0 ]; then
  python3 -m dsmack_guest_io.closure close "$CLOSURE_STATE" "$EXPORT" || {
    echo "DSMACK_EXPORT_CLOSURE_FAIL"; exec $B poweroff -f;
  }
  echo "DSMACK_EXPORT_UNMOUNT_OK vdd unmounted cleanly"
else
  echo "DSMACK_EXPORT_CLOSURE_REFUSED prior publication or cleanup failure"
fi
echo "DSMACK_POWERING_OFF"
exec $B poweroff -f
fail 99
