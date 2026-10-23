#!/usr/bin/env python3
"""Bounded engineering QEMU reproduction, not hardware attestation.

Uses 4096 MiB/1 vCPU, admitted blank templates and immutable descriptor-loader
image. The loader's sealed component copies feed QEMU and explicit fw_cfg boot
observations. Actual live guest cmdline/root mapper state is independently
checked. Overall acceptance needs exact exported bytes plus positive supervisor
closure; host console evidence here is engineering only. Production acceptance
requires the authenticated native console/result envelope in the external checker.

Host staging GC is deferred without destructive pathname operations; private
residue is explicitly retained. Residue-free policies refuse before launch.
Guest-private cleanup, writer shutdown and process/FD quiescence remain required.
"""
import tempfile
import argparse, fcntl, hashlib, json, os, re, shutil, signal, stat, subprocess, sys, tarfile, time, threading

LANE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BATCH = '/home/amiller/dsmack-sprints/attested-runner-20261019/joined-sprint/app-compose-20261020'
QEMU_IMAGE = 'dsmack-arm64/qemu-aarch64:ubu22.04'          # arm64 lane's container (reused)
BUILDER_IMAGE = 'dsmack-dstack-arm64/builder:trixie-20260721'
# F04: pin the host execution images by ID; a mutable tag that no longer
# resolves to the reviewed bytes fails closed (no silent substitution).
QEMU_IMAGE_ID = 'sha256:d16bf43bb29acfa7b77fbc1b6703842044c04e1cf75282dab7f9e488f6f70511'
DESCRIPTOR_IMAGE_ID = 'sha256:a0c10b85e98b950c1b5a3efc7c6099a73e500446483bd0588f9ca749990b6672'
DESCRIPTOR_HELPER_SHA256 = '72a9c9916d33cd9eb6b549c571ddab968c840c6c8b7cc398e5955132339b4e3a'
BUILDER_IMAGE_ID = 'sha256:df98b52ea039e4bbb40c52ca51f869c908d687ab5ea4154e1678afd0da0a04e9'
SHARED_LOCK = os.path.join(BATCH, 'zed-vm.lock')

# The owning lane's promoted bundle default (referenced in place, never
# mutated; the four boot-consumed files are STAGED before consumption).
BUNDLE_DIR = '/data/amiller/dsmack/attested-runner-20261020/dstack-runner-join/build/artifacts'
BUNDLE_PIN = '46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2'
BUNDLE_FILES = ['Image', 'config-6.18.40-dstack', 'rootfs.squashfs.verity', 'initramfs.cpio.gz',
                'metadata.json', 'sha256sum.txt', 'digest.txt', 'artifact-manifest.json']
# The four files QEMU/admission actually CONSUME at boot (staged + verified).
BOOT_CONSUMED = ['Image', 'initramfs.cpio.gz', 'rootfs.squashfs.verity', 'metadata.json']
# Workload base_vm declaration this engineering launch must match (F03).
DECLARED_VCPUS = 1
DECLARED_MEM_MIB = 4096

# I/O-CONTINUITY DELTA (guest-io-integration): the measured vdc PUBLIC workload
# carries only public declarations, admission + base bundle, OCI assets and
# selected commitment declarations. The default-uncommitted runtime envelopes
# and the per-run broker channel (config + credential) move to the OPTIONAL
# UNMEASURED vde private-input disk. The guest reads vde through a REAL safe
# bounded parser (dsmack_guest_io.private_transport), never `tar xf`.
# GIO09: oci-layout is a PUBLIC measured channel -- the content-addressed OCI
# image layout the in-guest publisher serves on loopback must be PACKED onto
# vdc (it was previously omitted, so supplied layout bytes never reached the
# guest and the delivery path stayed disconnected).
PUBLIC_CHANNELS = ('manifests', 'admission', 'base-bundle', 'images', 'commitments', 'oci-layout', 'closure-context')
PRIVATE_CHANNELS = ('envelopes', 'broker')
# vde image byte cap (small: envelopes + broker channel only).
MAX_PRIVATE_BYTES = 64 * 1024 * 1024

# I/O-CONTINUITY (GIO02): the host packer shares the guest parser's bounds and
# validates the completed private transport with the ACTUAL measured guest
# reader before it is written -- the host never packs a vde the guest would
# refuse, and the limits are one source of truth, not two.
_RUNNER_CONTENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'runner-content')
if _RUNNER_CONTENT not in sys.path:
    sys.path.insert(0, _RUNNER_CONTENT)
from dsmack_guest_io import private_transport as _pt  # noqa: E402
from dsmack_guest_io import pt_limits as _ptl  # noqa: E402


def _safe_source_stat(path):
    """lstat a source path, refusing symlinks, non-regular files AND hard-linked
    files (GIO02/GIO03): a public- or private-channel alias to other content --
    whether a symlink OR a hardlink -- is never followed, copied or hashed."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SystemExit('I/O-continuity: refusing a non-regular / symlinked source entry %r '
                         '(no symlink following, no cross-channel alias)' % path)
    if st.st_nlink != 1:
        raise SystemExit('I/O-continuity: refusing a hard-linked source entry %r (nlink=%d; a '
                         'hardlink is a cross-channel alias to other content)' % (path, st.st_nlink))
    return st


def _open_admitted_root(base_dir):
    """GIO03: open and RETURN the admitted root directory descriptor for
    ``base_dir``, traversing it component-by-component from the real filesystem
    root ("/") with O_NOFOLLOW so NO alias in its ancestry (including base_dir
    itself being a symlink) can be followed.

    The reviewer's probe passed base_dir=/proc/self/root (a symlink to /) and
    the previous copy opened it with ``os.open(base_dir, O_RDONLY|O_DIRECTORY)``
    -- NO O_NOFOLLOW -- so the symlinked root was silently followed.  A symlink
    anywhere in base_dir's ancestry fails closed here (O_NOFOLLOW raises
    ELOOP).  The returned descriptor is the single admitted root; every child
    is traversed relative to IT (openat), so a post-admission swap of the path
    cannot redirect the copy.  base_dir must be absolute."""
    if not os.path.isabs(base_dir):
        raise SystemExit('I/O-continuity: refusing a non-absolute confine root %r' % base_dir)
    comps = [c for c in base_dir.split(os.sep) if c not in ("", ".")]
    if any(c == ".." for c in comps):
        raise SystemExit('I/O-continuity: refusing a confine root %r with .. in its path' % base_dir)
    root_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)  # "/" itself is not a symlink
    cur = root_fd
    opened = [root_fd]
    try:
        for comp in comps:
            dfd = os.open(comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=cur)
            opened.append(dfd)
            cur = dfd
    except OSError as exc:
        for fd in opened:
            os.close(fd)
        raise SystemExit('I/O-continuity: confine root %r has a symlinked/aliased ancestor; refusing '
                         'to follow it: %s' % (base_dir, exc))
    # close every intermediate; keep ONLY the final admitted-root descriptor
    for fd in opened[:-1]:
        os.close(fd)
    return cur


def _open_confined(base_dir, rel, phase, root_fd=None):
    """GIO03: open ``base_dir/rel`` by traversing EVERY path component with
    O_NOFOLLOW from the ADMITTED ROOT DESCRIPTOR, returning the final file's
    descriptor.

    The admitted root is obtained from ``_open_admitted_root`` (base_dir opened
    component-wise from "/" with O_NOFOLLOW, so a symlinked root/ancestor fails
    closed -- the exact /proc/self/root probe the review reproduced).  A caller
    that already holds the retained root descriptor passes it as ``root_fd`` so
    EVERY child is traversed relative to the SAME admitted inode (no re-open
    window).  Each intermediate is opened O_NOFOLLOW|O_DIRECTORY relative to the
    previous descriptor (openat), so no intermediate alias can be traversed
    between admission and copy.  The caller fstat-validates and binds the
    returned descriptor to the admitted (dev, ino)."""
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise SystemExit('I/O-continuity: refusing a non-confined source path %r under %r'
                         % (rel, base_dir))
    own_root = root_fd is None
    base_fd = _open_admitted_root(base_dir) if own_root else root_fd
    opened = [base_fd] if own_root else []
    try:
        cur = base_fd
        for comp in parts[:-1]:
            dfd = os.open(comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=cur)
            opened.append(dfd)
            cur = dfd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=cur)
    except OSError as exc:
        raise SystemExit('I/O-continuity: cannot open source %r under %r without following a '
                         'symlinked component: %s' % (rel, base_dir, exc))
    finally:
        # close everything opened HERE; never close a caller-owned root_fd
        for fd in opened:
            os.close(fd)


class _HostIOAlarm:
    """GIO01: a real-time upper bound on BLOCKING host I/O (read/write) during a
    confined copy.

    The copy loop's ``remaining_budget`` check is COOPERATIVE: it cannot
    interrupt an ``os.read``/``os.write`` that is ALREADY blocked on a wedged
    source or destination, so the cooperative check never fires and the copy
    could block unbounded.  This arms SIGALRM for the seconds remaining on the
    overall deadline (clipped to a per-copy cap); its handler raises so, per PEP
    475, a syscall whose handler RAISES is NOT retried -- a stalled blocking
    read/write fails closed at the deadline.  It is only armed on the main
    thread (where staging/copy runs, before the sampler threads start); off the
    main thread it degrades to the single cooperative budget check (the caller
    still checks per chunk).  Reinstalls any previous handler on exit."""

    def __init__(self, phase, cap=None):
        self._phase = phase
        self._cap = cap
        self._armed = False
        self._prev = None

    def _usable(self):
        return (hasattr(signal, "setitimer")
                and threading.current_thread() is threading.main_thread())

    def __enter__(self):
        remaining = remaining_budget(self._phase, self._cap)
        if not self._usable():
            return self

        def _fire(_signum, _frame):
            raise SystemExit('I/O-continuity: host copy for %s exceeded its blocking-I/O deadline '
                             '(stalled read/write failed closed)' % self._phase)

        self._entered_at = time.monotonic()
        self._old_timer = signal.getitimer(signal.ITIMER_REAL)
        if self._old_timer[0] > 0:
            remaining = min(remaining, self._old_timer[0])
        self._prev = signal.signal(signal.SIGALRM, _fire)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        self._armed = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._prev)
            if self._old_timer[0] > 0:
                signal.setitimer(signal.ITIMER_REAL, max(0.000001, self._old_timer[0] - (time.monotonic() - self._entered_at)), self._old_timer[1])
            self._armed = False
        return False


def bounded_host_io(function):
    def bounded(*args, **kwargs):
        if threading.current_thread() is not threading.main_thread():
            raise SystemExit('host I/O requires interruptible main thread')
        with _HostIOAlarm(function.__name__):
            return function(*args, **kwargs)
    return bounded


def _safe_copy_into_fd(base_dir, rel, dst_fd, expected_size, expected_dev, expected_ino, phase,
                       root_fd=None, digest=None):
    """Descriptor-validated, BOUNDED copy of base_dir/rel into an already-open
    dst fd (GIO01/GIO02/GIO03).

    The source is opened by descriptor-confined traversal (``_open_confined``:
    O_NOFOLLOW on EVERY component, not only the last) and the OPENED descriptor
    is validated by fstat -- regular, single link, size equal to the
    pre-accounted size, and the SAME (st_dev, st_ino) FULL identity admitted by
    the walk-time lstat -- so the bytes copied are exactly the admitted inode's
    bytes (closing both the lstat-then-reopen race AND the
    intermediate-substitution race the review flagged).  GIO03: binding only
    st_ino is insufficient -- an inode number is reused within a filesystem and
    collides ACROSS filesystems, so a bind-mount/overlay swap at the same path
    could present a DIFFERENT device's identically-numbered inode; the full
    (st_dev, st_ino) pair is bound.  GIO03: when the caller holds the RETAINED
    admitted-root descriptor it passes it as ``root_fd`` so EVERY child is
    traversed (openat) relative to the SAME admitted inode -- no per-file
    re-open of the root after pathname-based admission.  Copying is bounded: a
    source that GREW past the accounted size is refused rather than copied
    unbounded, zero-progress writes are refused, the overall deadline is honored
    across the loop.

    GIO01 (repair3-review): the real-time watchdog is armed FIRST -- BEFORE the
    source open and fstat -- so a STALLED source open (a wedged device/FIFO that
    never returns from open(2)) fails closed at the deadline instead of blocking
    unbounded before the copy deadline was ever armed.  The whole
    admit->open->validate->copy lifecycle runs under ONE ``_HostIOAlarm``
    (per-copy cap 300 s, clipped to the remaining overall budget); the
    cooperative ``remaining_budget`` check in the loop still gives a precise
    rule on the fast (non-stalled) path.  Returns the bytes copied."""
    src = os.path.join(base_dir, rel)
    # GIO01: arm the watchdog BEFORE opening the source, so the open itself is
    # bounded (the prior code opened + fstat'd before entering _HostIOAlarm).
    with _HostIOAlarm(phase, cap=300):
        sfd = _open_confined(base_dir, rel, phase, root_fd=root_fd)
        try:
            st = os.fstat(sfd)
            if not stat.S_ISREG(st.st_mode):
                raise SystemExit('I/O-continuity: opened source %r is not a regular file' % src)
            if st.st_nlink != 1:
                raise SystemExit('I/O-continuity: opened source %r is hard-linked (nlink=%d)'
                                 % (src, st.st_nlink))
            if expected_dev is not None and st.st_dev != expected_dev:
                raise SystemExit('I/O-continuity: source %r device changed between admission and open '
                                 '(%d != %d); refusing a substituted filesystem/device'
                                 % (src, st.st_dev, expected_dev))
            if expected_ino is not None and st.st_ino != expected_ino:
                raise SystemExit('I/O-continuity: source %r inode changed between admission and open '
                                 '(%d != %d); refusing a substituted inode' % (src, st.st_ino, expected_ino))
            if st.st_size != expected_size:
                raise SystemExit('I/O-continuity: source %r changed size between accounting and open '
                                 '(%d != %d); refusing' % (src, st.st_size, expected_size))
            copied = 0
            while True:
                remaining_budget(phase)  # precise rule on the fast (non-stalled) path
                chunk = os.read(sfd, 1 << 20)
                if not chunk:
                    break
                if digest is not None:
                    digest.update(chunk)
                copied += len(chunk)
                if copied > expected_size:
                    raise SystemExit('I/O-continuity: source %r grew past %d bytes while copying; refusing'
                                     % (src, expected_size))
                off, mv = 0, memoryview(chunk)
                while off < len(mv):
                    n = os.write(dst_fd, mv[off:])
                    if n <= 0:
                        raise SystemExit('I/O-continuity: zero-progress write while copying %r' % src)
                    off += n
            if copied != expected_size:
                raise SystemExit('I/O-continuity: source %r shrank while copying (%d != %d); refusing'
                                 % (src, copied, expected_size))
            return copied
        finally:
            os.close(sfd)

# R01: identities known to be the STALE integration-repair1 freeze -- the base
# image that still embeds the OLD in-guest validator/runner/supervisor, the OLD
# harness container image, and the OLD api/subscription wrappers. The frozen
# command MUST NOT boot any of these. A BUILT-ARTIFACTS lock produced by the
# GATED build/delivery procedure (BUILD-DELIVERY.md) must supply fresh
# identities distinct from every stale value below, and --pin must equal the
# lock's rebuilt base os_image_hash. See enforce_built_artifacts_lock().
STALE_BASE_OS_IMAGE_HASH = '46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2'
STALE_HARNESS_IMAGE_DIGESTS = {
    'sha256:48c2a81bc901a25084fa1bbb36291c7ed84f2d6ce3fe0efede753c4c07dc96eb',  # product-manifest pin
    'sha256:1ffe3d32a9c9a5dda6ee51f967e62d4c77021ff95057304f94aae1da126c32cd',  # digest-lock repo_digest
}
# The repaired wrappers that a correct rebuilt image MUST embed (and whose
# sha256 the regenerated product manifests MUST record), replacing the stale
# 7f2f3aa1… (api) / 93e50e51… (subscription) bytes.
# SPECULATIVE-IMAGE-E2E fix: the guest snapshot carried STALE wrapper identities
# (726412d1/7827917b from the integration-build-prep-repair2 lane). The actual
# current wrapper bytes -- which are ALSO the exact bytes inside the reused
# arm64-harness OCI (ARM64-HARNESS-LOCK context_sha256) and the BUILD.sh pins --
# hash to 31a541a7 (api) / e396cd29 (subscription). Align R01 to the actual
# current wrapper identities so a lock built from them is accepted (not falsely
# stale).
REPAIRED_API_WRAPPER_SHA256 = '31a541a779aaffc645dd9966248f1ffc3f25b7b999e1253e8ef558391f142c2f'
REPAIRED_SUBSCRIPTION_WRAPPER_SHA256 = 'e396cd293fe9b53fc728098bdbf66e0dccb69a1cf0b5f4f6b8dfceae863e2c5a'
STALE_WRAPPER_PREFIXES = ('7f2f3aa1', '93e50e51')


def enforce_built_artifacts_lock(lock_path, pin):
    """R01: fail closed unless a BUILT-ARTIFACTS lock produced by the GATED
    build/delivery procedure is supplied AND binds rebuilt identities that are
    distinct from the known-stale integration-repair1 freeze. The launch --pin
    MUST equal the lock's rebuilt base os_image_hash, so the boot can only ever
    target the repaired implementation (never the stale 46c4bcc9… image)."""
    if not lock_path:
        raise SystemExit(
            'R01: no --built-artifacts-lock supplied. This command fails closed and will NOT '
            'boot the stale integration-repair1 artifacts. Run the GATED build/delivery '
            'procedure (dstack-runner-join/source/build/BUILD-DELIVERY.md) to mint the repaired '
            'base image + harness image + wrappers, then pass the emitted lock.')
    try:
        with open(lock_path) as fh:
            lock = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit('R01: --built-artifacts-lock unreadable (%s); refusing' % type(exc).__name__)
    required = ('base_os_image_hash', 'harness_image_digest',
                'api_wrapper_sha256', 'subscription_wrapper_sha256')
    missing = [k for k in required if not lock.get(k)]
    if missing:
        raise SystemExit('R01: built-artifacts lock missing required identities %r; refusing' % missing)
    if lock['base_os_image_hash'] == STALE_BASE_OS_IMAGE_HASH:
        raise SystemExit('R01: built-artifacts lock still names the STALE base os_image_hash; '
                         'the repaired image was not rebuilt. Refusing.')
    if lock['harness_image_digest'] in STALE_HARNESS_IMAGE_DIGESTS:
        raise SystemExit('R01: built-artifacts lock still names a STALE harness image digest; refusing.')
    if lock['api_wrapper_sha256'] != REPAIRED_API_WRAPPER_SHA256:
        raise SystemExit('R01: api wrapper sha256 in lock is not the repaired wrapper; refusing.')
    if lock['subscription_wrapper_sha256'] != REPAIRED_SUBSCRIPTION_WRAPPER_SHA256:
        raise SystemExit('R01: subscription wrapper sha256 in lock is not the repaired wrapper; refusing.')
    for key in ('base_os_image_hash', 'api_wrapper_sha256', 'subscription_wrapper_sha256'):
        if any(str(lock[key]).startswith(pfx) for pfx in STALE_WRAPPER_PREFIXES):
            raise SystemExit('R01: built-artifacts lock contains a stale-prefixed identity; refusing.')
    if pin != lock['base_os_image_hash']:
        raise SystemExit('R01: --pin %s does not equal the rebuilt base os_image_hash %s in the '
                         'built-artifacts lock; the command must target the rebuilt image. Refusing.'
                         % (pin, lock['base_os_image_hash']))
    # S02: string distinctness from stale values is NECESSARY but not
    # SUFFICIENT -- the lock must also carry the post-build verification
    # transcript (verify_built_artifacts.py) proving the repaired source
    # bytes were measured INSIDE the rebuilt artifacts (embedded validator/
    # runner/supervisor/sentinel hashes, on-image wrapper hashes, manifest
    # delivery endpoint). A lock without a passing verification is refused.
    ver = lock.get('verification')
    if not isinstance(ver, dict) or ver.get('predicate') != 'pass':
        raise SystemExit('S02: built-artifacts lock carries no PASSING post-build verification '
                         '(verification.predicate != "pass"). Run verify_built_artifacts.py in the '
                         'gated build and emit the lock from its transcript. Refusing.')
    for required_measure in ('embedded_validator_sha256', 'embedded_runner_sha256',
                             'embedded_supervisor_sha256', 'embedded_sentinel_sha256',
                             'transcript_sha256'):
        if not ver.get(required_measure):
            raise SystemExit('S02: built-artifacts lock verification block lacks %s; refusing.'
                             % required_measure)
    print('R01/S02: built-artifacts lock accepted (post-build verification pass); booting rebuilt '
          'base %s (not the stale 46c4bcc9…)' % lock['base_os_image_hash'])
    return lock


def sha256f(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _match_recorded_file(path, recorded_sha256, recorded_bytes=None):
    """GIO04/GIO11: compare an exported file against a receipt-recorded
    (sha256, bytes). A NULL recorded digest is the EMPTY-output convention
    (receipting records sha256=None for 0 bytes): the file must exist and be
    exactly 0 bytes -- NOT sha256(b''). A non-null digest compares the actual
    sha256 and, when provided, the exact byte length."""
    if not os.path.isfile(path):
        return False
    size = os.path.getsize(path)
    if recorded_bytes is not None and size != recorded_bytes:
        return False
    if recorded_sha256 is None:
        return size == 0
    return sha256f(path) == recorded_sha256


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# GIO05 (repair3-review + PUBLICATION-CLOSURE-CONTRACT-DECISION): the per-selector
# SUPERVISOR CLOSURE record is a STRUCTURAL disk aid gated on the exporter having
# RETURNED successfully (supervisor rc==0 + exact-marker), so a post-rename fault
# (rename succeeds, post-rename dir fsync fails, unlink + neutralization both
# fail) that leaves the exact EXPORT-COMPLETE bytes still has NO closure record.
# Astra's independent review established that disk-only acceptance is IMPOSSIBLE
# when failed and successful final disk bytes can be identical, so this disk
# record NEVER claims overall acceptance on its own: overall acceptance requires
# the AUTHENTICATED POSITIVE CONSOLE CLOSURE record (DSMACK_RESULT_CLOSED_V1,
# parse_result_closure/verify_result_closure below) cross-bound to the admitted
# closure-context and the actual disk digests.  check_export_tree reports
# STRUCTURAL validity only; the authoritative closure lives on the console.
SUPERVISOR_CLOSED_NAME = 'SUPERVISOR-CLOSED'


def supervisor_closed_bytes(index_sha256):
    return ('dsmack-supervisor-closed/1\nindex_sha256=%s\n' % index_sha256).encode()


def record_supervisor_closure(selector_dir):
    """GIO05: write the per-selector SUPERVISOR CLOSURE record durably.  Called
    (by the supervisor shell's byte-identical equivalent, and by the host tests
    that model supervisor closure) ONLY after the exporter RETURNED successfully
    and the EXPORT-COMPLETE marker carries the exact bytes."""
    with open(os.path.join(selector_dir, 'outputs', 'index.json'), 'rb') as fh:
        idx_bytes = fh.read()
    data = supervisor_closed_bytes(sha256_bytes(idx_bytes))
    path = os.path.join(selector_dir, SUPERVISOR_CLOSED_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(selector_dir, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return path


# ---------------------------------------------------------------------------
# GIO05 AUTHORITATIVE POSITIVE CONSOLE CLOSURE
# (PUBLICATION-CLOSURE-CONTRACT-DECISION/1).  The authoritative acceptance of a
# published result disk is a SINGLE authenticated console record, emitted by the
# trusted supervisor ONLY after every expected selector published, the result
# disk synced AND unmounted.  A surviving disk marker (post-rename fault) can
# never earn acceptance because that record is never emitted.  Owner scope:
# guest producer/supervisor + this smoke "overall" checker.  The full product
# authenticates the actual console bytes against the signed native envelope
# (cross lane); this engineering checker verifies the record grammar and binds
# it to the admitted closure-context and the actual disk digests.
RESULT_CLOSURE_PREFIX = b'DSMACK_RESULT_CLOSED_V1 '
RESULT_CLOSURE_MAX_BYTES = 16384
RESULT_CLOSURE_SELECTOR_MAX = 32
CLOSURE_CONTEXT_REL = ('closure-context', 'context.json')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_SELECTOR_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _canon_closure_json(obj):
    """Canonical compact JSON bytes: ensure_ascii, sorted keys, (',',':')
    separators, NO trailing LF.  Byte-identical to the supervisor's python3
    json.dumps(...) emission so the record round-trips exactly."""
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def closure_context_sha256_and_selectors(workload_dir):
    """Read the ADMITTED public closure-context document (closure-context/
    context.json -- an explicit public channel, never manifests/*.json), return
    (sha256_of_exact_bytes, sorted_expected_selectors).  The expected context is
    taken from the admitted workload input (the engineering stand-in for the
    relying party's independently-pinned context); a malformed/absent context is
    a fail-closed reason."""
    path = os.path.join(workload_dir, *CLOSURE_CONTEXT_REL)
    try:
        with open(path, 'rb') as fh:
            raw = fh.read(8193)
    except OSError:
        return None, None, 'closure-context-missing'
    if len(raw) > 8192:
        return None, None, 'closure-context-too-large'
    try:
        doc = json.loads(raw.decode('ascii'), object_pairs_hook=_unique_json_object)
    except (ValueError, UnicodeDecodeError):
        return None, None, 'closure-context-not-ascii-json'
    if not isinstance(doc, dict) or _canon_closure_json(doc) != raw or set(doc) != {'schema', 'attempt_id', 'selectors'}:
        return None, None, 'closure-context-bad-keys'
    if doc.get('schema') != 'dsmack-result-closure-context/1':
        return None, None, 'closure-context-bad-schema'
    aid = doc.get('attempt_id')
    if not (isinstance(aid, str) and re.fullmatch(r'[0-9a-f]{32}', aid)):
        return None, None, 'closure-context-bad-attempt-id'
    sels = doc.get('selectors')
    if not (isinstance(sels, list) and 1 <= len(sels) <= RESULT_CLOSURE_SELECTOR_MAX
            and all(isinstance(s, str) and _SELECTOR_ID.match(s) for s in sels)
            and len(set(sels)) == len(sels) and sels == sorted(sels)):
        return None, None, 'closure-context-bad-selectors'
    return sha256_bytes(raw), sorted(sels), None


def parse_result_closure(console_bytes):
    """Parse EXACTLY ONE anchored DSMACK_RESULT_CLOSED_V1 record from RAW console
    bytes.  Returns (record_dict, reasons).  Raw-byte LF framing only: a line is
    the bytes between LFs and must START with the prefix (a CR/Unicode separator
    inside other diagnostics can NOT create a record boundary); at most one
    trailing CR before the LF is tolerated (tty ONLCR); CR/NUL anywhere inside
    the trusted body is rejected; the body must be canonical JSON (re-encode and
    require byte-equality) within the size bound; exactly one such line may
    exist."""
    reasons = []
    hits = []
    for raw in console_bytes.split(b'\n')[:-1]:
        if raw.startswith(RESULT_CLOSURE_PREFIX):
            hits.append(raw + b'\n')
    if console_bytes.split(b'\n')[-1].startswith(RESULT_CLOSURE_PREFIX):
        return None, ['closure-record-unterminated']
    if not hits:
        return None, ['closure-record-absent']
    if len(hits) > 1:
        return None, ['closure-record-duplicate:%d' % len(hits)]
    frame = hits[0]
    if len(frame) > RESULT_CLOSURE_MAX_BYTES:
        return None, ['closure-record-too-large']
    line = frame[:-1]
    if line.endswith(b'\r'):
        line = line[:-1]
    body = line[len(RESULT_CLOSURE_PREFIX):]
    if b'\r' in body or b'\x00' in body:
        return None, ['closure-record-control-bytes']
    try:
        rec = json.loads(body.decode('ascii'), object_pairs_hook=_unique_json_object)
    except (ValueError, UnicodeDecodeError):
        return None, ['closure-record-not-json']
    if not isinstance(rec, dict) or _canon_closure_json(rec) != body:
        return None, ['closure-record-not-canonical-json']
    if set(rec) != {'schema', 'attempt_context_sha256', 'result_device', 'closure', 'selectors'}:
        return None, ['closure-record-bad-keys']
    if rec.get('schema') != 'dsmack-result-closure/1':
        return None, ['closure-record-bad-schema']
    if not (isinstance(rec.get('attempt_context_sha256'), str) and _HEX64.match(rec['attempt_context_sha256'])):
        return None, ['closure-record-bad-context-hash']
    sels = rec.get('selectors')
    if not (isinstance(sels, list) and 1 <= len(sels) <= RESULT_CLOSURE_SELECTOR_MAX):
        return None, ['closure-record-bad-selector-count']
    names = []
    for e in sels:
        if not (isinstance(e, dict) and set(e) == {'selector', 'run_id', 'receipt_sha256', 'index_sha256'}):
            return None, ['closure-record-bad-selector-entry']
        if not (all(isinstance(e[k], str) for k in e)
                and _SELECTOR_ID.fullmatch(e['selector'])
                and re.fullmatch(r'[\x21-\x7e]{1,128}', e['run_id'])
                and _HEX64.fullmatch(e['receipt_sha256']) and _HEX64.fullmatch(e['index_sha256'])):
            return None, ['closure-record-bad-selector-fields']
        names.append(e['selector'])
    if len(set(names)) != len(names) or names != sorted(names):
        return None, ['closure-record-selectors-not-sorted-unique']
    return rec, []


def parse_result_closure_streams(streams):
    """Independent byte streams never supply each other's missing terminators."""
    records, errors = [], []
    for stream in streams:
        rec, reasons = parse_result_closure(stream)
        if rec is not None:
            records.append(rec)
        errors.extend(r for r in reasons if r != 'closure-record-absent')
    if errors:
        return None, errors
    if len(records) != 1:
        return None, ['closure-record-stream-count:%d' % len(records)]
    return records[0], []


def verify_result_closure(rec, expected_context_sha256, expected_selectors, disk_facts):
    """Bind a parsed closure record to the independently-expected context and the
    ACTUAL disk-extracted digests.  Returns a list of reason strings (empty ==
    accepted)."""
    reasons = []
    if rec.get('result_device') != 'vdd':
        reasons.append('closure-bad-result-device')
    if rec.get('closure') != 'synced-unmounted':
        reasons.append('closure-not-synced-unmounted')
    if rec.get('attempt_context_sha256') != expected_context_sha256:
        reasons.append('closure-context-hash-mismatch')
    names = sorted(e['selector'] for e in rec['selectors'])
    if names != sorted(expected_selectors):
        reasons.append('closure-selector-set-mismatch:%s!=%s' % (names, sorted(expected_selectors)))
    for e in rec['selectors']:
        s = e['selector']
        df = disk_facts.get(s)
        if df is None:
            reasons.append('closure-selector-not-on-disk:%s' % s)
            continue
        if e['run_id'] != df.get('run_id'):
            reasons.append('closure-run-id-mismatch:%s' % s)
        if e['receipt_sha256'] != df.get('receipt_sha256'):
            reasons.append('closure-receipt-digest-mismatch:%s' % s)
        if e['index_sha256'] != df.get('index_sha256'):
            reasons.append('closure-index-digest-mismatch:%s' % s)
    return reasons


def check_export_tree(selector_dir, selector, receipt, receipt_sha256):
    """GIO04/GIO11: validate ONE selector's CANONICAL output export tree at
    ``selector_dir`` (== <result-root>/<selector>) against the frozen receipt.

    Checks: ``outputs/EXPORT-COMPLETE`` present with the EXACT marker bytes;
    ``outputs/index.json`` bound to the receipt (receipt_sha256) with exact
    per-stream index-path/digest/length agreement and a boolean truncation
    flag; every recorded (non-null) stream at ``outputs/streams/<stream>`` and
    recorded artifact at ``outputs/artifacts/<name>`` present with bytes
    matching the receipt (EMPTY-safe: a null recorded digest requires an empty
    file, never sha256(b'')). Returns a list of ``reason:selector`` strings
    (empty == pass).

    This is the ONE consumer of the export tree -- the smoke launcher AND the
    host unit tests call it, so there is no divergent mirrored consumer that
    could carry the empty-artifact bug independently (GIO11)."""
    reasons = []
    outputs = receipt.get('outputs') or {}
    odir = os.path.join(selector_dir, 'outputs')
    marker = os.path.join(odir, 'EXPORT-COMPLETE')
    if not os.path.isfile(marker) or open(marker, 'rb').read() != b'dsmack-export/1\n':
        reasons.append('export-incomplete:%s' % selector)
        return reasons
    try:
        with open(os.path.join(odir, 'index.json'), 'rb') as _ifh:
            idx_bytes = _ifh.read()
        idx = json.loads(idx_bytes)
    except (OSError, ValueError):
        reasons.append('export-index-unreadable:%s' % selector)
        return reasons
    # Structural disk validity only; overall acceptance requires authenticated positive closure.
    if idx.get('receipt_sha256') != receipt_sha256:
        reasons.append('export-index-not-bound-to-receipt:%s' % selector)
    for stream in ('stdout', 'stderr'):
        rec = outputs.get(stream)
        ent = (idx.get('streams') or {}).get(stream)
        if rec is None and ent is None:
            continue
        if rec is None or ent is None:
            reasons.append('export-stream-presence-mismatch:%s:%s' % (selector, stream))
            continue
        if ent.get('path') != 'streams/%s' % stream:
            reasons.append('export-stream-index-path:%s:%s' % (selector, stream))
            continue
        if ent.get('sha256') != rec.get('sha256') or ent.get('bytes') != rec.get('bytes'):
            reasons.append('export-stream-index-mismatch:%s:%s' % (selector, stream))
        if not isinstance(ent.get('truncated'), bool):
            reasons.append('export-stream-truncated-not-bool:%s:%s' % (selector, stream))
        sp = os.path.join(odir, ent['path'])
        if not _match_recorded_file(sp, rec.get('sha256'), rec.get('bytes')):
            reasons.append('export-stream-bytes-mismatch:%s:%s' % (selector, stream))
    idx_arts = {a.get('name'): a for a in (idx.get('artifacts') or [])}
    for art in outputs.get('artifacts') or []:
        name = str(art.get('name', ''))
        sp = os.path.join(odir, 'artifacts', name)
        if not _match_recorded_file(sp, art.get('sha256'), art.get('bytes')):
            reasons.append('export-artifact-bytes-mismatch:%s:%s' % (selector, name))
        ie = idx_arts.get(name)
        if ie is None or ie.get('path') != 'artifacts/%s' % name \
                or ie.get('sha256') != art.get('sha256') or ie.get('bytes') != art.get('bytes'):
            reasons.append('export-artifact-index-mismatch:%s:%s' % (selector, name))
    return reasons


# S04: every host container this launcher starts is NAMED and tracked here so
# cleanup can force-remove and CONFIRM each one (an unnamed container whose
# docker client was killed keeps running server-side).
OWNED_CONTAINERS = []
_OVERALL_DEADLINE = [None]


def start_overall_deadline(seconds):
    _OVERALL_DEADLINE[0] = time.monotonic() + seconds


def remaining_budget(phase, cap=None):
    """S04: seconds left of the ONE overall deadline (optionally clipped to a
    per-step cap). Exhaustion anywhere -- including copying/hashing/extraction
    steps -- fails closed."""
    if _OVERALL_DEADLINE[0] is None:
        raise SystemExit('internal: overall deadline not started before %s' % phase)
    left = _OVERALL_DEADLINE[0] - time.monotonic()
    if left <= 0:
        raise SystemExit('overall deadline exhausted before %s' % phase)
    return left if cap is None else min(left, cap)


def owned_container_name(kind, run_name):
    name = 'dsmack-%s-%s' % (kind, run_name)
    OWNED_CONTAINERS.append(name)
    return name


def _assert_image_pins():
    """F04: resolve each execution image tag to its ID and fail closed on
    any drift from the reviewed pin (no mutable-tag substitution)."""
    for tag, pinned in ((QEMU_IMAGE, QEMU_IMAGE_ID), (BUILDER_IMAGE, BUILDER_IMAGE_ID)):
        r = subprocess.run(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'],
                           capture_output=True, text=True, timeout=60)
        got = r.stdout.strip()
        if r.returncode != 0 or got != pinned:
            raise SystemExit('host execution image %s does not resolve to the pinned ID %s (got %r); '
                             'refusing to run' % (tag, pinned, got))
    print('host execution images pinned: qemu=%s builder=%s' % (QEMU_IMAGE_ID[:19], BUILDER_IMAGE_ID[:19]))


@bounded_host_io
def bundle_snapshot(ev, files_dir, tag, name):
    lines = []
    for f in sorted(BUNDLE_FILES):
        remaining_budget('bundle-snapshot')  # S04: hashing honors the deadline
        p = os.path.join(files_dir, f)
        lines.append('%s  %s' % (sha256f(p), f))
    out = os.path.join(ev, '%s-bundle-%s.txt' % (name, tag))
    open(out, 'w').write('\n'.join(lines) + '\n')
    return lines


@bounded_host_io
def stage_verified(rt, files_dir):
    """F03/R05 staging: copy the boot-consumed files into a launcher-private,
    FRESH per-run staging dir and return its path plus the consumed-byte
    sha256s. Admission and QEMU both consume THESE staged bytes. On this
    shared developer host the staging is best-effort hygiene, NOT a
    cryptographic consumption guarantee -- the owning user can still reach
    the dir; the real owned-buffer boot binding is the GATED signed-app ABI."""
    stage = os.path.join(rt, 'verified-boot')
    os.makedirs(stage, mode=0o700, exist_ok=False)
    os.chmod(stage, 0o700)
    # Carry the bundle's serialized manifests too, so admission runs wholly
    # against the staged copy (never the externally-visible owner dir).
    consumed = {}
    for f in BUNDLE_FILES:
        remaining_budget('stage-copy')  # S04: copying honors the deadline
        src = os.path.join(files_dir, f)
        dst = os.path.join(stage, f)
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            shutil.copyfileobj(s, d, 1 << 20)
        os.chmod(dst, 0o400)
    for f in BOOT_CONSUMED:
        remaining_budget('stage-hash')
        consumed[f] = sha256f(os.path.join(stage, f))
    return stage, consumed


@bounded_host_io
def admit(rt, stage_dir, pin, run_name):
    """Image admission: full verify (incl. dm-verity recompute) in the builder,
    read-only, against the pinned identity -- run over the STAGED copy so the
    verified bytes are exactly the consumed bytes. A private per-run verifier
    dir holds only the verify_manifest.py (the owning lane's reviewed copy).
    S04: the admission container is NAMED and tracked (cleanup removes it even
    if this client is killed) and its timeout is clipped to the remaining
    overall deadline."""
    verifier_src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'tests', 'verify_manifest.py')
    vdir = os.path.join(rt, 'verifier')
    os.makedirs(vdir, mode=0o700, exist_ok=False)
    shutil.copy(verifier_src, os.path.join(vdir, 'verify_manifest.py'))
    cname = owned_container_name('admit', run_name)
    r = subprocess.run(['docker', 'run', '--rm', '--name', cname,
                        '-v', '%s:/stage:ro' % stage_dir, '-v', '%s:/v:ro' % vdir, BUILDER_IMAGE_ID,
                        'python3', '/v/verify_manifest.py', '/stage'],
                       capture_output=True, text=True,
                       timeout=remaining_budget('admission', 300))
    print(r.stdout, end='')
    if r.returncode != 0:
        print(r.stderr[-2000:], file=sys.stderr)
        raise SystemExit('image admission REJECTED (rc=%d)' % r.returncode)
    admitted = open(os.path.join(stage_dir, 'digest.txt')).read().strip()
    if admitted != pin:
        raise SystemExit('admitted os_image_hash %s != pinned %s; refusing to boot' % (admitted, pin))
    print('admitted os_image_hash matches pin %s' % pin)
    return admitted


def _transport_entries(root_fd, channels, include_workload=False):
    """Enumerate only retained descriptors; never resolve the admitted root again."""
    entries = []
    def walk(fd, prefix):
        for name in sorted(os.listdir(fd)):
            rel = prefix + '/' + name if prefix else name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    got = os.fstat(child)
                    if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
                        raise SystemExit('transport directory identity changed')
                    entries.append((rel, st, True))
                    walk(child, rel)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                entries.append((rel, st, False))
            else:
                raise SystemExit('transport refuses source alias/nonregular entry: ' + rel)
    if include_workload:
        st = os.stat('WORKLOAD', dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SystemExit('transport refuses aliased WORKLOAD')
        entries.append(('WORKLOAD', st, False))
    for channel in channels:
        try:
            st = os.stat(channel, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise SystemExit('transport refuses non-directory/aliased channel: ' + channel)
        fd = os.open(channel, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            got = os.fstat(fd)
            if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
                raise SystemExit('transport channel identity changed')
            entries.append((channel, st, True))
            walk(fd, channel)
        finally:
            os.close(fd)
    return entries


TRANSPORT_RESIDUE = []


def _pt_tar_filter(ti):
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ''
    ti.mtime = _ptl.PT_CANONICAL_MTIME
    ti.mode = _ptl.PT_CANONICAL_DIR_MODE if ti.isdir() else _ptl.PT_CANONICAL_FILE_MODE
    return ti


def _build_transport(rt, workload_dir, out_img, max_bytes, private, require_residue_free=False):
    # Namespace exclusion is not established on a same-UID host. Never delete,
    # rename, or restore uncertain names, including preexisting destinations.
    if require_residue_free:
        raise SystemExit('transport refuses residue-free policy: host GC is deferred')
    if threading.current_thread() is not threading.main_thread():
        raise SystemExit('transport requires interruptible main-thread I/O')
    kind = 'private' if private else 'workload'
    residue = []
    try:
        with _HostIOAlarm(kind + '-complete-lifecycle', cap=300):
            root_fd = _open_admitted_root(workload_dir)
            try:
                if not private and any(c in ('envelopes', 'broker') for c in PUBLIC_CHANNELS):
                    raise SystemExit('private channel in public transport allowlist')
                entries = _transport_entries(root_fd, PRIVATE_CHANNELS if private else PUBLIC_CHANNELS,
                                             include_workload=not private)
                files = [(rel, st) for rel, st, directory in entries if not directory]
                if private and not files:
                    return False
                total = sum(st.st_size for _, st in files)
                if total > min(max_bytes, _ptl.PT_TOTAL_BYTES_MAX if private else max_bytes):
                    raise SystemExit('transport source byte cap exceeded')
                if private and (len(files) > _ptl.PT_ENTRY_COUNT_MAX or any(
                        st.st_size > _ptl.PT_FILE_BYTES_MAX or len(rel.split('/')) > _ptl.PT_DEPTH_MAX
                        for rel, st in files)):
                    raise SystemExit('transport private entry/depth cap exceeded')
                # No named staging namespace: same-UID name substitution must
                # never redirect private writes or alter bytes after admission.
                # Linux memfds stay descriptor-owned and are sealed before any
                # hash/pack/read consumer. All descriptors close on every exit.
                import contextlib
                import fcntl
                with contextlib.ExitStack() as owned:
                    seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                             fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                    def anonymous(label):
                        fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                        owned.callback(os.close, fd)
                        return fd
                    def seal(fd, expected):
                        st = os.fstat(fd)
                        if (not stat.S_ISREG(st.st_mode) or st.st_size != expected):
                            raise SystemExit('transport staged size/type changed')
                        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
                        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                            raise SystemExit('transport immutable descriptor refused')
                        return st
                    def consume(fd, expected):
                        st = os.fstat(fd)
                        if (not stat.S_ISREG(st.st_mode) or st.st_size != expected or
                                fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals):
                            raise SystemExit('transport sealed descriptor changed')
                        os.lseek(fd, 0, os.SEEK_SET)
                        return os.fdopen(os.dup(fd), 'rb')
                    staged = []
                    sums = []
                    for rel, st, directory in entries:
                        if directory:
                            staged.append((rel, None, 0))
                            continue
                        fd = anonymous(kind + '-entry')
                        copied_digest = hashlib.sha256()
                        _safe_copy_into_fd(workload_dir, rel, fd, st.st_size, st.st_dev, st.st_ino,
                                           kind + '-copy', root_fd=root_fd, digest=copied_digest)
                        seal(fd, st.st_size)
                        with consume(fd, st.st_size) as f:
                            sealed_hash = hashlib.sha256()
                            for chunk in iter(lambda: f.read(1048576), b''):
                                sealed_hash.update(chunk)
                            sealed_digest = sealed_hash.digest()
                        if sealed_digest != copied_digest.digest():
                            raise SystemExit('transport staged digest changed before seal')
                        staged.append((rel, fd, st.st_size))
                        if not private:
                            digest = hashlib.sha256()
                            with consume(fd, st.st_size) as f:
                                for chunk in iter(lambda: f.read(1048576), b''):
                                    digest.update(chunk)
                            sums.append('%s  %s' % (digest.hexdigest(), rel))
                    if not private:
                        raw = ('\n'.join(sums) + '\n').encode()
                        fd = anonymous('workload-checksums')
                        with os.fdopen(os.dup(fd), 'wb') as f:
                            f.write(raw)
                        seal(fd, len(raw))
                        with consume(fd, len(raw)) as f:
                            if f.read() != raw:
                                raise SystemExit('transport checksums digest changed before seal')
                        staged.append(('SHA256SUMS', fd, len(raw)))
                    tfd = anonymous(kind + '-archive')
                    # Enforce the packed limit during creation, not only after
                    # allocating an arbitrarily grown archive.
                    archive_digest = hashlib.sha256()
                    class BoundedArchive:
                        def __init__(self, f): self.f = f
                        def tell(self): return self.f.tell()
                        def write(self, data):
                            if self.tell() + len(data) > max_bytes:
                                raise SystemExit('transport packed byte cap exceeded')
                            result = self.f.write(data)
                            if result != len(data):
                                raise SystemExit('transport archive short write')
                            archive_digest.update(data)
                            return result
                        def flush(self): return self.f.flush()
                    with os.fdopen(os.dup(tfd), 'wb') as tf:
                        with tarfile.open(fileobj=BoundedArchive(tf), mode='w', format=tarfile.USTAR_FORMAT) as t:
                            for rel, fd, size_bytes in sorted(staged):
                                ti = tarfile.TarInfo(rel)
                                ti.type = tarfile.DIRTYPE if fd is None else tarfile.REGTYPE
                                ti.size = size_bytes
                                _pt_tar_filter(ti)
                                if fd is None:
                                    t.addfile(ti)
                                else:
                                    with consume(fd, size_bytes) as f:
                                        t.addfile(ti, f)
                        tf.flush()
                    archive_size = os.fstat(tfd).st_size
                    seal(tfd, archive_size)
                    with consume(tfd, archive_size) as f:
                        blob = f.read(max_bytes + 1)
                        if len(blob) != archive_size or f.read(1):
                            raise SystemExit('transport archive changed during read')
                    if hashlib.sha256(blob).digest() != archive_digest.digest():
                        raise SystemExit('transport archive digest changed before seal')
                    if len(blob) > max_bytes:
                        raise SystemExit('transport packed byte cap exceeded')
                align = _ptl.PT_IMAGE_ALIGN if private else 1 << 20
                size = ((len(blob) + align - 1) // align) * align or align
                if size > max_bytes:
                    raise SystemExit('transport aligned image byte cap exceeded')
                padded = blob + b'\x00' * (size - len(blob))
                if private:
                    _pt.parse_entries(padded)
                parent_fd = _open_admitted_root(os.path.dirname(os.path.abspath(out_img)))
                try:
                    fd = os.open(os.path.basename(out_img), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
                residue.append(out_img)
                try:
                    view = memoryview(padded)
                    while view:
                        n = os.write(fd, view)
                        if n <= 0:
                            raise SystemExit('transport image write made no progress')
                        view = view[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return True
            finally:
                os.close(root_fd)
    finally:
        # All synchronous writers and descriptors have quiesced before this
        # report. Reporting has no filesystem probes or destructive operations.
        TRANSPORT_RESIDUE.append({'kind': kind, 'cleanup': 'deferred', 'paths': residue[:]})
        print('transport host cleanup deferred; residue=%r' % residue, file=sys.stderr)


def build_workload_disk(rt, workload_dir, out_img, max_bytes, require_residue_free=False):
    return _build_transport(rt, workload_dir, out_img, max_bytes, False, require_residue_free)


def build_private_disk(rt, workload_dir, out_img, max_bytes, require_residue_free=False):
    return _build_transport(rt, workload_dir, out_img, max_bytes, True, require_residue_free)


def copy_admitted_template(template_dir, role, path, cmdline):
    """Fresh copy from retained descriptors, bound to authenticated cmdline."""
    token = {'scratch': 'dstack.scratch_template_sha256',
             'result': 'dstack.result_template_sha256'}[role]
    matches = [t.split('=', 1)[1] for t in cmdline.split() if t.startswith(token + '=')]
    if len(matches) != 1 or not re.fullmatch(r'[0-9a-f]{64}', matches[0]):
        raise SystemExit('mandatory authenticated template binding missing: ' + token)
    alarm = _HostIOAlarm('template-copy')
    alarm.__enter__()
    root_fd = src_fd = dst_fd = None
    try:
        root_fd = _open_admitted_root(template_dir)
        mfd = _open_confined(template_dir, 'disk-templates.json', 'template-manifest', root_fd=root_fd)
        with os.fdopen(mfd, 'rb') as f:
            raw = f.read(65537)
        if len(raw) > 65536:
            raise SystemExit('template manifest too large')
        manifest = json.loads(raw, object_pairs_hook=_unique_json_object)
        entry = manifest['templates'][role]
        if entry['role'] != {'scratch': 'vdb-scratch', 'result': 'vdd-result'}[role]:
            raise SystemExit('template role mismatch')
        name = entry['name']
        if not isinstance(name, str) or '/' in name or name in ('.', '..'):
            raise SystemExit('invalid template name')
        src_fd = _open_confined(template_dir, name, 'template-copy', root_fd=root_fd)
        st = os.fstat(src_fd)
        size = entry['size_bytes']
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or type(size) is not int
                or not 0 < size <= 1073741824 or size % 512 or st.st_size != size):
            raise SystemExit('template size refused')
        digest = hashlib.sha256()
        dst_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        left = size
        while left:
            chunk = os.read(src_fd, min(left, 1048576))
            if not chunk:
                raise SystemExit('template shrank')
            digest.update(chunk)
            left -= len(chunk)
            view = memoryview(chunk)
            while view:
                n = os.write(dst_fd, view)
                if n <= 0:
                    raise SystemExit('template short write')
                view = view[n:]
        if os.read(src_fd, 1) or os.fstat(src_fd).st_size != size:
            raise SystemExit('template grew')
        if digest.hexdigest() != matches[0] or entry['sha256'] != matches[0]:
            raise SystemExit('template authenticated digest mismatch')
        os.fsync(dst_fd)
    finally:
        for fd in (dst_fd, src_fd, root_fd):
            if fd is not None:
                os.close(fd)
        alarm.__exit__(None, None, None)


def sync_parent(path):
    fd = _open_admitted_root(os.path.dirname(os.path.abspath(path)))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def retain_runtime_file(root, rel, destination, max_bytes):
    with _HostIOAlarm('runtime-evidence-retention'):
        root_fd = _open_admitted_root(root)
        try:
            source_fd = _open_confined(root, rel, 'runtime-evidence-retention', root_fd=root_fd)
            try:
                st = os.fstat(source_fd)
            finally:
                os.close(source_fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 <= st.st_size <= max_bytes:
                raise SystemExit('runtime evidence file type/size refused')
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                _safe_copy_into_fd(root, rel, fd, st.st_size, st.st_dev, st.st_ino,
                                   'runtime-evidence-retention', root_fd=root_fd)
                os.fsync(fd)
                sync_parent(destination)
            finally:
                os.close(fd)
        finally:
            os.close(root_fd)


def fresh_scratch(rt, path, run_name, template_dir=None, cmdline=None):
    if template_dir is None or cmdline is None:
        raise SystemExit('mandatory scratch template admission missing')
    copy_admitted_template(template_dir, 'scratch', path, cmdline)


def fresh_export(rt, path, run_name, template_dir=None, cmdline=None):
    if template_dir is None or cmdline is None:
        raise SystemExit('mandatory result template admission missing')
    copy_admitted_template(template_dir, 'result', path, cmdline)


def bind_workload_to_pin(workload_dir, pin, metadata_cmdline, smp, mem, expected_manifests):
    """S02: bind the REBUILT boot identity to workload admission BEFORE boot.
    Every delivered manifest's base_vm must name the pinned bundle (hash +
    verbatim cmdline) and the actual launch resources; the delivered admission
    document must admit EXACTLY the pin; and each --expect-manifest sha must
    equal the sha256 of the delivered manifest bytes. A workload that admits
    any other bundle (e.g. the separately delivered stale one) is refused --
    receipts produced by this run can therefore only ever admit the booted
    bundle. Returns {manifest_sha256: name}."""
    mdir = os.path.join(workload_dir, 'manifests')
    delivered = {}
    problems = []
    for fn in sorted(os.listdir(mdir)):
        if not fn.endswith('.app-compose.json'):
            continue
        raw = open(os.path.join(mdir, fn), 'rb').read()
        sha = hashlib.sha256(raw).hexdigest()
        doc = json.loads(raw)
        bv = doc.get('base_vm') or {}
        name = fn[:-len('.app-compose.json')]
        if bv.get('os_image_hash') != pin:
            problems.append('%s: base_vm.os_image_hash %r != pin' % (name, bv.get('os_image_hash')))
        if bv.get('cmdline') != metadata_cmdline:
            problems.append('%s: base_vm.cmdline differs from the staged metadata cmdline' % name)
        if bv.get('vcpus') != smp or bv.get('memory_mb') != mem:
            problems.append('%s: base_vm resources %r/%r != launch %d vCPU/%d MiB'
                            % (name, bv.get('vcpus'), bv.get('memory_mb'), smp, mem))
        delivered[sha] = name
    if set(delivered) != set(expected_manifests):
        problems.append('delivered manifest sha set %s != expected %s'
                        % (sorted(delivered), sorted(expected_manifests)))
    adm_path = os.path.join(workload_dir, 'admission', 'base-admission.json')
    try:
        admission = json.load(open(adm_path))
    except (OSError, ValueError):
        problems.append('admission document unreadable: %s' % adm_path)
        admission = {}
    if admission.get('allowed_os_image_hashes') != [pin]:
        problems.append('admission allowed_os_image_hashes %r != [pin] -- the workload could admit '
                        'a bundle other than the booted one' % admission.get('allowed_os_image_hashes'))
    if problems:
        raise SystemExit('S02: workload not bound to the rebuilt boot identity:\n  ' +
                         '\n  '.join(problems))
    print('S02: workload bound to pin %s (manifests, cmdline, resources, admission)' % pin)
    return delivered


@bounded_host_io
def verify_exported_receipts(rt, ev, run_name, workload_dir, pin, expected_manifests,
                             receipts_written, name_by_sha):
    """S05: extract the export disk (debugfs in the pinned builder container,
    never mounted) and validate the exported results: each expected receipt
    must exist, hash to the console-declared DSMACK_RECEIPT_WRITTEN value,
    validate under the frozen contract library against the exact delivered
    manifest+envelope bytes, name the booted bundle, be completed rc=0, and
    every receipt-declared artifact's exported bytes must hash to the receipt
    value. Returns (reasons, facts); empty reasons == pass."""
    reasons = []
    facts = {}
    img = os.path.join(ev, '%s-export.img' % run_name)
    if not os.path.isfile(img):
        return ['export-disk-missing'], facts
    outdir = os.path.join(rt, 'export-extract')
    os.makedirs(outdir, exist_ok=False)
    cname = owned_container_name('exportread', run_name)
    r = subprocess.run(['docker', 'run', '--rm', '--name', cname,
                        '-v', '%s:/d:ro' % os.path.dirname(img), '-v', '%s:/out' % outdir,
                        BUILDER_IMAGE_ID,
                        'debugfs', '-R', 'rdump / /out', '/d/%s' % os.path.basename(img)],
                       capture_output=True, text=True,
                       timeout=remaining_budget('export-extract', 180))
    if r.returncode != 0:
        return ['export-extract-failed(rc=%d)' % r.returncode], facts
    # Clean filesystem state is an additional structural check, not publication
    # success. Positive authenticated closure remains mandatory. EXPORT-COMPLETE
    # markers on the disk are NOT sufficient after a failed close. A guest that
    # failed to sync/unmount vdd (DSMACK_EXPORT_UNMOUNT_FAIL) leaves the ext4
    # "Filesystem state" NOT clean; debugfs reads that intrinsic superblock flag
    # from the raw image, so marker presence ALONE can never signal completion
    # after a failed closure. A non-clean / unreadable state fails closed.
    sr = subprocess.run(['docker', 'run', '--rm', '--name', owned_container_name('exportstate', run_name),
                         '-v', '%s:/d:ro' % os.path.dirname(img), BUILDER_IMAGE_ID,
                         'debugfs', '-R', 'show_super_stats -h', '/d/%s' % os.path.basename(img)],
                        capture_output=True, text=True,
                        timeout=remaining_budget('export-disk-state', 120))
    if sr.returncode != 0:
        reasons.append('export-disk-state-unreadable(rc=%d)' % sr.returncode)
    elif not re.search(r'Filesystem state:\s+clean', sr.stdout):
        reasons.append('export-disk-not-cleanly-unmounted')
    lib = os.path.join(os.path.dirname(LANE), 'contract10-candidate', 'lib')
    if lib not in sys.path:
        sys.path.insert(0, lib)
    try:
        from dsmack_compose_contract import validate_receipt_bytes
    except ImportError:
        return ['contract-library-unavailable:%s' % lib], facts
    for sha in sorted(expected_manifests):
        mname = name_by_sha.get(sha)
        if mname is None:
            reasons.append('expected-manifest-not-run:%s' % sha)
            continue
        rp = os.path.join(outdir, mname, 'receipt.json')
        if not os.path.isfile(rp):
            reasons.append('receipt-missing:%s' % mname)
            continue
        rb = open(rp, 'rb').read()
        rsha = hashlib.sha256(rb).hexdigest()
        if receipts_written.get(mname) != rsha:
            reasons.append('receipt-hash-vs-console-mismatch:%s' % mname)
        manifest_raw = open(os.path.join(workload_dir, 'manifests',
                                         mname + '.app-compose.json'), 'rb').read()
        env_path = os.path.join(workload_dir, 'envelopes', mname + '.envelope.json')
        env_raw = open(env_path, 'rb').read() if os.path.isfile(env_path) else None
        try:
            validate_receipt_bytes(manifest_raw, rb, envelope_bytes=env_raw)
        except Exception as exc:  # the contract library's refusal classes vary
            reasons.append('receipt-invalid:%s:%s' % (mname, type(exc).__name__))
            continue
        receipt = json.loads(rb)
        if receipt.get('manifest_sha256') != sha:
            reasons.append('receipt-manifest-sha-mismatch:%s' % mname)
        if (receipt.get('base_vm') or {}).get('os_image_hash') != pin:
            reasons.append('receipt-admits-other-bundle:%s' % mname)
        outputs = receipt.get('outputs') or {}
        if outputs.get('status') != 'completed' or outputs.get('exit_code') != 0:
            reasons.append('receipt-not-completed-rc0:%s' % mname)
        # I/O-CONTINUITY (GIO04/GIO11): validate the COMPLETE canonical output
        # export tree a consumer would use -- recompute every recorded output
        # from the EXPORTED retained bytes (not the supervisor's run.out). The
        # SAME shared consumer the host unit tests exercise is used here, so an
        # empty-artifact bug cannot hide in a divergent mirror.
        reasons.extend(check_export_tree(os.path.join(outdir, mname), mname, receipt, rsha))
        # GIO05: the actual on-disk index digest, bound by the authoritative
        # console closure record (verify_result_closure in main).
        idx_sha = None
        idx_disk = os.path.join(outdir, mname, 'outputs', 'index.json')
        if os.path.isfile(idx_disk):
            idx_sha = sha256f(idx_disk)
        facts[mname] = {'receipt_sha256': rsha, 'manifest_sha256': sha, 'index_sha256': idx_sha,
                        'run_id': receipt.get('run_id')}
    keep = os.path.join(ev, '%s-export-extract' % run_name)
    # GIO11 (image-lane live repro): `debugfs rdump` of an ext4 image recreates a
    # ROOT-OWNED lost+found/ in outdir; a cross-filesystem shutil.move then tries
    # to copy+unlink it as the non-root launcher and raised PermissionError AFTER
    # poweroff, crashing before the verdict printed. Copy the extract EXCLUDING
    # lost+found (an ext4 fsck artifact, never exported evidence) and drop the
    # source best-effort, so the verdict is always produced.
    shutil.copytree(outdir, keep, ignore=shutil.ignore_patterns('lost+found'))
    print('deferred-host-gc:', outdir)
    return reasons, facts


def sample_stats(name, stop, peak):
    while not stop.is_set():
        try:
            r = subprocess.run(['docker', 'stats', '--no-stream', '--format',
                                '{{.CPUPerc}} {{.MemUsage}}', name],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.split()
                peak['cpu'] = max(peak['cpu'], float(parts[0].rstrip('%')))
                mem = parts[1].split('/')[0].strip()
                v = float(mem[:-3] if mem[-3:] in ('GiB', 'MiB') else mem)
                if mem.endswith('GiB'):
                    v *= 1024
                peak['mem_mb'] = max(peak['mem_mb'], v)
        except Exception:
            pass
        stop.wait(5)


# GIO02: the OWNED PRIVATE runtime paths (the unmeasured vde image, its packed
# tar and its 0700 staging tree).  A removal failure on ANY of these leaves
# private envelope/broker bytes on the host and MUST fail the run -- it is not
# a best-effort cleanup.
_PRIVATE_RUNTIME_FILES = ('private.img', 'private.tar')
_PRIVATE_RUNTIME_DIRS = ('private-stage',)
# Non-private runtime scratch/staging: not private bytes, but still owned, so a
# residue is reported (never a false "cleaned").
_RUNTIME_FILES = ('scratch.img', 'workload.img', 'ttyAMA0.log')
_RUNTIME_DIRS = ('verified-boot', 'verifier', 'workload-stage', 'export-extract')


def finalize_runtime_cleanup(rt, cleanup_failed, require_residue_free=False):
    """Close processes/FDs in caller; defer same-UID mutable-name garbage collection.

    No stat/check followed by unlink/rename can establish namespace exclusion.
    Report all potentially retained paths without touching them. A policy that
    requires residue-free completion refuses; default engineering retention is
    explicit and does not assert deletion of private bytes.
    """
    names = _PRIVATE_RUNTIME_FILES + _PRIVATE_RUNTIME_DIRS + _RUNTIME_FILES + _RUNTIME_DIRS
    residue = ['deferred-host-gc:' + os.path.join(rt, name) for name in names]
    if require_residue_free:
        cleanup_failed.append('residue-free-policy-unconfirmed')
    return residue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--files', default=BUNDLE_DIR, help='image bundle files/ dir (staged + verified before boot)')
    ap.add_argument('--pin', default=BUNDLE_PIN, help='required os_image_hash; refuse to boot anything else')
    ap.add_argument('--workload', default='/data/amiller/dsmack/attested-runner-20261020/dstack-runner-join/build/runner-inputs')
    ap.add_argument('--name', required=True)
    ap.add_argument('--runtime-dir', default=os.path.join(LANE, 'build', 'runtime'),
                    help='scratch/staging dir (kept OUTSIDE the frozen candidate)')
    ap.add_argument('--evidence-dir', default=os.path.join(LANE, 'evidence'))
    ap.add_argument('--timeout', type=int, default=1800, help='engineering observation deadline; task runtime limits remain manifest-bound')
    ap.add_argument('--scratch-bytes', type=int, default=1073741824, help='Mini-equivalent scratch capacity; default 1 GiB')
    ap.add_argument('--mem', type=int, default=DECLARED_MEM_MIB)
    ap.add_argument('--smp', type=int, default=DECLARED_VCPUS)
    ap.add_argument('--cpu', default='max')
    ap.add_argument('--descriptor-launcher-image', required=True, help='immutable derived QEMU image ID embedding the static descriptor helper')
    ap.add_argument('--descriptor-launcher-sha256', required=True, help='independently pinned loader helper digest')
    ap.add_argument('--lock-wait', type=int, default=480)
    ap.add_argument('--base-only', action='store_true')
    ap.add_argument('--built-artifacts-lock', default=None,
                    help='R01: JSON lock emitted by the GATED build/delivery procedure, binding the '
                         'rebuilt base os_image_hash + harness image digest + repaired wrapper hashes. '
                         'REQUIRED: the command fails closed without it and refuses stale identities.')
    ap.add_argument('--expect-manifest', action='append', default=[], metavar='SHA256',
                    help='R06: expected workload manifest_sha256 (repeat once per manifest). Acceptance '
                         'requires EXACTLY this set of manifests to each validate, run rc=0 and write a '
                         'receipt. REQUIRED unless --base-only.')
    ap.add_argument('--max-log-bytes', type=int, default=16 * 1024 * 1024,
                    help='R04: cap bytes read from the boot/console logs (fail-closed storage bound)')
    ap.add_argument('--max-workload-bytes', type=int, default=1024 * 1024 * 1024,
                    help='R04: cap the assembled workload disk size (fail-closed storage bound)')
    ap.add_argument('--require-residue-free', action='store_true',
                    help='refuse launch: same-UID host namespace does not permit verified destructive cleanup')
    ap.add_argument('--no-require-acceptance', action='store_true',
                    help='record the verdict but do not exit nonzero (diagnostics only)')
    args = ap.parse_args()
    if args.smp != 1 or not 256 <= args.mem <= 4096:
        raise SystemExit('smoke bounds: exactly 1 vCPU, 256..4096 MiB')
    if not 1 <= args.timeout <= 3600:
        raise SystemExit('engineering observation deadline bound: 1..3600 s')
    if args.scratch_bytes != 1073741824:
        raise SystemExit('measured Mini scratch profile requires exactly 1 GiB')
    # R01: fail closed unless the rebuilt-artifacts lock is supplied and binds
    # fresh identities; --pin must equal the rebuilt base os_image_hash.
    if args.descriptor_launcher_image != DESCRIPTOR_IMAGE_ID or not _HEX64.fullmatch(args.descriptor_launcher_sha256):
        raise SystemExit('descriptor loader image/digest pin malformed')
    if args.descriptor_launcher_sha256 != DESCRIPTOR_HELPER_SHA256:
        raise SystemExit('descriptor helper does not match frozen immutable image lock')
    built_lock = enforce_built_artifacts_lock(args.built_artifacts_lock, args.pin)
    # R06: the expected workload identities are REQUIRED for a real acceptance.
    if not args.base_only and not args.expect_manifest:
        raise SystemExit('R06: --expect-manifest is required (once per expected workload manifest) so '
                         'acceptance can enforce the exact two-workload set; refusing an any>=1 verdict.')
    if args.require_residue_free:
        raise SystemExit('residue-free host cleanup cannot be established; launch refused')
    expected_manifests = set(args.expect_manifest)
    # F03/S02: the engineering launch MUST equal the declared base_vm
    # resources -- receipts declare this tuple, so a 4vCPU/2560MiB run under a
    # 2/2048 declaration is a false receipt (try4's exact defect). FATAL.
    if (args.smp, args.mem) != (DECLARED_VCPUS, DECLARED_MEM_MIB):
        raise SystemExit('S02: launch resources %dvCPU/%dMiB do not equal the declared base_vm '
                         '%dvCPU/%dMiB; receipts would declare resources the run did not use. '
                         'Refusing.' % (args.smp, args.mem, DECLARED_VCPUS, DECLARED_MEM_MIB))

    RT = os.path.abspath(args.runtime_dir)
    EV = os.path.abspath(args.evidence_dir)
    os.makedirs(RT, mode=0o700, exist_ok=False)
    # GIO02: the runtime directory holds the private-stage, private.tar and the
    # unmeasured vde image; enforce 0700 so private bytes are never group/world
    # readable even transiently.
    os.chmod(RT, 0o700)
    os.makedirs(EV, exist_ok=True)
    _assert_image_pins()
    files = os.path.abspath(args.files)

    # R03: single bounded lock owner -- ALWAYS acquire the shared lock here.
    # The prior DSMACK_ZED_LOCK_HELD=1 ambient bypass is removed: there is no
    # env-controlled way to skip the lock (the frozen command passes no outer
    # flock, so this launcher is the sole acquirer). Bounded wait, fail closed.
    shared = None
    lane_lock = None
    shared = open(SHARED_LOCK, 'w')
    print('acquiring shared lock %s (wait <= %ds)' % (SHARED_LOCK, args.lock_wait), flush=True)
    t0 = time.time()
    while True:
        try:
            fcntl.flock(shared, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            if time.time() - t0 > args.lock_wait:
                raise SystemExit('shared zed-vm.lock busy too long; not starting a VM')
            time.sleep(10)
    print('shared lock held after %.0fs' % (time.time() - t0))
    # R04/S04: the OVERALL deadline starts now (after lock acquisition, which
    # is separately bounded by --lock-wait) and covers staging, admission,
    # formatting, workload build, the QEMU wait AND the post-run extraction;
    # every host subprocess timeout below is clipped to the remaining budget.
    start_overall_deadline(args.timeout)

    p = None
    stage_dir = None
    stop = None
    sampler = None
    log_watch = None
    cleanup_failed = []
    container = owned_container_name('dstackboot', args.name)
    verdict = {'accepted': False, 'reasons': ['launcher-did-not-complete']}
    try:
        lane_lock = open(os.path.join(RT, 'vm.lock'), 'w')
        fcntl.flock(lane_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        before = bundle_snapshot(EV, files, 'before', args.name)
        # F03: stage the boot-consumed bytes privately, then verify+consume them.
        stage_dir, consumed = stage_verified(RT, files)
        os_image_hash = admit(RT, stage_dir, args.pin, args.name)
        metadata = json.load(open(os.path.join(stage_dir, 'metadata.json')))
        cmdline = metadata['cmdline']
        # F03: pass the MEASURED cmdline verbatim; never mutate post-verification.
        if 'console=' not in cmdline:
            raise SystemExit('measured cmdline carries no console= directive; refusing to inject one '
                             '(declared must equal actual)')
        append = cmdline
        # S02: bind the delivered workload to the pinned rebuilt identity
        # BEFORE boot (manifest base_vm tuple, admission set, expected shas).
        name_by_expected_sha = {}
        if not args.base_only:
            name_by_expected_sha = bind_workload_to_pin(
                args.workload, args.pin, cmdline, args.smp, args.mem, expected_manifests)

        log_path = os.path.join(EV, 'boot-%s.log' % args.name)
        tty_path = os.path.join(RT, 'ttyAMA0.log')
        if os.path.lexists(tty_path):
            raise SystemExit('refusing occupied console output path')
        remaining_budget('disk-format')
        fresh_scratch(RT, os.path.join(RT, 'scratch.img'), args.name, files, cmdline)
        fresh_export(RT, os.path.join(RT, 'export.img'), args.name, files, cmdline)
        if os.stat(os.path.join(RT, 'scratch.img')).st_size != args.scratch_bytes:
            raise SystemExit('admitted scratch template capacity differs from selected Mini profile')
        print('scratch disk: admitted fresh-copy %d bytes' % args.scratch_bytes)
        priv_present = False
        if not args.base_only:
            # S04: the byte cap is enforced WHILE staging/packing inside.
            build_workload_disk(RT, args.workload, os.path.join(RT, 'workload.img'),
                                args.max_workload_bytes)
            # I/O-CONTINUITY: build the OPTIONAL vde private-input disk from the
            # envelope + broker channels (returns False when there is nothing
            # private to deliver -- then no vde drive is attached below).
            priv_present = build_private_disk(RT, args.workload, os.path.join(RT, 'private.img'),
                                              MAX_PRIVATE_BYTES)
        remaining_budget('qemu-launch')

        # Consume the SAME staged, verified files (host verify -> qemu open ->
        # guest dm-verity all over /stage).
        cmd = ['docker', 'run', '--rm', '-i', '--name', container,
               '-v', '%s:/b:ro' % stage_dir, '-v', '%s:/rt' % RT, args.descriptor_launcher_image,
               '/descriptor-launch', '--',
               '-M', 'virt', '-cpu', args.cpu, '-accel', 'tcg,thread=multi',
               '-smp', str(args.smp), '-m', str(args.mem),
               '-kernel', '/b/Image', '-initrd', '/b/initramfs.cpio.gz', '-append', append,
               '-device', 'virtio-serial-pci', '-device', 'virtconsole,chardev=ch0',
               '-chardev', 'stdio,id=ch0,signal=off',
               '-serial', 'file:/rt/ttyAMA0.log',
               '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0,romfile=',
               '-display', 'none', '-monitor', 'none', '-no-reboot',
               '-drive', 'if=virtio,format=raw,file=/b/rootfs.squashfs.verity,readonly=on',
               '-drive', 'if=virtio,format=raw,file=/rt/scratch.img',
               ] + ([] if args.base_only else
            ['-drive', 'if=virtio,format=raw,file=/rt/workload.img,readonly=on']
       ) + ['-drive', 'if=virtio,format=raw,file=/rt/export.img'] + (
            # vde: the OPTIONAL UNMEASURED private-input disk, appended LAST so
            # the device order stays vda=rootfs vdb=scratch vdc=workload
            # vdd=export vde=private (read-only; the guest only ever reads it).
            ['-drive', 'if=virtio,format=raw,file=/rt/private.img,readonly=on']
            if priv_present else [])
        print('+', ' '.join(cmd[6:20]), '...', flush=True)
        t0 = time.time()
        stop = threading.Event(); peak = {'cpu': 0.0, 'mem_mb': 0.0}
        sampler = threading.Thread(target=sample_stats, args=(container, stop, peak))
        sampler.start()
        # S04: watch log growth DURING the run (not merely cap the post-run
        # read): on overflow the VM is killed and acceptance rejects below --
        # a log that outgrew the bound can hide later failures (S05).
        log_overflow = {'hit': False}

        def _watch_log_sizes():
            while not stop.is_set():
                for pth in (log_path, tty_path):
                    try:
                        if os.path.exists(pth) and os.path.getsize(pth) > args.max_log_bytes:
                            log_overflow['hit'] = True
                    except OSError:
                        pass
                if log_overflow['hit']:
                    print('S04: log byte bound exceeded during the run; killing the VM', file=sys.stderr)
                    try:
                        subprocess.run(['docker', 'kill', container], capture_output=True, timeout=60)
                    except (OSError, subprocess.SubprocessError):
                        pass
                    return
                stop.wait(2)
        log_watch = threading.Thread(target=_watch_log_sizes)
        log_watch.start()
        with open(log_path, 'wb') as log:
            p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            # R04: the QEMU wait is bounded by the REMAINING overall deadline
            # (which already covered staging/admission/formatting), not a fresh
            # full --timeout -- so the whole run honors one deadline.
            qemu_budget = int(remaining_budget('qemu-boot'))
            try:
                rc = p.wait(timeout=qemu_budget)
                print('qemu exited rc=%d after %.0fs' % (rc, time.time() - t0))
            except subprocess.TimeoutExpired:
                print('TIMEOUT after %ds (overall budget): killing VM' % qemu_budget)
                subprocess.run(['docker', 'kill', container], capture_output=True, timeout=60)
                try:
                    p.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()

        # R04: bound bytes read from the console/boot logs (fail-closed storage).
        def _read_capped(path):
            with open(path, 'rb') as fh:
                data = fh.read(args.max_log_bytes + 1)
            if len(data) > args.max_log_bytes:
                print('WARNING: %s exceeded %d-byte log bound; truncating for analysis'
                      % (os.path.basename(path), args.max_log_bytes), file=sys.stderr)
                data = data[:args.max_log_bytes]
            return data.decode('utf-8', errors='replace')
        log_txt = _read_capped(log_path)
        if os.path.exists(tty_path):
            tty_txt = _read_capped(tty_path)
            log_txt += tty_txt
        else:
            tty_txt = ''

        # GIO05: the authoritative closure record is parsed from RAW console
        # bytes (no terminal/ANSI/CR normalization), per the closure contract.
        def _read_capped_raw(path):
            try:
                with open(path, 'rb') as fh:
                    return fh.read(args.max_log_bytes + 1)[:args.max_log_bytes]
            except OSError:
                return b''
        console_streams = [_read_capped_raw(log_path)]
        if os.path.exists(tty_path):
            console_streams.append(_read_capped_raw(tty_path))
        markers = {}
        for line in log_txt.splitlines():
            m = re.match(r'(DSMACK_[A-Z_0-9]+|\[dstack-init\].*)', line)
            if m:
                markers.setdefault(m.group(1), []).append('')

        def seen(mk):
            return mk in markers
        compose_exit = None
        boundary_ok = 'DSMACK_BOUNDARY_OK_' in log_txt and 'DSMACK_BOUNDARY_FAIL' not in log_txt
        for line in log_txt.splitlines():
            m = re.match(r'DSMACK_COMPOSE_EXIT (\d+)', line)
            if m:
                compose_exit = int(m.group(1))
        runner_exits = {}
        runner_validations = {}
        runner_begin = []
        for line in log_txt.splitlines():
            m = re.match(r'DSMACK_RUNNER_EXIT (\S+) rc=(\d+) phase=(\S+)', line)
            if m:
                runner_exits.setdefault(m.group(1), {})[m.group(3)] = int(m.group(2))
            m = re.match(r'DSMACK_RUNNER_VALIDATE(_INPUTS)? (\S+) rc=(\d+)', line)
            if m:
                runner_validations.setdefault(m.group(2), {})[
                    'validate_inputs' if m.group(1) else 'validate'] = int(m.group(3))
            m = re.match(r'DSMACK_RUNNER_BEGIN (\S+) manifest_sha256=([0-9a-f]{64})', line)
            if m:
                runner_begin.append({'manifest': m.group(1), 'manifest_sha256': m.group(2)})
        runner_done = None
        m = re.search(r'DSMACK_RUNNER_DONE manifests=(\d+) failures=(\d+)', log_txt)
        if m:
            runner_done = {'manifests': int(m.group(1)), 'failures': int(m.group(2))}
        # R06: receipts actually written by the guest runner (one per manifest).
        receipts_written = {}
        for line in log_txt.splitlines():
            m = re.match(r'DSMACK_RECEIPT_WRITTEN (\S+) sha256=([0-9a-f]{64})', line)
            if m:
                receipts_written[m.group(1)] = m.group(2)
        ran_manifest_shas = {b['manifest_sha256'] for b in runner_begin}
        runner_facts = {'begins': runner_begin, 'exits': runner_exits,
                        'validations': runner_validations, 'done': runner_done,
                        'receipts_written': receipts_written}
        # R06: a detected guest FAILURE terminal is never overwritten by a later
        # POWERING_OFF marker (poweroff is emitted on BOTH the success and the
        # fail-closed paths). Compute POWERING_OFF first, then let a failure win.
        terminal = None
        if seen('DSMACK_SUPERVISOR_DONE'):
            terminal = 'supervisor_done'
        if seen('DSMACK_POWERING_OFF'):
            terminal = 'powering_off'
        if seen('DSMACK_DOCKERD_TIMEOUT') or seen('DSMACK_SUPERVISOR_FAIL'):
            terminal = 'guest_fail_closed'
        if p.returncode not in (0, None) and terminal is None:
            terminal = 'qemu_died_no_guest_terminal_marker'

        after = bundle_snapshot(EV, files, 'after', args.name)
        bundle_unchanged = before == after
        if not bundle_unchanged:
            print('BUNDLE CHANGED DURING RUN — referenced image was mutated!', file=sys.stderr)
        tty_copy = os.path.join(EV, '%s-ttyAMA0.log' % args.name)
        if os.path.exists(tty_path):
            retain_runtime_file(RT, 'ttyAMA0.log', tty_copy, args.max_log_bytes)

        # S05: preserve the export disk FIRST so acceptance can validate the
        # exported results (receipts + artifact bytes), not only console text.
        export_copy = os.path.join(EV, '%s-export.img' % args.name)
        if os.path.exists(os.path.join(RT, 'export.img')):
            retain_runtime_file(RT, 'export.img', export_copy, 1073741824)
            print('export disk preserved:', export_copy)

        # R06/S05: machine-enforced acceptance verdict from the ACTUAL console
        # AND the exported results.
        boundary_probe_ran = seen('DSMACK_BOUNDARY_PROBE_END')
        # S05: ANY marker carrying a _FAIL class (not only suffix matches --
        # e.g. DSMACK_BOUNDARY_FAIL_PROBE_EXEC) or DOCKERD_TIMEOUT rejects.
        guest_fail_markers = sorted(k for k in markers if '_FAIL' in k or k == 'DSMACK_DOCKERD_TIMEOUT')
        reasons = []
        if p.returncode != 0:
            reasons.append('qemu-rc=%s' % p.returncode)
        # S04/S05: a log that hit the byte bound may have DROPPED later
        # failures; an overflowed run is never accepted.
        if log_overflow['hit'] or os.path.getsize(log_path) > args.max_log_bytes or \
                (os.path.exists(tty_path) and os.path.getsize(tty_path) > args.max_log_bytes):
            reasons.append('log-overflow')
        if terminal not in ('supervisor_done', 'powering_off'):
            reasons.append('terminal=%s' % terminal)
        if not (seen('DSMACK_POWERING_OFF') and p.returncode == 0):
            reasons.append('poweroff-not-clean')
        if not boundary_probe_ran:
            reasons.append('boundary-probe-did-not-run')
        if not boundary_ok:
            reasons.append('boundary_ok=false')
        if runner_done is None or runner_done.get('failures', 1) != 0 or runner_done.get('manifests', 0) < 1:
            reasons.append('runner-not-all-passed')
        if not bundle_unchanged:
            reasons.append('bundle-mutated')
        # R06: ANY guest fail-closed marker independently rejects acceptance.
        if guest_fail_markers:
            reasons.append('guest-fail-markers=%s' % ','.join(guest_fail_markers))
        # R06: require EXACTLY the expected workload identities (not any>=1).
        receipt_facts = {}
        if not args.base_only:
            if ran_manifest_shas != expected_manifests:
                reasons.append('manifest-set-mismatch: ran=%s expected=%s'
                               % (sorted(ran_manifest_shas), sorted(expected_manifests)))
            # each expected manifest validated rc=0, ran rc=0, and wrote a receipt.
            name_by_sha = {b['manifest_sha256']: b['manifest'] for b in runner_begin}
            for sha in expected_manifests:
                name = name_by_sha.get(sha)
                if name is None:
                    reasons.append('expected-manifest-not-run:%s' % sha)
                    continue
                if runner_validations.get(name, {}).get('validate') != 0:
                    reasons.append('validate-not-ok:%s' % name)
                if runner_exits.get(name, {}).get('run') != 0:
                    reasons.append('run-not-ok:%s' % name)
                if receipts_written.get(name) is None:
                    reasons.append('no-receipt:%s' % name)
            # S05: validate the EXPORTED receipts/artifacts (extracted, never
            # mounted) against the delivered manifest/envelope bytes, the
            # console-declared receipt hashes and the booted bundle identity.
            receipt_reasons, receipt_facts = verify_exported_receipts(
                RT, EV, args.name, args.workload, args.pin, expected_manifests,
                receipts_written, name_by_sha)
            reasons.extend(receipt_reasons)
        if not args.base_only:
            ctx_hash, ctx_selectors, ctx_error = closure_context_sha256_and_selectors(args.workload)
            if ctx_error:
                reasons.append(ctx_error)
            closure, closure_errors = parse_result_closure_streams(console_streams)
            reasons.extend(closure_errors)
            if closure is not None and ctx_error is None:
                reasons.extend(verify_result_closure(closure, ctx_hash, ctx_selectors, receipt_facts))
        verdict = {'accepted': not reasons, 'reasons': reasons or ['all-acceptance-checks-passed'],
                   'expected_manifests': sorted(expected_manifests),
                   'ran_manifests': sorted(ran_manifest_shas),
                   'receipts_written': receipts_written,
                   'exported_receipts_verified': receipt_facts}

        summary = {'name': args.name, 'qemu_rc': p.returncode, 'seconds': round(time.time() - t0),
                   'scratch_capacity_bytes': args.scratch_bytes, 'engineering_observation_budget_seconds': args.timeout,
                   'timeout': args.timeout, 'mem_mib': args.mem, 'smp': args.smp, 'accel': 'tcg,thread=multi',
                   'os_image_hash': os_image_hash, 'bundle_pinned': args.pin, 'bundle_path': files,
                   'staged_consumed_sha256': consumed,
                   'declared_resources': {'vcpus': DECLARED_VCPUS, 'memory_mib': DECLARED_MEM_MIB},
                   'bundle_unchanged': bundle_unchanged, 'cmdline': append, 'cmdline_verbatim': append == cmdline,
                   'markers': {k: len(v) for k, v in sorted(markers.items())},
                   'runner': runner_facts,
                   'terminal': {'marker': terminal,
                                'docker_ready': seen('DSMACK_DOCKERD_READY'),
                                'workload_verified': seen('DSMACK_WORKLOAD_VERIFIED'),
                                'compose_exit': compose_exit,
                                'boundary_probe_ran': boundary_probe_ran,
                                'boundary_ok': boundary_ok,
                                'poweroff_clean': seen('DSMACK_POWERING_OFF') and p.returncode == 0,
                                'guest_fail': guest_fail_markers},
                   'acceptance': {'accepted': False, 'reasons': ['pending-checked-process-closure']},
                   'qemu_container_peak': peak,
                   'log': os.path.relpath(log_path, LANE),
                   'ttyAMA0_log': os.path.relpath(tty_copy, LANE) if os.path.exists(tty_path) else None,
                   'workload_dir': args.workload}
        jp = os.path.join(EV, 'boot-%s-summary.json' % args.name)
        json.dump(summary, open(jp, 'w'), indent=1)
        print(json.dumps(summary['markers'], indent=1)[:2000])
        print(json.dumps(summary['terminal'], indent=1))
        print('acceptance:', json.dumps(verdict))
        print('summary:', jp)
    finally:
        # R04/S04: stop every OWNED process/container BEFORE deleting backing
        # files, and CONFIRM each removal. A failed `docker rm -f` OR a failed
        # `docker ps` re-check is treated as NOT CONFIRMED and fails the run
        # (a docker client error never counts as evidence of termination).
        if stop is not None:
            stop.set()
        for th in (sampler, log_watch):
            if th is not None:
                try:
                    th.join(timeout=15)
                except RuntimeError:
                    pass
        for cname in OWNED_CONTAINERS:
            try:
                subprocess.run(['docker', 'rm', '-f', cname], capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError):
                cleanup_failed.append('rm-failed:%s' % cname)
                continue
            try:
                chk = subprocess.run(['docker', 'ps', '-a', '--filter', 'name=^%s$' % cname,
                                      '--format', '{{.ID}}'],
                                     capture_output=True, text=True, timeout=60)
                if chk.returncode != 0:
                    cleanup_failed.append('ps-failed:%s' % cname)
                elif chk.stdout.strip():
                    cleanup_failed.append('still-present:%s' % cname)
            except (OSError, subprocess.SubprocessError):
                cleanup_failed.append('ps-failed:%s' % cname)
        if not cleanup_failed:
            print('all %d owned containers confirmed removed' % len(OWNED_CONTAINERS))
        else:
            print('S04: cleanup NOT confirmed: %s' % '; '.join(cleanup_failed), file=sys.stderr)
        # Reap the launcher-side docker client process if still alive.
        if p is not None and p.poll() is None:
            try:
                p.terminate(); p.wait(timeout=15)
            except (OSError, subprocess.SubprocessError):
                try:
                    p.kill(); p.wait(timeout=15)
                except (OSError, subprocess.SubprocessError):
                    cleanup_failed.append('launcher-process-not-reaped')
        for th in (sampler, log_watch):
            if th is not None and th.is_alive():
                cleanup_failed.append('owned-thread-not-stopped')
        # GIO02: exception-safe cleanup of runtime scratch + staging that
        # TRACKS and VERIFIES removal of every owned path (locks release as the
        # fds drop when the process exits).  A private.img/private.tar/
        # private-stage removal failure now enters cleanup_failed (as
        # private-residue) and fails the run, instead of being suppressed while
        # the launcher printed that disks+staging were cleaned.  Runs on every
        # path (success/failure/cancellation) via this encompassing finally.
        residue = finalize_runtime_cleanup(RT, cleanup_failed, args.require_residue_free)
        if residue:
            print('GIO02: host garbage collection deferred; retained paths: %s' % '; '.join(residue), file=sys.stderr)
        else:
            print('owned processes stopped; no residue-free filesystem claim')

    if cleanup_failed:
        verdict['accepted'] = False
        verdict['reasons'] = verdict.get('reasons', []) + ['process-closure-unconfirmed']
    if 'summary' in locals():
        summary['acceptance'] = verdict
        summary['host_cleanup'] = {'garbage_collection': 'deferred',
                                   'residue_free': False,
                                   'process_errors': cleanup_failed}
        with _HostIOAlarm('final-summary-retention'):
            with open(jp, 'w') as report:
                json.dump(summary, report, indent=1)
                report.flush()
                os.fsync(report.fileno())
            sync_parent(jp)

    # S04/GIO02: unconfirmed termination of ANY owned container OR any owned
    # private/runtime residue fails the run (no false "cleaned").
    if cleanup_failed:
        raise SystemExit('CLEANUP NOT CONFIRMED (S04 containers / GIO02 owned residue): %s'
                         % '; '.join(cleanup_failed))
    # R06: fail the process when the guest did not accept.
    if not verdict['accepted'] and not args.no_require_acceptance:
        raise SystemExit('ACCEPTANCE FAILED: %s' % '; '.join(verdict['reasons']))


if __name__ == '__main__':
    main()
