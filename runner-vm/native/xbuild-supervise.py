#!/usr/bin/env python3
"""F12 — bounded, reproducible, ISOLATED cross-build supervisor for the v3 archive.

Resolves the review's F12 defects:

  * PINNED toolchain by EXACT version, not a substring. The previous check used
    `EXPECT_RUSTC in rustc_stdout`, which matches any 1.97.1.x and never pins the
    commit/date. We now require the FULL version line to match EXACTLY
    (`rustc 1.97.1 (8bab26f4f 2026-07-14)`) and assert the aarch64-apple-darwin
    `rust-std` component is present in the pinned toolchain. (The darwin std is a
    component that currently lives only under the `stable-x86_64-unknown-linux-gnu`
    toolchain dir; we pin that dir BUT verify its exact version content, so a
    silently-rolled `stable` is rejected rather than trusted by name.)

  * UNIQUE, RESERVED staging — never a fixed path recursively deleted on entry.
    The old supervisor rmtree()'d a fixed STAGING at startup, so two concurrent
    invocations could delete each other's build tree. We now RESERVE a fresh,
    uniquely-named staging directory per run under an owned base (mkdtemp), never
    touching any other run's tree, and we take an EXCLUSIVE, NON-BLOCKING file
    lock to enforce the stated single-concurrent-build policy (a second
    invocation fails fast instead of racing).

  * BOUNDED process-group cleanup with RETAINED ownership on unconfirmed
    termination. The old cleanup fell back to an UNBOUNDED `proc.wait()` after
    SIGKILL, which could hang forever on an unkillable descendant. We now wait
    with a hard deadline after SIGKILL and, if the group still cannot be
    confirmed reaped, report the retained PGID and exit fail-closed rather than
    blocking indefinitely.

Produces libdsmack_hvf_returning.a for aarch64-apple-darwin with the v3 symbols
(dsmack_ctl_v3_init, dsmack_ctl_join_{vm_new,run,finalize,receipt,result,free}_v3,
dsmack_ctl_join_abi_version_v3, dsmack_ctl_join_err_cap_min_v3). The Swift
relink/app build and any execution are a SEPARATE Mac gate — NOT run here. This
is a CROSS-COMPILE (no Mac, no VM, no SDK: a staticlib only archives objects).
"""
import os, sys, time, signal, shutil, subprocess, resource, pathlib, fcntl, tempfile, select, json, hashlib, traceback

HERE = pathlib.Path(__file__).resolve().parent               # candidate/
MANIFEST = HERE / "source-tree/apple-static/Cargo.toml"
TARGET = "aarch64-apple-darwin"

# PINNED existing toolchain (exact dir). The aarch64-apple-darwin rust-std
# component is installed only under this toolchain dir in this environment; we
# pin the dir BUT verify its EXACT version below so a rolled `stable` is refused.
TOOLCHAIN = pathlib.Path.home() / ".rustup/toolchains/stable-x86_64-unknown-linux-gnu"
# EXACT expected rustc version line — NOT a substring. A different build/date is
# a different toolchain and is refused.
EXPECT_RUSTC_FULL = "rustc 1.97.1 (8bab26f4f 2026-07-14)"
CARGO = TOOLCHAIN / "bin/cargo"
RUSTC = TOOLCHAIN / "bin/rustc"

# Owned staging BASE: each run RESERVES a fresh unique subdir here (mkdtemp);
# an existing run's tree is NEVER deleted. Overridable, but never a shared target.
STAGING_BASE = pathlib.Path(os.environ.get(
    "XBUILD_STAGING_BASE",
    "/data/amiller/dsmack/attested-runner-20261020/loop40-native-nat-repair4/.xbuild-staging"))
# Exclusive, non-blocking lock file enforcing the single-concurrent-build policy.
LOCK_PATH = pathlib.Path(os.environ.get(
    "XBUILD_LOCK",
    "/data/amiller/dsmack/attested-runner-20261020/loop40-native-nat-repair4/.xbuild.lock"))

# Aggregate bounds (F12).
WALL_SECONDS = 1800          # hard ceiling, SIGKILL the build group past this
GRACE_SECONDS = 30
KILL_CONFIRM_SECONDS = 30    # bounded wait for group reap after SIGKILL
AGG_RSS_BYTES = 12 * (1 << 30)   # 12 GiB process-tree RSS ceiling
STAGING_MAX_BYTES = 20 * (1 << 30)
MIN_FREE_BYTES = 10 * (1 << 30)
# CONCURRENCY: single build; cargo jobs bounded so the RSS ceiling is realistic.
CARGO_JOBS = int(os.environ.get("XBUILD_JOBS", "4"))

def die(msg, code=2):
    print(f"xbuild-supervise: FAIL: {msg}", file=sys.stderr); sys.exit(code)

def tree_rss_bytes(pgid):
    """Sum RSS over the build process group (best-effort via /proc)."""
    total = 0
    for p in pathlib.Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            if os.getpgid(int(p.name)) != pgid:
                continue
            with open(p / "statm") as f:
                rss_pages = int(f.read().split()[1])
            total += rss_pages * resource.getpagesize()
        except (ProcessLookupError, FileNotFoundError, PermissionError, ValueError):
            continue
    return total

def dir_bytes(path):
    total = 0
    for dp, _dn, fn in os.walk(path):
        for name in fn:
            try:
                total += os.lstat(os.path.join(dp, name)).st_size
            except OSError:
                pass
    return total

def group_members(pgid):
    """Enumerate LIVE (non-zombie) members of the process group by scanning
    /proc and reading each task's pgrp from stat. Zombies are already reaped and
    do not count as live members. Returns a sorted list of PIDs."""
    members = []
    for p in pathlib.Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        pid = int(p.name)
        try:
            with open(p / "stat") as f:
                data = f.read()
            # Fields after the "(comm)" field: state ppid pgrp session ...
            after = data.rsplit(")", 1)[1].split()
            state = after[0]
            pgrp = int(after[2])
        except (FileNotFoundError, ProcessLookupError):
            continue
        if pgrp != pgid:
            continue
        if state == "Z":   # zombie: already dead, not a live member
            continue
        members.append(pid)
    return sorted(members)

def group_alive(pgid):
    """True if any LIVE process remains in the group."""
    try:
        return bool(group_members(pgid))
    except OSError:
        return True  # inspection failure cannot establish quiescence

def _reap_direct_child(proc, timeout):
    """Best-effort bounded wait+reap of the DIRECT child so it does not linger
    as a zombie. Ignores TimeoutExpired."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    except (ChildProcessError, OSError):
        pass

def confirm_group_reaped(proc, pgid):
    """Confirm the ENTIRE build group (by PGID) is reaped on EVERY exit path.

    Escalation is driven by the REMAINING GROUP MEMBERS, not by the direct
    child's wait:

      1. If the group is already empty, done.
      2. SIGTERM the group; poll members for up to GRACE_SECONDS.
      3. If members remain, SIGKILL the group; poll members for up to
         KILL_CONFIRM_SECONDS.
      4. If members STILL remain, hand the residual PGID to a real persistent
         owner (fork+setsid detached reaper) that keeps SIGKILLing it after we
         exit, and report the transfer.

    Returns a dict:
      {"status": "clean"}
      {"status": "transferred", "owner_pid": <pid>, "residual": [pids...],
       "pgid": <pgid>}
    """
    # Reap the direct child first (bounded) so we don't leave it as a zombie and
    # so group_members reflects only genuinely-live descendants.
    _reap_direct_child(proc, timeout=0.1)

    if not group_alive(pgid):
        return {"status": "clean"}

    # --- stage 1: SIGTERM, escalate on remaining members ---
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError as error:
        print(f"group signal failed; retaining ownership: {error}", file=sys.stderr)
    deadline = time.monotonic() + GRACE_SECONDS
    while time.monotonic() < deadline:
        _reap_direct_child(proc, timeout=0.0)
        if not group_alive(pgid):
            return {"status": "clean"}
        time.sleep(0.25)

    # --- stage 2: members remain -> SIGKILL, re-check members ---
    try:
        os.killpg(pgid, signal.SIGKILL)
    except OSError as error:
        print(f"group signal failed; retaining ownership: {error}", file=sys.stderr)
    deadline = time.monotonic() + KILL_CONFIRM_SECONDS
    while time.monotonic() < deadline:
        _reap_direct_child(proc, timeout=0.0)
        if not group_alive(pgid):
            return {"status": "clean"}
        time.sleep(0.25)

    # --- stage 3: STILL alive -> transfer to a real persistent owner ---
    try:
        residual = group_members(pgid)
    except OSError as error:
        residual = [f"inspection-unconfirmed: {error}"]
    if not residual:
        return {"status": "clean"}
    while True:
        try:
            owner_pid = spawn_persistent_owner(pgid)
            break
        except Exception as error:
            print(f"owner transfer failed; supervisor retains PGID {pgid}: {error}", file=sys.stderr)
            if not group_alive(pgid):
                return {"status": "clean"}
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError as signal_error:
                print(f"retained owner signal error: {signal_error}", file=sys.stderr)
            time.sleep(0.5)
    return {"status": "transferred", "owner_pid": owner_pid,
            "residual": residual, "pgid": pgid}

# Where the persistent-owner reaper records its PID (overridable).
OWNER_PID_FILE = pathlib.Path(os.environ.get(
    "XBUILD_OWNER_PIDFILE",
    "/data/amiller/dsmack/attested-runner-20261020/loop40-native-nat-repair4/.xbuild-owner.pid"))
OWNER_ACK_SECONDS = 5

def spawn_persistent_owner(pgid):
    """Transfer only after child initializes its durable status and acknowledges.

    No lifetime expiry: permission/signal/inspection failures remain observable
    and are retried until the target group is confirmed empty.
    """
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd); os.close(write_fd)
        raise
    if pid:
        os.close(write_fd)
        try:
            ready, _, _ = select.select([read_fd], [], [], OWNER_ACK_SECONDS)
            ack = os.read(read_fd, 128) if ready else b""
            if ack != b"READY\n":
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # Initialization failure is not transfer. Reap the failed
                # candidate without waiting indefinitely on an unkillable task.
                deadline = time.monotonic() + OWNER_ACK_SECONDS
                while time.monotonic() < deadline:
                    try:
                        done, _ = os.waitpid(pid, os.WNOHANG)
                        if done:
                            break
                    except ChildProcessError:
                        break
                    time.sleep(0.05)
                raise RuntimeError(f"owner {pid} did not acknowledge initialization: {ack!r}")
            return pid
        finally:
            os.close(read_fd)
    os.close(read_fd)
    try:
        os.setsid()
        if os.getpgrp() == pgid:
            raise RuntimeError("owner aliases target group")
        # Keep the build lock while residual work is owned.
        OWNER_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        status_file = OWNER_PID_FILE.with_name(OWNER_PID_FILE.name + f".{os.getpid()}.json")
        def status(state, error=None):
            payload = {"owner_pid": os.getpid(), "pgid": pgid,
                       "state": state, "error": error, "at": time.time()}
            with open(status_file, "w") as stream:
                json.dump(payload, stream); stream.flush(); os.fsync(stream.fileno())
        status("initialized")
        OWNER_PID_FILE.write_text(str(os.getpid()) + "\n")
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        os.close(devnull)
        # Ignore ordinary supervisor shutdown signals: ownership persists.
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        os.write(write_fd, b"READY\n")
        os.close(write_fd)
        while True:
            try:
                if not group_alive(pgid):
                    status("confirmed-empty")
                    break
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    # Reinspect instead of treating an ambiguous signal result
                    # as proof that the whole group has disappeared.
                    pass
                status("owning")
            except BaseException as error:
                # A status-write failure also must not terminate ownership.
                try:
                    status("retrying-error", repr(error))
                except BaseException:
                    pass
            time.sleep(0.5)
    except BaseException as error:
        try:
            os.write(write_fd, ("ERROR " + repr(error)).encode()[:128])
        except OSError:
            pass
    finally:
        os._exit(0)

def source_inventory():
    root = HERE / "source-tree"
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in {"target", "__pycache__"} for part in path.relative_to(root).parts):
            continue
        entries.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(HERE)) + "\n")
    entries.append(hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest() + "  xbuild-supervise.py\n")
    return "".join(entries)

def main():
    # --- pin assertions (EXACT, not substring) ---
    if not CARGO.exists():
        die(f"pinned toolchain missing: {CARGO}")
    out = subprocess.run([str(RUSTC), "--version"], capture_output=True, text=True)
    actual = out.stdout.strip()
    if actual != EXPECT_RUSTC_FULL:
        die(f"toolchain rustc mismatch:\n  expected EXACTLY: {EXPECT_RUSTC_FULL}\n  actual:          {actual}")
    std = TOOLCHAIN / f"lib/rustlib/{TARGET}"
    if not (std / "lib").exists():
        die(f"{TARGET} rust-std not installed in pinned toolchain: {std}")
    if not MANIFEST.exists():
        die(f"manifest missing: {MANIFEST}")

    # --- single-concurrent-build lock (non-blocking; never deletes a peer) ---
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        die(f"another xbuild is already running (lock held: {LOCK_PATH})", 75)
    os.ftruncate(lock_fd, 0)
    os.write(lock_fd, f"{os.getpid()}\n".encode())

    STAGING_BASE.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(STAGING_BASE).free
    if free < MIN_FREE_BYTES:
        die(f"insufficient free disk: {free} < {MIN_FREE_BYTES}")

    # --- RESERVE a unique staging dir (never delete an existing run's tree) ---
    staging = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=str(STAGING_BASE)))

    env = os.environ.copy()
    env["PATH"] = f"{TOOLCHAIN/'bin'}:{env.get('PATH','')}"
    env["CARGO_TARGET_DIR"] = str(staging)
    env["CARGO_BUILD_JOBS"] = str(CARGO_JOBS)
    env["RUSTUP_TOOLCHAIN"] = TOOLCHAIN.name
    # OFFLINE: shared registry cache only, no network. CARGO_HOME left as the
    # user default (~/.cargo) for the read-only registry closure.
    cmd = [str(CARGO), "build", "--release", "--offline", "--locked",
           "--manifest-path", str(MANIFEST), "--target", TARGET]

    print(f"xbuild-supervise: {' '.join(cmd)}")
    print(f"  staging={staging} wall={WALL_SECONDS}s rss<= {AGG_RSS_BYTES>>30}GiB "
          f"jobs={CARGO_JOBS}")
    source_before = source_inventory()
    (staging / "BUILD-SOURCE-SHA256SUMS.txt").write_text(source_before)
    start = time.monotonic()
    proc = subprocess.Popen(cmd, env=env, start_new_session=True)
    pgid = proc.pid
    try:
        killed = None
        while proc.poll() is None:
            el = time.monotonic() - start
            if el > WALL_SECONDS:
                killed = "wall-clock"; break
            rss = tree_rss_bytes(pgid)
            if rss > AGG_RSS_BYTES:
                killed = f"aggregate RSS {rss>>20}MiB"; break
            st = dir_bytes(staging)
            if st > STAGING_MAX_BYTES:
                killed = f"staging {st>>20}MiB"; break
            if shutil.disk_usage(staging).free < MIN_FREE_BYTES:
                killed = "free disk"; break
            time.sleep(2)
    
        def finalize(reason, base_code):
            """Confirm the ENTIRE build group is reaped on THIS exit path, escalating
            on remaining members and transferring any residual to a persistent owner.
            Returns a (code, done_bool) so callers can keep going on a clean success."""
            res = confirm_group_reaped(proc, pgid)
            if res["status"] == "clean":
                if base_code == 0:
                    print(f"xbuild-supervise: build group {pgid} confirmed fully reaped")
                else:
                    print(f"xbuild-supervise: {reason}; build group {pgid} confirmed "
                          f"fully reaped", file=sys.stderr)
                return base_code, False
            # Transferred to a real, running, detached persistent owner.
            msg = (f"{reason}; build group {pgid} NOT confirmed reaped within bounds — "
                   f"residual members {res['residual']} TRANSFERRED to persistent owner "
                   f"pid={res['owner_pid']} (pidfile={OWNER_PID_FILE}), which will keep "
                   f"SIGKILLing residual PGID {pgid} after exit")
            print(f"xbuild-supervise: {msg}", file=sys.stderr)
            # A transfer is always a non-clean exit: use 125 unless the path already
            # has a more specific failure code (preserve bound 124 / cargo rc).
            return (base_code if base_code != 0 else 125), True
    
        if killed:
            print(f"xbuild-supervise: bound exceeded ({killed}); confirming/killing build "
                  f"group {pgid}", file=sys.stderr)
            code, _ = finalize(f"build stopped on bound ({killed})", 124)
            sys.exit(code)
    
        rc = proc.returncode
        if rc != 0:
            # Failed DIRECT-child exit must ALSO confirm the group (descendants can
            # outlive a failed cargo leader).
            code, _ = finalize(f"cargo build failed rc={rc}", rc)
            sys.exit(code)
    
        # Normal (rc==0) exit ALSO confirms the entire group before succeeding.
        code, transferred = finalize("cargo build succeeded", 0)
        if transferred:
            print("xbuild-supervise: build produced output but residual processes were "
                  "transferred to the persistent owner; failing closed", file=sys.stderr)
            sys.exit(code)
    
        archive = staging / TARGET / "release" / "libdsmack_hvf_returning.a"
        if not archive.exists():
            die(f"archive not produced: {archive}")
        source_after = source_inventory()
        if source_after != source_before:
            die("source changed during compilation; archive has no frozen source provenance")
        provenance = {"source_inventory_sha256": hashlib.sha256(source_before.encode()).hexdigest(),
                      "source_inventory": str(staging / "BUILD-SOURCE-SHA256SUMS.txt"),
                      "archive": str(archive), "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                      "archive_bytes": archive.stat().st_size, "rustc": actual,
                      "command": cmd, "group_quiescence": "confirmed-empty",
                      "elapsed_seconds": time.monotonic()-start}
        (staging / "BUILD-PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
        print(f"xbuild-supervise: OK in {time.monotonic()-start:.1f}s -> {archive} "
              f"({archive.stat().st_size} bytes)")
    finally:
        # Includes KeyboardInterrupt, signal cancellation, disk/proc inspection
        # errors, and output/provenance failures after successful cargo exit.
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        confirm_group_reaped(proc, pgid)

if __name__ == "__main__":
    def interrupted(signum, frame):
        raise RuntimeError(f"supervisor interrupted by signal {signum}")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    main()
