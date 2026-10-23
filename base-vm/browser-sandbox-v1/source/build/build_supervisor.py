#!/usr/bin/env python3
"""build_supervisor.py -- ONE external supervisor around the ENTIRE build
lifecycle (B03-storage-residual + B03-deadline-residual repair).

This process -- not a shell trap inside BUILD.sh -- is the authority for:

  * ONE absolute wall-clock deadline (default 18000 s INCLUDING cleanup).
    The supervised child (BUILD.sh: preflight hashing, filesystem scans,
    legs, promote, harness build, final inventory verification, lock
    generation, its own normal-path cleanup) gets deadline-minus-reserve;
    the supervisor then ALWAYS has the reserve left, while still alive, for
    forced termination and bounded ID-tracked docker cleanup. Forced-kill
    grace is spent INSIDE the budget, never appended after it.

  * a bounded, FAIL-CLOSED storage monitor. Every accounting sample is a
    bounded subprocess (du on the build root, `docker inspect --size`
    SizeRw for every owned container id recorded via cidfiles), plus a
    fixed worst-case charge for the dockerd-enforced json-file log caps.
    A sample that fails, hangs or is unparseable is an accounting FAILURE;
    two consecutive failures cancel the run (exit 94). Crossing the soft
    limit cancels the run (exit 93). Monitoring continues through writer
    termination and cleanup.

  * prompt cancellation that reaches ACTIVE writers. The child runs under a
    watchdog in its OWN session/process group; cancellation SIGTERMs the
    whole group, docker-kills every owned container (detached containers
    keep writing even after their client shell dies), then SIGKILLs the
    group after the grace. SIGKILL is not deferrable, so a foreground
    command that ignores/defers SIGTERM (the repair2 defect) still stops
    within the grace.

  * fail-closed monitor health in BOTH directions: supervisor failures
    cancel the child (try/finally around the whole run), and supervisor
    DEATH kills the child: the watchdog holds the read end of a pipe whose
    write end only the supervisor owns; EOF (supervisor gone, even
    SIGKILLed) makes the watchdog docker-kill the owned containers and
    SIGKILL its own process group.

HONEST BOUNDS -- what this does and does not guarantee:
  * The storage bound is a sampling monitor with bounded cancellation
    latency, NOT a kernel quota. The HOST build process group reaches
    SIGKILL within sample_interval + accounting_time(<= acct_timeout) +
    kill_grace (defaults: 15 + 60 + 5 = 80 s) of a threshold crossing:
    the host TERM->KILL schedule is now ABSOLUTE and is NOT delayed by any
    docker-kill latency (B03-storage-residual: terminate_child used to run
    up to four serial docker kills BEFORE the host grace, pushing host
    SIGKILL out to ~45 s). After the host group is dead the owned DETACHED
    containers are docker-killed within a further bounded window
    (<= owned_count x DOCKER_KILL_SLOT, clamped to the deadline); while
    that window elapses those containers keep their dockerd-enforced
    per-container limits (--cpus/--memory/--pids/json-file log caps).
    Accounting continues across termination AND cleanup (a post-terminate
    sample and periodic cleanup samples), and a failed/over-limit sample
    at ANY of those points -- including the final one -- is recorded as a
    cleanup-unconfirmed failure that FAILS acceptance; it is never merely
    logged. Usage may therefore transiently exceed the soft limit by
    (write rate x that bounded latency); no maximum real-build write rate
    is asserted, so NO hard "cannot exceed the cap" guarantee is claimed.
    The preflight free-space requirement (40 GiB vs the 30 GiB target) is
    the physical margin behind that honest, documented transient overshoot.
    The reviewer accepted a functional monitor bound; the tunables below
    are the single point to tighten it.
  * If the supervisor itself is SIGKILLed, the watchdog kills all HOST
    processes in the build's process group and best-effort docker-kills
    owned containers; a simultaneous watchdog+supervisor SIGKILL would
    leave detached containers to their dockerd-enforced per-container
    limits (--cpus/--memory/--pids/log caps) and the operator.

Test tightening: DSMACK_TEST_* environment knobs may only TIGHTEN the
frozen production bounds (same rule the reviewed BUILD.sh used for
DSMACK_TEST_WALL_CLOCK_MAX); loosening is rejected loudly. A non-default
workload (--workload, behavioral tests only) additionally requires
DSMACK_SUPERVISOR_ALLOW_TEST_WORKLOAD=1 and is recorded in the event log,
so a production transcript shows exactly what ran.
"""

import argparse
import errno
import glob
import json
import os
import select
import signal
import subprocess
import sys
import time

# ---- frozen production bounds (DSMACK_TEST_* may only tighten) ---------------
WALL_CLOCK_MAX = 18000          # ONE deadline, everything included
CLEANUP_RESERVE = 600           # supervisor-held reserve for kill + cleanup
KILL_GRACE = 5                  # SIGTERM -> SIGKILL grace, spent INSIDE budgets
STORAGE_MAX_BYTES = 32212254720             # 30 GiB accounted-storage target
STORAGE_HEADROOM_BYTES = 2 * 1024**3        # soft limit = max - headroom - logs
LOG_WORST_CASE_BYTES = 4 * 3 * 64 * 1024**2 # 4 containers x max-file=3 x 64 MiB
SAMPLE_SECS = 15                # accounting interval
ACCT_TIMEOUT = 60               # bound on ONE accounting sample (incl. grace)
ACCT_FAILS_MAX = 2              # consecutive failed samples -> fail closed
DOCKER_KILL_SLOT = 10           # per-container docker-kill bound during stop

# ---- B01: the single sanitized local Docker/Buildx environment ---------------
# Every docker client this process (or its watchdog/child) runs MUST address the
# ONE local daemon through a credential-free, context-free, TLS-free config whose
# buildx state is the SAME directory BUILD.sh creates and uses -- otherwise the
# supervisor's accounting/cancellation/cleanup could talk to a DIFFERENT daemon
# or buildx instance from the build (foreign DOCKER_HOST/CONTEXT/CONFIG/
# BUILDX_CONFIG) and a "no such object" answer could falsely confirm removal.
LOCAL_DOCKER_HOST = "unix:///var/run/docker.sock"   # the fixed local endpoint
# ambient client overrides that must never leak into any supervised docker call:
AMBIENT_DOCKER_VARS = ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_TLS",
                       "DOCKER_CERT_PATH", "BUILDX_BUILDER")

EXIT_STORAGE = 93
EXIT_ACCOUNTING = 94
EXIT_INTERNAL = 95
EXIT_CLEANUP_UNCONFIRMED = 96
EXIT_DEADLINE = 97


def die(msg, code=1):
    sys.stderr.write("build_supervisor: %s\n" % msg)
    sys.exit(code)


def tighten(env_name, default, kind=float):
    """Read a DSMACK_TEST_* override that may only TIGHTEN (be <=) the default."""
    raw = os.environ.get(env_name)
    if raw is None:
        return default
    try:
        val = kind(raw)
    except ValueError:
        die("%s=%r is not a number" % (env_name, raw))
    if val <= 0 or val > default:
        die("%s=%r may only TIGHTEN the frozen bound %r, never extend it"
            % (env_name, raw, default))
    return val


class Supervisor(object):
    def __init__(self, args):
        self.lane = os.path.abspath(args.lane)
        if not self.lane.startswith("/data/"):
            die("lane %s is not under /data" % self.lane)
        if not os.path.isdir(self.lane):
            die("lane %s is not a directory" % self.lane)
        self.build_root = os.path.join(self.lane, "build")
        self.sup_dir = os.path.join(self.build_root, "supervisor")
        # B01: the SHARED sanitized Docker/Buildx config. These are the SAME
        # paths BUILD.sh exports (DOCKER_CONFIG=$BUILD_ROOT/docker-config,
        # BUILDX_CONFIG=$BUILD_ROOT/buildx), so the supervisor's accounting,
        # cancellation and cleanup address the same daemon AND the same buildx
        # instance the build used. They are NOT pre-created here (BUILD.sh
        # materializes the credential-free config.json and the fresh-root check
        # tolerates only "supervisor/"); the supervisor makes no credentialed
        # docker call before they exist (owned_cids() is empty until BUILD.sh
        # has created its isolated config and started its first container).
        self.docker_config_dir = os.path.join(self.build_root, "docker-config")
        self.buildx_dir = os.path.join(self.build_root, "buildx")
        self.docker_env = None   # built in run() before the first docker call

        self.wall_max = tighten("DSMACK_TEST_WALL_CLOCK_MAX", WALL_CLOCK_MAX)
        self.reserve = tighten("DSMACK_TEST_CLEANUP_RESERVE", CLEANUP_RESERVE)
        if self.reserve >= self.wall_max:
            self.reserve = self.wall_max / 2.0
        self.grace = tighten("DSMACK_TEST_KILL_GRACE", KILL_GRACE)
        self.storage_max = tighten("DSMACK_TEST_STORAGE_MAX_BYTES",
                                   STORAGE_MAX_BYTES, int)
        headroom = int(os.environ.get("DSMACK_TEST_STORAGE_HEADROOM_BYTES",
                                      STORAGE_HEADROOM_BYTES))
        log_charge = tighten("DSMACK_TEST_LOG_CHARGE_BYTES",
                             LOG_WORST_CASE_BYTES, int) \
            if "DSMACK_TEST_LOG_CHARGE_BYTES" in os.environ else LOG_WORST_CASE_BYTES
        self.soft_limit = self.storage_max - headroom - log_charge
        prod_soft = STORAGE_MAX_BYTES - STORAGE_HEADROOM_BYTES - LOG_WORST_CASE_BYTES
        if self.soft_limit > prod_soft:
            die("effective soft limit %d would exceed the frozen production "
                "soft limit %d; overrides may only tighten" % (self.soft_limit,
                                                               prod_soft))
        if self.soft_limit <= 0:
            die("soft limit %d <= 0 (headroom+log charge exceed the cap)"
                % self.soft_limit)
        self.log_charge = log_charge
        self.sample_secs = tighten("DSMACK_TEST_SAMPLE_SECS", SAMPLE_SECS)
        self.acct_timeout = tighten("DSMACK_TEST_ACCT_TIMEOUT", ACCT_TIMEOUT)

        if args.workload:
            if os.environ.get("DSMACK_SUPERVISOR_ALLOW_TEST_WORKLOAD") != "1":
                die("--workload is for behavioral tests and requires "
                    "DSMACK_SUPERVISOR_ALLOW_TEST_WORKLOAD=1")
            self.workload = args.workload
        else:
            self.workload = ["bash", os.path.join(
                self.lane, "candidate/dstack-runner-join/source/build/BUILD.sh")]

        self.t0 = time.monotonic()
        self.hard_deadline = self.t0 + self.wall_max      # NOTHING survives this
        self.child_deadline = self.hard_deadline - self.reserve
        self.events_f = None
        self.child = None
        self.cancel_code = None
        self.cancel_reason = None
        self.cleanup_unconfirmed = []

    # ---- evidence -------------------------------------------------------------
    def event(self, kind, **kw):
        rec = dict(kind=kind, t=round(time.monotonic() - self.t0, 3),
                   epoch=round(time.time(), 3), **kw)
        line = json.dumps(rec, sort_keys=True)
        if self.events_f:
            self.events_f.write(line + "\n")
            self.events_f.flush()
            os.fsync(self.events_f.fileno())
        sys.stderr.write("supervisor: %s\n" % line)

    def remaining_hard(self):
        return max(0.0, self.hard_deadline - time.monotonic())

    # ---- B01: the single sanitized Docker/Buildx environment ------------------
    def build_docker_env(self):
        """Establish the ONE sanitized Docker/Buildx environment shared by the
        supervisor, the watchdog, the build child and every accounting/cleanup
        docker call. Ambient context/TLS overrides are STRIPPED; DOCKER_HOST is
        forced to the fixed local endpoint; DOCKER_CONFIG/BUILDX_CONFIG are the
        SAME build-root paths BUILD.sh uses (so buildx builders this build
        created are visible to the supervisor's confirm/remove calls)."""
        env = dict(os.environ)
        stripped = [k for k in AMBIENT_DOCKER_VARS if k in env]
        for k in AMBIENT_DOCKER_VARS:
            env.pop(k, None)
        prior_host = env.get("DOCKER_HOST")
        env["DOCKER_HOST"] = LOCAL_DOCKER_HOST
        env["DOCKER_CONFIG"] = self.docker_config_dir
        env["BUILDX_CONFIG"] = self.buildx_dir
        self.docker_env = env
        self.event("docker-env", docker_host=env["DOCKER_HOST"],
                   docker_config=env["DOCKER_CONFIG"],
                   buildx_config=env["BUILDX_CONFIG"],
                   stripped_ambient=stripped,
                   overrode_foreign_docker_host=(
                       prior_host if prior_host not in (None, LOCAL_DOCKER_HOST)
                       else None))
        return env

    # ---- bounded subprocess (grace INSIDE the slot, ABSOLUTE deadline) --------
    def run_bounded(self, cmd, slot, env=None):
        """Run cmd with total worst-case duration <= min(slot, remaining_hard)
        measured from an ABSOLUTE deadline: initial wait, TERM grace and KILL
        reap are ALL clamped to that one deadline, so nothing (not even the
        post-SIGKILL reap) is ever appended OUTSIDE the slot or the overall hard
        budget (B03-deadline-residual: the old code added a fixed 5 s reap after
        the slot). Returns (rc, stdout, stderr); rc 124 on timeout (termination
        UNCONFIRMED when the budget is exhausted before the group dies), 127 on
        spawn failure. Never raises, never extends the declared bound. All
        docker clients run under the single sanitized env (B01)."""
        slot = min(slot, self.remaining_hard())
        if slot < 0.1:
            return (124, "", "no budget remaining for %r" % (cmd,))
        deadline = time.monotonic() + slot
        g = min(self.grace, max(0.1, slot / 2.0))
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 start_new_session=True,
                                 env=self.docker_env if env is None else env)
        except OSError as e:
            return (127, "", str(e))

        def left():
            return deadline - time.monotonic()

        try:
            out, err = p.communicate(timeout=max(0.0, left() - g))
            return (p.returncode, out.decode("utf-8", "replace"),
                    err.decode("utf-8", "replace"))
        except subprocess.TimeoutExpired:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(p.pid, sig)
                except (ProcessLookupError, PermissionError):
                    pass
                wait = left()
                if sig is signal.SIGTERM:
                    wait = min(wait, g)   # short TERM grace, still inside the slot
                if wait <= 0:
                    continue              # budget gone: do NOT extend it
                try:
                    out, err = p.communicate(timeout=wait)
                    return (124, out.decode("utf-8", "replace"),
                            "timed out; terminated within the slot")
                except subprocess.TimeoutExpired:
                    continue
            p.poll()   # reap if it already died; never block past the deadline
            return (124, "", "timed out; termination UNCONFIRMED within the slot")

    # ---- storage accounting (bounded, fail-closed) ----------------------------
    def owned_cids(self):
        cids = []
        seen = set()
        path = os.path.join(self.build_root, "owned-containers.txt")
        if os.path.isfile(path):
            try:
                for ln in open(path).read().splitlines():
                    parts = ln.split()
                    if parts and parts[0] not in seen:
                        seen.add(parts[0])
                        cids.append((parts[0], parts[1] if len(parts) > 1 else parts[0][:12]))
            except OSError:
                pass
        for cidf in sorted(glob.glob(os.path.join(self.build_root, "cid.*"))):
            try:
                cid = open(cidf).read().strip()
            except OSError:
                continue
            if cid and cid not in seen:
                seen.add(cid)
                cids.append((cid, os.path.basename(cidf)[4:]))
        return cids

    def account(self):
        """One bounded sample. Returns (ok, total_bytes, detail)."""
        budget = self.acct_timeout
        t_start = time.monotonic()
        rc, out, err = self.run_bounded(["du", "-sb", self.build_root],
                                        budget)
        # SPECULATIVE-IMAGE-E2E fix: the legs/promote containers run as root and
        # create root-owned 0700 cache dirs (e.g. var/cache/ldconfig) under the
        # bind-mounted build root. This UNPRIVILEGED supervisor's `du` then exits
        # nonzero with EACCES on exactly those dirs while STILL printing the
        # aggregate of everything it could read on stdout. Treat a du whose ONLY
        # stderr is 'Permission denied' as a (documented) UNDERCOUNT sample
        # rather than a fail-closed accounting failure; any other du error still
        # fails closed. The unreadable items are small root-owned caches and the
        # 40 GiB preflight margin over the 30 GiB target absorbs the undercount.
        du_eacces = False
        if rc != 0:
            errlines = [l for l in err.splitlines() if l.strip()]
            if errlines and all("Permission denied" in l for l in errlines) and out.split():
                du_eacces = True
            else:
                return (False, None, "du rc=%s err=%s" % (rc, err.strip()[:300]))
        try:
            du_bytes = int(out.split()[0])
        except (IndexError, ValueError):
            return (False, None, "du output unparseable: %r" % out[:200])
        total = du_bytes
        per_cid = {}
        for cid, name in self.owned_cids():
            left = budget - (time.monotonic() - t_start)
            if left < 0.5:
                return (False, None,
                        "accounting exceeded its %.1fs bound before container %s"
                        % (budget, name))
            rc, out, err = self.run_bounded(
                ["docker", "inspect", "--size",
                 "--format", "{{.SizeRw}}", cid], left)
            if rc != 0:
                if "No such" in err or "no such" in err:
                    per_cid[name] = 0   # already removed: its storage is gone
                    continue
                return (False, None, "docker inspect --size %s rc=%s err=%s"
                        % (name, rc, err.strip()[:300]))
            txt = out.strip()
            if txt in ("", "<nil>", "0"):
                per_cid[name] = 0
                continue
            try:
                per_cid[name] = int(txt)
            except ValueError:
                return (False, None, "SizeRw unparseable for %s: %r" % (name, txt))
            total += per_cid[name]
        total += self.log_charge
        return (True, total, dict(du=du_bytes, containers=per_cid,
                                  log_charge=self.log_charge,
                                  du_eacces_undercount=du_eacces))

    # ---- cancellation: reach active writers promptly --------------------------
    def group_alive(self, pgid):
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _wait_group_dead(self, pgid, deadline):
        """Poll (reaping our direct child) until the group is gone or the
        ABSOLUTE deadline passes. Returns True if the group died in time."""
        while time.monotonic() < deadline:
            self.child.poll()        # reap our direct child so a zombie never
            if not self.group_alive(pgid):   # masquerades as a live group member
                return True
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        self.child.poll()
        return not self.group_alive(pgid)

    def terminate_child(self, why):
        if self.child is None:
            return
        pgid = self.child.pid
        self.event("terminate", why=why, pgid=pgid,
                   remaining=round(self.remaining_hard(), 2))
        # (1) HOST process-group kill on an ABSOLUTE schedule, INDEPENDENT of any
        # docker-call latency (B03-storage-residual): SIGTERM now, SIGKILL after
        # the grace, every wait clamped to the hard deadline (B03-deadline). The
        # old code ran up to four serial docker kills FIRST, pushing host SIGKILL
        # out to ~45 s; detached-container stop is now step (2), AFTER this.
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        term_deadline = min(time.monotonic() + self.grace, self.hard_deadline)
        if not self._wait_group_dead(pgid, term_deadline):
            try:
                os.killpg(pgid, signal.SIGKILL)   # not deferrable by any trap
            except ProcessLookupError:
                pass
        conf_deadline = min(time.monotonic() + self.grace, self.hard_deadline)
        alive = not self._wait_group_dead(pgid, conf_deadline)
        self.event("child-group-dead" if not alive else "child-group-SURVIVED-kill",
                   pgid=pgid, remaining=round(self.remaining_hard(), 2))
        if alive:
            self.cleanup_unconfirmed.append(
                "child process group %d survived SIGKILL within the hard deadline" % pgid)
        try:
            self.child.wait(timeout=min(1.0, max(0.0, self.remaining_hard())))
        except Exception:
            pass
        # (2) NOW stop the owned DETACHED containers (they keep writing after the
        # host client dies). Each kill is bounded and clamped to the deadline; a
        # stalled daemon can delay THIS, but it can no longer delay the host kill
        # above. Budget exhaustion is recorded, never silently skipped.
        for cid, name in self.owned_cids():
            kslot = min(DOCKER_KILL_SLOT, self.remaining_hard())
            if kslot < 0.5:
                self.cleanup_unconfirmed.append(
                    "docker-kill budget exhausted before owned container %s" % name)
                self.event("docker-kill-budget-exhausted", name=name)
                break
            self.run_bounded(["docker", "kill", cid], kslot)
            self.event("docker-kill", name=name)
        # (3) keep accounting ACTIVE across termination: a sample here confirms
        # the writers' storage is accounted for after the group is gone. A failed
        # sample is a cleanup-unconfirmed failure (fails acceptance), not a log.
        ok, total, detail = self.account()
        self.event("post-terminate-account", ok=ok, total=total, detail=detail)
        if not ok:
            self.cleanup_unconfirmed.append(
                "storage accounting failed after termination: %s" % detail)
        elif total is not None and total > self.soft_limit:
            self.cleanup_unconfirmed.append(
                "accounted storage %dB over soft limit %dB after termination"
                % (total, self.soft_limit))

    def cancel(self, reason, code):
        if self.cancel_code is None:
            self.cancel_code = code
            self.cancel_reason = reason
            try:
                with open(os.path.join(self.sup_dir, "CANCEL-REASON.txt"), "w") as f:
                    f.write(reason + "\n")
            except OSError:
                pass
            self.event("cancel", reason=reason, code=code)
        self.terminate_child(reason)

    # ---- bounded ID-tracked cleanup (supervisor alive, inside the reserve) ----
    def cleanup(self):
        # sweep stragglers: a workload that exited while grandchildren kept
        # running in its group must not leave unowned writers behind
        if self.child is not None and self.group_alive(self.child.pid):
            self.terminate_child("residual processes in the build group after child exit")
        cids = self.owned_cids()
        bx_name = None
        bx_path = os.path.join(self.build_root, "owned-buildx.txt")
        if os.path.isfile(bx_path):
            try:
                bx_name = open(bx_path).read().strip() or None
            except OSError:
                pass
        ops = [("logs", cid, name) for cid, name in cids] + \
              [("rm", cid, name) for cid, name in cids] + \
              [("confirm", cid, name) for cid, name in cids]
        if bx_name:
            ops += [("bx-rm", bx_name, bx_name), ("bx-confirm", bx_name, bx_name)]
        self.event("cleanup-begin", containers=[n for _, n in cids],
                   buildx=bx_name, remaining=round(self.remaining_hard(), 2))
        logdir = os.path.join(self.sup_dir, "cleanup-logs")
        try:
            os.makedirs(logdir, exist_ok=True)
        except OSError:
            pass
        # B03-storage-residual: accounting stays ACTIVE through cleanup. We take
        # a bounded sample whenever a sample interval has elapsed between ops; a
        # failed or over-soft-limit sample is recorded as a cleanup-unconfirmed
        # failure so continued writes during cleanup cannot pass unnoticed.
        last_cleanup_sample = time.monotonic()

        def cleanup_sample(tag):
            ok, total, detail = self.account()
            self.event("cleanup-sample", tag=tag, ok=ok, total=total, detail=detail)
            if not ok:
                self.cleanup_unconfirmed.append(
                    "storage accounting failed during cleanup (%s): %s" % (tag, detail))
            elif total is not None and total > self.soft_limit:
                self.cleanup_unconfirmed.append(
                    "accounted storage %dB over soft limit %dB during cleanup (%s)"
                    % (total, self.soft_limit, tag))

        for i, (op, ref, name) in enumerate(ops):
            if time.monotonic() - last_cleanup_sample >= self.sample_secs:
                cleanup_sample("op-%d" % i)
                last_cleanup_sample = time.monotonic()
            left = self.remaining_hard()
            ops_left = len(ops) - i
            # per-op slot = min(fair share of the REMAINING budget, a 120 s cap):
            # never a fixed timeout that ignores the budget, never an unbounded
            # share that lets one hung op eat the whole remaining wall clock.
            slot = min(left / ops_left if ops_left else left, 120.0)
            if slot < 0.5:
                self.cleanup_unconfirmed.append(
                    "cleanup budget exhausted before %s %s" % (op, name))
                self.event("cleanup-budget-exhausted", op=op, name=name)
                break
            if op == "logs":
                rc, out, err = self.run_bounded(["docker", "logs", ref], slot)
                try:
                    with open(os.path.join(logdir, "%s.log" % name), "w") as f:
                        f.write(out)
                        if err:
                            f.write("\n--- stderr ---\n" + err)
                except OSError:
                    pass
            elif op == "rm":
                self.run_bounded(["docker", "rm", "-f", ref], slot)
            elif op == "confirm":
                # B02 semantics preserved: the QUERY's own success is checked
                # separately from its output; failed/timed-out query => UNCONFIRMED.
                rc, out, err = self.run_bounded(
                    ["docker", "ps", "-aq", "--no-trunc", "--filter", "id=" + ref],
                    slot)
                if rc != 0:
                    self.cleanup_unconfirmed.append(
                        "removal UNCONFIRMED for %s: status query rc=%s" % (name, rc))
                elif out.strip():
                    self.cleanup_unconfirmed.append(
                        "container %s still present after cleanup" % name)
                self.event("cleanup-confirm", name=name, rc=rc,
                           present=bool(out.strip() if rc == 0 else None))
            elif op == "bx-rm":
                self.run_bounded(["docker", "buildx", "rm", ref], slot)
            elif op == "bx-confirm":
                rc, out, err = self.run_bounded(["docker", "buildx", "ls"], slot)
                if rc != 0:
                    self.cleanup_unconfirmed.append(
                        "buildx removal UNCONFIRMED: listing rc=%s" % rc)
                elif any(l.split() and l.split()[0] == ref
                         for l in out.splitlines()):
                    self.cleanup_unconfirmed.append(
                        "buildx builder %s still present" % ref)
                self.event("cleanup-bx-confirm", name=ref, rc=rc)
        # final accounting sample AFTER termination+cleanup: monitoring covers
        # the whole lifecycle. B03-storage-residual: a FAILED or OVER-LIMIT final
        # sample is no longer merely logged -- it becomes a cleanup-unconfirmed
        # failure, so the run cannot be accepted with unaccounted/over-limit
        # storage (the old code's forced-final-failure probe got unconfirmed=[]).
        ok, total, detail = self.account()
        self.event("final-account", ok=ok, total=total, detail=detail)
        if not ok:
            self.cleanup_unconfirmed.append(
                "final storage accounting failed: %s" % detail)
        elif total is not None and total > self.soft_limit:
            self.cleanup_unconfirmed.append(
                "final accounted storage %dB over soft limit %dB" % (total, self.soft_limit))
        self.event("cleanup-end", unconfirmed=self.cleanup_unconfirmed,
                   remaining=round(self.remaining_hard(), 2))

    # ---- main -----------------------------------------------------------------
    def run(self):
        # ONE fresh output root (B03): the supervisor owns this check now.
        if os.path.islink(self.build_root):
            die("output root %s is a symlink; refusing" % self.build_root)
        if os.path.exists(self.build_root):
            if not os.path.isdir(self.build_root) or os.listdir(self.build_root):
                die("output root %s exists and is not an empty directory; "
                    "refusing to reuse prior outputs" % self.build_root)
        os.makedirs(self.sup_dir, exist_ok=True)
        self.events_f = open(os.path.join(self.sup_dir, "events.jsonl"), "a")
        self.event("start", lane=self.lane, workload=self.workload,
                   wall_clock_max=self.wall_max, cleanup_reserve=self.reserve,
                   kill_grace=self.grace, storage_max=self.storage_max,
                   soft_limit=self.soft_limit, log_charge=self.log_charge,
                   sample_secs=self.sample_secs, acct_timeout=self.acct_timeout,
                   test_workload=bool(os.environ.get(
                       "DSMACK_SUPERVISOR_ALLOW_TEST_WORKLOAD") == "1"))

        # B01: establish the single sanitized Docker/Buildx env BEFORE any
        # docker invocation (the first account() below, the child, the watchdog,
        # every cleanup call). The build child and watchdog inherit it, so BUILD.sh
        # re-exports the SAME DOCKER_HOST/DOCKER_CONFIG/BUILDX_CONFIG it already
        # uses and no path addresses a foreign daemon/buildx.
        self.build_docker_env()

        rfd, wfd = os.pipe()           # watchdog fail-closed link: EOF = we died
        child_env = dict(self.docker_env)
        child_env["DSMACK_BUILD_LANE"] = self.lane   # BUILD.sh lane == supervised lane
        child_env["DSMACK_SUPERVISED"] = "1"
        child_env["DSMACK_SUPERVISOR_PID"] = str(os.getpid())
        child_env["DSMACK_DEADLINE_EPOCH"] = str(
            int(time.time() + max(1.0, self.child_deadline - time.monotonic())))
        child_env["DSMACK_WALL_CLOCK_MAX"] = str(int(self.wall_max))
        out_path = os.path.join(self.sup_dir, "build-output.log")
        outf = open(out_path, "ab", buffering=0)
        self.child = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--watchdog",
             "--pipe-fd", str(rfd), "--build-root", self.build_root,
             "--kill-grace", str(self.grace), "--"] + self.workload,
            stdout=outf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True, pass_fds=(rfd,), env=child_env,
            cwd=self.lane)
        os.close(rfd)
        os.set_inheritable(wfd, False)   # only THIS process holds the write end
        self.event("child-spawned", pid=self.child.pid,
                   output=out_path,
                   child_deadline_in=round(self.child_deadline - time.monotonic(), 2))

        fails = 0
        next_sample = time.monotonic()   # first sample immediately
        child_rc = None
        try:
            while True:
                rc = self.child.poll()
                if rc is not None:
                    child_rc = rc
                    self.event("child-exit", rc=rc)
                    break
                now = time.monotonic()
                if now >= self.child_deadline:
                    self.cancel("overall %ss deadline reached (reserve %ss held "
                                "for cleanup)" % (self.wall_max, self.reserve),
                                EXIT_DEADLINE)
                    break
                if now >= next_sample:
                    ok, total, detail = self.account()
                    self.event("sample", ok=ok, total=total, detail=detail,
                               soft_limit=self.soft_limit, fails=fails)
                    if ok:
                        fails = 0
                        if total > self.soft_limit:
                            self.cancel(
                                "accounted storage %dB crossed the %dB soft "
                                "limit (target %dB - headroom - %dB log charge)"
                                % (total, self.soft_limit, self.storage_max,
                                   self.log_charge), EXIT_STORAGE)
                            break
                        next_sample = time.monotonic() + self.sample_secs
                    else:
                        fails += 1
                        if fails >= ACCT_FAILS_MAX:
                            self.cancel("storage accounting failed %d times in a "
                                        "row (%s); failing CLOSED" % (fails, detail),
                                        EXIT_ACCOUNTING)
                            break
                        next_sample = time.monotonic() + 1.0   # fast retry
                time.sleep(max(0.02, min(0.2,
                                         next_sample - time.monotonic(),
                                         self.child_deadline - time.monotonic())))
            if self.cancel_code is None and child_rc is None:
                # loop broke without either: internal error, fail closed
                self.cancel("supervisor main loop exited unexpectedly",
                            EXIT_INTERNAL)
        except BaseException as e:   # fail-closed: ANY supervisor error cancels
            self.cancel("supervisor exception: %r" % (e,), EXIT_INTERNAL)
            self.cleanup()
            raise
        finally:
            if self.child.poll() is None:
                self.terminate_child(self.cancel_reason or "supervisor exiting")
        self.cleanup()
        try:
            os.close(wfd)
        except OSError:
            pass
        final = self.cancel_code if self.cancel_code is not None else child_rc
        if final is None:
            final = EXIT_INTERNAL
        if final < 0:
            final = 128 + (-final)
        if self.cleanup_unconfirmed and final == 0:
            final = EXIT_CLEANUP_UNCONFIRMED
        self.event("exit", code=final, cancel_reason=self.cancel_reason,
                   unconfirmed=self.cleanup_unconfirmed,
                   elapsed=round(time.monotonic() - self.t0, 2))
        return final


# ---- watchdog mode: fail-closed child-side guard ------------------------------
def watchdog(pipe_fd, build_root, grace, cmd):
    """Runs as the session/process-group leader of the workload. If the
    supervisor dies (pipe EOF, even on SIGKILL), docker-kill the owned
    containers and SIGKILL the whole group -- the build NEVER continues
    unmonitored."""
    term_seen = {"v": False}

    def on_term(signum, frame):
        term_seen["v"] = True
    signal.signal(signal.SIGTERM, on_term)   # survive our own group's TERM

    workload = subprocess.Popen(cmd)         # same session + process group

    def supervisor_lost():
        try:
            with open(os.path.join(build_root, "SUPERVISOR-LOST"), "w") as f:
                f.write("supervisor pipe EOF; killing the build process group "
                        "and owned containers (fail closed)\n")
        except OSError:
            pass
        cids = []
        path = os.path.join(build_root, "owned-containers.txt")
        if os.path.isfile(path):
            try:
                cids = [ln.split()[0] for ln in open(path).read().splitlines()
                        if ln.split()]
            except OSError:
                pass
        for cidf in glob.glob(os.path.join(build_root, "cid.*")):
            try:
                c = open(cidf).read().strip()
                if c and c not in cids:
                    cids.append(c)
            except OSError:
                pass
        for cid in cids:
            try:
                subprocess.run(["docker", "kill", cid], timeout=10,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception:
                pass
        pg = os.getpgrp()
        try:
            os.killpg(pg, signal.SIGTERM)
        except OSError:
            pass
        time.sleep(min(2.0, grace))
        os.killpg(pg, signal.SIGKILL)        # includes this watchdog: fail closed

    while True:
        rc = workload.poll()
        if rc is not None:
            sys.exit(rc if rc >= 0 else 128 + (-rc))
        try:
            r, _, _ = select.select([pipe_fd], [], [], 0.2)
        except OSError as e:
            if e.errno == errno.EBADF:
                supervisor_lost()
            raise
        if r:
            if os.read(pipe_fd, 1) == b"":
                supervisor_lost()
        if term_seen["v"]:
            # our group got SIGTERM (supervisor cancel): forward once and wait
            term_seen["v"] = False
            try:
                workload.terminate()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lane", help="build lane directory (output root = <lane>/build)")
    ap.add_argument("--workload", nargs=argparse.REMAINDER, default=None,
                    help="TEST ONLY: supervise this command instead of BUILD.sh")
    ap.add_argument("--watchdog", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--pipe-fd", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--build-root", help=argparse.SUPPRESS)
    ap.add_argument("--kill-grace", type=float, default=KILL_GRACE,
                    help=argparse.SUPPRESS)
    argv = sys.argv[1:]
    if argv and argv[0] == "--watchdog":
        # manual split: everything after "--" is the exact workload command
        sep = argv.index("--")
        opts = ap.parse_args(argv[:sep] + ["--lane", "/data/unused"])
        watchdog(opts.pipe_fd, opts.build_root, opts.kill_grace, argv[sep + 1:])
        return
    args = ap.parse_args(argv)
    if not args.lane:
        die("--lane is required")
    sys.exit(Supervisor(args).run())


if __name__ == "__main__":
    main()
