"""Confined tool execution — INNER helper (dsmack.safe-extract-result/1).

Executed INSIDE fresh user+net+mount+pid namespaces (spawned by
extraction.py via util-linux unshare).  As the namespace's mapped root it
builds a minimal jail and execs the pinned parser with no shell:

  tmpfs jail/            (fresh, size-bounded, mode 0700)
    usr/   <- bind RO of host /usr   (tool + libraries)
    lib,lib64 -> usr/lib, usr/lib64  (symlinks, Debian/Ubuntu merged-usr)
    snap.img <- RO bind of the verified snapshot file
    work/  <- RW bind of the fresh destination directory
  chroot(jail); chdir(/work); rlimits; empty environment; execv(tool).

Filesystem restriction: after chroot the process can read only /usr (RO)
and /snap.img (RO) and write only /work (and its own /tmp-less jail).
Network restriction: the net namespace has no interfaces.  Process
restriction: fresh pid namespace, rlimits (AS/CPU/FSIZE/NOFILE/CORE).

Config (argv[1] = JSON file path, written by the parent OUTSIDE the jail):
  {"jail": ..., "snapshot": ..., "workdir": ..., "tool": ...,
   "tool_args": [...], "rlimit_as": N, "rlimit_cpu": N, "rlimit_fsize": N}
"""
import ctypes
import json
import os
import resource
import sys

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND = 32, 4096

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def _mount(source, target, fstype, flags, data=None):
    result = _libc.mount(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        flags,
        data.encode() if data else None)
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, "mount(%s -> %s): %s" % (source, target,
                                                    os.strerror(err)))


def main():
    with open(sys.argv[1], "rb") as fh:
        config = json.load(fh)
    jail = config["jail"]

    _mount("tmpfs", jail, "tmpfs", MS_NOSUID | MS_NODEV,
           "size=16777216,mode=0700")
    os.mkdir(os.path.join(jail, "usr"), 0o755)
    _mount("/usr", os.path.join(jail, "usr"), None, MS_BIND)
    _mount(None, os.path.join(jail, "usr"), None,
           MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    os.symlink("usr/lib", os.path.join(jail, "lib"))
    if os.path.exists("/lib64"):
        os.symlink("usr/lib64", os.path.join(jail, "lib64"))

    snap_target = os.path.join(jail, "snap.img")
    with open(snap_target, "wb"):
        pass
    _mount(config["snapshot"], snap_target, None, MS_BIND)
    _mount(None, snap_target, None,
           MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)

    work_target = os.path.join(jail, "work")
    os.mkdir(work_target, 0o700)
    _mount(config["workdir"], work_target, None, MS_BIND)

    os.chroot(jail)
    os.chdir("/work")

    resource.setrlimit(resource.RLIMIT_AS,
                       (config["rlimit_as"], config["rlimit_as"]))
    resource.setrlimit(resource.RLIMIT_CPU,
                       (config["rlimit_cpu"], config["rlimit_cpu"]))
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (config["rlimit_fsize"], config["rlimit_fsize"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    os.execve(config["tool"], [config["tool"]] + config["tool_args"], {})


if __name__ == "__main__":
    main()
