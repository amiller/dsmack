#!/usr/bin/env python3
"""Read-only offline Mach-O inspection. Never launches the candidate executable."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


def read_regular(path, maximum=256 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("input must be a regular, single-link file")
        if before.st_uid != os.getuid() or before.st_mode & 0o022:
            raise ValueError("input must be owned by current user and not group/world writable")
        if not 0 < before.st_size <= maximum:
            raise ValueError("input size outside supported bound")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(fd)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if key(before) != key(after) or len(data) != before.st_size:
            raise ValueError("input changed during inspection")
        return data
    finally:
        os.close(fd)


def inspect(path, expected_cdhash, expected_team, expected_bundle):
    source = Path(__file__).resolve().parents[2] / "contracts" / "cd_args.py"
    spec = importlib.util.spec_from_file_location("dsmack_cd_args", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result, _ = module.inspect_bytes(read_regular(path))
    primary = next(d for d in result["code_directories"] if d["slot"] == 0)
    if primary["hash_type"] != 2 or primary["sha256"] != expected_cdhash:
        raise ValueError("primary SHA-256 CodeDirectory does not match independent pin")
    for directory in result["code_directories"]:
        if directory["team"] != expected_team or directory["identifier"] != expected_bundle:
            raise ValueError("CodeDirectory team/bundle does not match independent policy")
    result["expected_identity_matched"] = True
    result["trust_note"] = "Page integrity only; use Apple codesign for CMS/chain/bundle seal and GitHub attestation for build provenance."
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable")
    parser.add_argument("--expected-cdhash", required=True)
    parser.add_argument("--expected-team", required=True)
    parser.add_argument("--expected-bundle", required=True)
    args = parser.parse_args()
    try:
        if len(args.expected_cdhash) != 64 or any(c not in "0123456789abcdef" for c in args.expected_cdhash):
            raise ValueError("expected full SHA-256 CDHash must be 64 lowercase hex characters")
        print(json.dumps(inspect(args.executable, args.expected_cdhash,
                                 args.expected_team, args.expected_bundle), indent=2))
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"checked": False, "error": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
