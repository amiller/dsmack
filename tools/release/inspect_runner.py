#!/usr/bin/env python3
"""Check a runner executable's CodeDirectory hashes against an expected CDHash, team and bundle."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def inspect(path, expected_cdhash, expected_team, expected_bundle):
    source = Path(__file__).resolve().parents[2] / "contracts" / "cd_args.py"
    spec = importlib.util.spec_from_file_location("dsmack_cd_args", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result, _ = module.inspect_bytes(Path(path).read_bytes())
    primary = next(d for d in result["code_directories"] if d["slot"] == 0)
    if primary["hash_type"] != 2 or primary["sha256"] != expected_cdhash:
        raise ValueError("primary SHA-256 CodeDirectory does not match independent pin")
    for directory in result["code_directories"]:
        if directory["team"] != expected_team or directory["identifier"] != expected_bundle:
            raise ValueError("CodeDirectory team/bundle does not match independent policy")
    result["expected_identity_matched"] = True
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
