#!/usr/bin/env python3
"""Relocate the original bounded Linux staticlib cross-build; never signs/runs VM.

Heavy build: run on a build machine, not the laptop. Original supervisor and
native source bytes are preserved. This adapter changes paths, not its limits.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from source_check import ROOT, check, selected_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--toolchain-dir', required=True, type=Path)
    parser.add_argument('--cargo-home', required=True, type=Path)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--source-derivation-sha256')
    args = parser.parse_args()
    result = check(derivation_sha256=args.source_derivation_sha256)
    for path in (args.work_dir, args.toolchain_dir, args.cargo_home):
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('build/cache/toolchain paths must be absolute and not symlinks')
    if sys.platform != 'linux':
        raise ValueError('bounded cross-build supervisor requires Linux /proc')
    source = ROOT / 'native/xbuild-supervise.py'
    spec = importlib.util.spec_from_file_location('dsmack_bounded_native_build', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Only filesystem placement changes; native source, exact rustc version,
    # target, --offline/--locked, resource bounds and cleanup remain original.
    module.TOOLCHAIN = args.toolchain_dir
    module.CARGO = args.toolchain_dir / 'bin/cargo'
    module.RUSTC = args.toolchain_dir / 'bin/rustc'
    module.STAGING_BASE = args.work_dir / 'runs'
    module.LOCK_PATH = args.work_dir / 'build.lock'
    module.OWNER_PID_FILE = args.work_dir / 'residual-owner.json'
    inventory = module.source_inventory()
    lock = selected_lock(result,json.loads((ROOT/'QUALIFIED-INPUTS.json').read_text()))
    if hashlib.sha256(inventory.encode()).hexdigest() != lock['native_source_inventory_sha256']:
        raise ValueError('native source inventory differs from qualified lock')
    if ROOT in args.work_dir.resolve().parents or args.work_dir.resolve() == ROOT:
        raise ValueError('build work directory must be outside source checkout')
    actual_rustc = subprocess.run([str(module.RUSTC), '--version'], check=True,
                                  capture_output=True, text=True, timeout=10).stdout.strip()
    if actual_rustc != module.EXPECT_RUSTC_FULL:
        raise ValueError('native compiler differs from exact qualified Rust version')
    if not (module.TOOLCHAIN/'lib/rustlib'/module.TARGET/'lib').is_dir():
        raise ValueError('pinned toolchain lacks aarch64-apple-darwin standard library')
    if not args.cargo_home.is_dir():
        raise ValueError('prepared offline Cargo cache directory is missing')
    result.update({'target': module.TARGET, 'rustc_required': module.EXPECT_RUSTC_FULL,
                   'work_dir': str(args.work_dir), 'cargo_home': str(args.cargo_home),
                   'native_source_inventory_sha256': hashlib.sha256(inventory.encode()).hexdigest(),
                   'actual_rustc': actual_rustc, 'check_only': args.check_only})
    print(json.dumps(result, indent=2), flush=True)
    if args.check_only:
        return
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.environ['CARGO_HOME'] = str(args.cargo_home)
    def interrupted(signum, frame):
        raise RuntimeError('build interrupted by signal %d' % signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    module.main()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'built': False, 'error': str(exc)}), file=sys.stderr)
        sys.exit(1)
