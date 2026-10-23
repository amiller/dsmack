#!/usr/bin/env python3
"""Build the imported generic Mac runner without signing, credentials or VM launch.

Uses the historical archive or an explicitly, independently selected native
build record. A new archive produces a new candidate, never the old app identity.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
from source_check import ROOT, check, selected_lock


def digest(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64*1024*1024:
        raise ValueError('expected bounded regular native archive')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(argv, timeout=30, env=None):
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout, env=env)
    return result.stdout.strip()


def select_native(archive, lock, record=None, expected_record=None, expected_archive=None):
    selected = (record is not None, expected_record is not None, expected_archive is not None)
    if any(selected) and not all(selected):
        raise ValueError('new native selection requires record and both independent SHA-256 pins')
    if not any(selected):
        if lock.get("source_derivation_sha256"):
            raise ValueError("derived source requires a new independently selected native build record")
        return {'profile':'historical-qualified-native',
                'expected_sha256':lock['native_archive_sha256']}
    for value in (expected_record, expected_archive):
        if not re.fullmatch(r'[0-9a-f]{64}',value):
            raise ValueError('native selection requires full lowercase SHA-256 pins')
    if record.is_symlink() or not record.is_file() or record.stat().st_size > 1024*1024:
        raise ValueError('selected native record must be bounded regular JSON')
    raw = record.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_record:
        raise ValueError('native build record differs from independent raw SHA-256 pin')
    document = json.loads(raw)
    if document.get('archive_sha256') != expected_archive or document.get('archive_bytes') != archive.stat().st_size:
        raise ValueError('native record does not bind selected archive digest/length')
    if document.get('source_inventory_sha256') != lock['native_source_inventory_sha256']:
        raise ValueError('native record source inventory differs from imported source')
    if document.get('rustc') != lock['native_rustc'] or document.get('group_quiescence') != 'confirmed-empty':
        raise ValueError('native compiler or build-process quiescence is not qualified')
    command = document.get('command')
    if not isinstance(command,list) or not all(isinstance(x,str) for x in command):
        raise ValueError('missing native build command')
    for flag in ('build','--release','--offline','--locked'):
        if flag not in command: raise ValueError('native build policy missing '+flag)
    if command.count('--target') != 1 or command.index('--target')+1 >= len(command) or command[command.index('--target')+1] != 'aarch64-apple-darwin':
        raise ValueError('native build target differs from selected profile')
    return {'profile':'independently-selected-new-native-build',
            'expected_sha256':expected_archive,'build_record_sha256':expected_record,
            'source_inventory_sha256':document['source_inventory_sha256'],
            'rustc':document['rustc'],'new_app_qualification_required':True,
            'provenance_note':'Operator-selected local build evidence; not a GitHub/Sigstore attestation.'}


def stage_archive(source, inputs, expected):
    inputs.mkdir()
    staged = inputs/'libdsmack_hvf_returning.a'
    shutil.copyfile(source, staged)
    staged.chmod(0o400)
    if digest(staged) != expected:
        raise ValueError('native archive changed during staging')
    return staged


def portable_group_members(pgid):
    try:
        output = capture(['/bin/ps', '-axo', 'pid=,pgid=,stat='], timeout=5)
        members = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) != 3:
                raise ValueError('cannot parse process-group inspection')
            pid, group = map(int, fields[:2])
            if group == pgid and not fields[2].startswith('Z'):
                members.append(pid)
        return sorted(members)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # The original supervisor treats OSError as unknown/alive, escalates,
        # and retains a persistent owner if inspection cannot prove quiescence.
        raise OSError('process-group inspection unavailable') from exc


def cleanup_adapter(owner_file):
    # Reuse the original reviewed TERM/KILL/group-confirmation/persistent-owner
    # implementation. Only its Linux /proc membership observer is replaced by
    # the Mac/Linux ps equivalent; no direct-child-only success shortcut.
    spec = importlib.util.spec_from_file_location('dsmack_build_cleanup', ROOT/'native/xbuild-supervise.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.group_members = portable_group_members
    module.OWNER_PID_FILE = owner_file
    return module


def compile_swift(argv, env, cwd, log_path):
    cleanup = cleanup_adapter(log_path.parent/'residual-owner.json')
    with log_path.open('xb') as log:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        def stop(signum, frame):
            raise RuntimeError('Swift build interrupted')
        previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        try:
            rc = process.wait(timeout=1200)
            if rc:
                raise RuntimeError('Swift build failed; inspect retained compile.log')
        finally:
            for sig in previous: signal.signal(sig, signal.SIG_IGN)
            try:
                outcome = cleanup.confirm_group_reaped(process, process.pid)
                if outcome['status'] != 'clean':
                    raise RuntimeError('Swift group quiescence unconfirmed; persistent owner retained: ' + json.dumps(outcome))
            finally:
                for sig, handler in previous.items(): signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--source-derivation-sha256')
    parser.add_argument('--native-build-record',type=Path)
    parser.add_argument('--expected-native-build-record-sha256')
    parser.add_argument('--expected-native-archive-sha256')
    args = parser.parse_args()
    result = check(derivation_sha256=args.source_derivation_sha256)
    lock = selected_lock(result,json.loads((ROOT/'QUALIFIED-INPUTS.json').read_text()))
    if sys.platform != 'darwin' or os.uname().machine != 'arm64':
        raise ValueError('requires Apple silicon macOS build host')
    for path in (args.archive, args.out):
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('archive/output must be absolute non-symlink paths')
    if ROOT in args.out.resolve().parents:
        raise ValueError('build output must be outside the source checkout')
    if args.out.exists():
        raise ValueError('refusing existing output directory')
    selection = select_native(args.archive,lock,args.native_build_record,
                              args.expected_native_build_record_sha256,args.expected_native_archive_sha256)
    archive_sha = digest(args.archive)
    if archive_sha != selection['expected_sha256']:
        raise ValueError('native archive differs from independently selected native pin')
    swift = capture(['/usr/bin/xcrun', '--find', 'swift'])
    swift_version = capture([swift, '--version']).splitlines()[0]
    if swift_version != lock['swift_version'] or capture(['/usr/bin/xcodebuild', '-version']) != lock['xcode_version']:
        raise ValueError('unqualified Swift/Xcode toolchain; needs separately reviewed lock')
    nm_result = subprocess.run(['/usr/bin/xcrun', 'nm', '-g', str(args.archive)],
                               capture_output=True, text=True, timeout=60)
    symbols = nm_result.stdout
    defined = set(re.findall(r'^.* [Tt] _?([A-Za-z0-9_]+)$', symbols, re.M))
    missing = sorted(set(lock['symbol_set']) - defined)
    if missing:
        raise ValueError('native archive missing required ABI symbols: ' + ', '.join(missing))
    result.update({'check_only': args.check_only, 'native_archive_sha256': archive_sha,
                   'abi_symbols_checked': len(lock['symbol_set']), 'swift': swift_version,
                   'nm_exit_code': nm_result.returncode,
                   'nm_diagnostics_present': bool(nm_result.stderr),
                   'nm_complete_archive_parse_claimed': nm_result.returncode == 0,
                   'native_selection':selection})
    if args.check_only:
        print(json.dumps(result, indent=2)); return
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = args.out/'inputs'
    staged_archive = stage_archive(args.archive, inputs, archive_sha)
    work = args.out/'work'; work.mkdir()
    for name in ('app-src', 'control-src'):
        shutil.copytree(ROOT/name, work/name, ignore=shutil.ignore_patterns('__pycache__'))
    env = os.environ.copy()
    env['DSMACK_V3_ARCHIVE_DIR'] = str(inputs)
    compile_swift([swift, 'build', '-c', 'release', '--product', 'mar', '--skip-update',
                   '--disable-automatic-resolution', '--disable-sandbox'], env, work/'app-src', args.out/'compile.log')
    # Detect source changes during compilation; build copy is checked too.
    check(derivation_sha256=args.source_derivation_sha256)
    if digest(staged_archive) != archive_sha:
        raise ValueError('consumed native input changed during compilation')
    for tree in ('app-src', 'control-src'):
        for path in (ROOT/tree).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                if path.read_bytes() != (work/tree/path.relative_to(ROOT/tree)).read_bytes():
                    raise ValueError('build input copy changed during compilation')
    app = args.out/'DsmackRunner.app'; binary = app/'Contents/MacOS/dsmack-runner'
    binary.parent.mkdir(parents=True)
    shutil.copyfile(work/'app-src/.build/release/mar', binary); binary.chmod(0o755)
    info = {'CFBundleIdentifier':'dev.dsmack.provider','CFBundleExecutable':'dsmack-runner',
            'CFBundleName':'DsmackRunner','CFBundlePackageType':'APPL','CFBundleVersion':'1',
            'CFBundleShortVersionString':'1.0','LSUIElement':True,'LSMinimumSystemVersion':'27.0'}
    (app/'Contents/Info.plist').write_bytes(plistlib.dumps(info,sort_keys=False))
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    result.update({'schema':'dsmack-portable-unsigned-build/1','compiled':True,'signed':False,
        'app':str(app),'unsigned_executable_sha256':actual,
        'historical_unsigned_match':actual==lock['original_unsigned_executable_sha256'],
        'bit_reproducibility_claim':False,'native_archive_sha256':archive_sha,'consumed_native_archive':str(staged_archive),
        'qualified_inputs_sha256':hashlib.sha256((ROOT/'QUALIFIED-INPUTS.json').read_bytes()).hexdigest(),
        'requires_independent_candidate_review_before_signing':True})
    (args.out/'UNSIGNED-BUILD.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'built':False,'error':str(exc)}),file=sys.stderr);sys.exit(1)
