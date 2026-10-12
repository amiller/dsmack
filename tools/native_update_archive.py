#!/usr/bin/env python3
"""Package an already signed Node.app in the updater's bounded ZIP format.

No signing, notarization, admission or publication is performed here.
"""
import argparse
from pathlib import Path
import stat
import zipfile


def package(app: Path, output: Path):
    if app.name != 'Node.app' or not app.is_dir() or app.is_symlink():
        raise ValueError('expected a regular Node.app directory')
    files = sorted(app.rglob('*'))
    if any(p.is_symlink() or (not p.is_dir() and not p.is_file()) for p in files):
        raise ValueError('symlinks and special files are not supported')
    files = [p for p in files if p.is_file()]
    if not files or len(files) > 4096 or sum(p.stat().st_size for p in files) > 600_000_000:
        raise ValueError('app exceeds updater limits')
    if any(not (app / name).is_file() for name in ['Contents/Info.plist', 'Contents/MacOS/node']):
        raise ValueError('missing executable or Info.plist')
    # No ZIP extra fields, resource-fork sidecars or alternate Unicode path records.
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, allowZip64=False) as z:
        for p in files:
            if p.stat().st_size > 250_000_000:
                raise ValueError('individual app file exceeds updater limit')
            info = zipfile.ZipInfo('Node.app/' + p.relative_to(app).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (p.stat().st_mode & 0o777)) << 16
            # Stored entries avoid compression-ratio ambiguity for legitimate zero data.
            info.compress_type = zipfile.ZIP_STORED
            with p.open('rb') as source, z.open(info, 'w') as dest:
                while chunk := source.read(1024 * 1024):
                    dest.write(chunk)
    if output.stat().st_size > 250_000_000:
        raise ValueError('archive exceeds updater download limit; do not publish')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    package(args.app, args.output)


if __name__ == '__main__':
    main()
