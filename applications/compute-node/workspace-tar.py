#!/usr/bin/env python3
"""Stream workspace archives and install authenticated archives after git fsck."""
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

INTERNAL = {'.tmp', 'artifacts', 'state'}
DEPENDENCIES = {'node_modules', '__pycache__', '.cache', '.npm', '.pnpm-store', '.venv', 'venv', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.tox', '.turbo'}
OUTPUTS = {'build', 'dist', 'target', '.next', '.nuxt', 'coverage'}
MAX_FILES_BYTES = 256 * 1024 * 1024


def pack(root):
    head = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', 'HEAD'], cwd=root,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raw = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '-z', 'HEAD'], cwd=root) if head.returncode == 0 else b''
    raw += subprocess.check_output(['git', 'diff', '--cached', '--name-only', '-z',
                                    '--ita-invisible-in-index', '--diff-filter=ACMR'], cwd=root)
    tracked = {os.fsdecode(name) for name in raw.split(b'\0') if name}
    parents = {str(parent) for name in tracked for parent in PurePosixPath(name).parents}

    def included(name, directory):
        parts = PurePosixPath(name).parts
        if parts[0] == '.git':
            return True
        if parts[0] in INTERNAL or any(part in DEPENDENCIES for part in parts):
            return False
        if any(parts[i:i + 2] == ('.yarn', 'cache') for i in range(len(parts) - 1)):
            return False
        if any(part in OUTPUTS for part in parts):
            return name in tracked or (directory and name in parents)
        return True

    size = 0
    seen_files = set()
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz', dereference=False) as archive:
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            for entry in sorted(dirs + files):
                path = Path(current) / entry
                name = path.relative_to(root).as_posix()
                info = path.lstat()
                directory = stat.S_ISDIR(info.st_mode)
                if not included(name, directory):
                    if entry in dirs:
                        dirs.remove(entry)
                    continue
                if not (directory or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                    raise ValueError('Workspace contains a special file: ' + name)
                if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in seen_files:
                    seen_files.add((info.st_dev, info.st_ino))
                    size += info.st_size
                    if size > MAX_FILES_BYTES:
                        raise ValueError('Workspace archive exceeds 256 MiB of files')
                archive.add(path, arcname=name, recursive=False)


def member_path(stage, name):
    parts = PurePosixPath(name).parts
    if not parts or PurePosixPath(name).is_absolute() or '..' in parts or parts[0] in INTERNAL:
        raise ValueError('Unsafe workspace archive path')
    path = stage.joinpath(*parts)
    for parent in path.parents:
        if parent == stage:
            break
        if parent.is_symlink():
            raise ValueError('Workspace archive writes through a symlink')
    return path


def restore(root):
    temporary = root / '.tmp'
    temporary.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='workspace-restore-', dir=temporary) as scratch:
        stage = Path(scratch)
        modes = []
        total = 0
        with tarfile.open(fileobj=sys.stdin.buffer, mode='r|gz') as archive:
            for member in archive:
                path = member_path(stage, member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                if member.isdir():
                    if path.is_symlink() or path.is_file():
                        raise ValueError('Duplicate workspace archive path')
                    path.mkdir(exist_ok=True)
                    modes.append((path, member.mode & 0o777))
                elif member.isfile():
                    total += member.size
                    if total > MAX_FILES_BYTES:
                        raise ValueError('Workspace archive exceeds 256 MiB of files')
                    with path.open('xb') as output, archive.extractfile(member) as source:
                        shutil.copyfileobj(source, output, length=64 * 1024)
                    path.chmod(member.mode & 0o777)
                    os.utime(path, (member.mtime, member.mtime))
                elif member.issym():
                    os.symlink(member.linkname, path)
                elif member.islnk():
                    target = member_path(stage, member.linkname)
                    if not stat.S_ISREG(target.lstat().st_mode):
                        raise ValueError('Unsafe workspace hardlink')
                    os.link(target, path, follow_symlinks=False)
                else:
                    raise ValueError('Workspace archive contains a special file')
        if not (stage / '.git').is_dir() or (stage / '.git').is_symlink():
            raise ValueError('Saved workspace has no git directory')
        subprocess.run(['git', 'fsck', '--full'], cwd=stage, check=True,
                       stdout=subprocess.DEVNULL, stderr=sys.stderr)
        for path, mode in reversed(modes):
            path.chmod(mode)
        for path in root.iterdir():
            if path.name not in INTERNAL:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        for path in stage.iterdir():
            path.rename(root / path.name)


if __name__ == '__main__':
    try:
        {'pack': pack, 'restore': restore}[sys.argv[1]](Path(sys.argv[2]).resolve())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
