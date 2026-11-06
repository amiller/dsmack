#!/usr/bin/env python3
"""Check that every dsmack file in a derived rootfs is a repo file and no SHA256SUMS remains: check_rootfs.py ROOTFS"""
import hashlib,subprocess,sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
ROOTS=('usr/local/lib/dsmack','usr/bin/dsmack-supervisor','etc/docker/daemon.json')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def installed(root):
    for p in [root/r for r in ROOTS]+sorted((root/'usr/local/bin').glob('dsmack-*')):
        yield from sorted(f for f in p.rglob('*') if not f.is_dir()) if p.is_dir() else [p]

def problems(root):
    tracked=subprocess.run(['git','-C',str(REPO),'ls-files','-z'],capture_output=True,check=True).stdout.decode().split('\0')
    known={sha(REPO/f) for f in tracked if f and (REPO/f).is_file()}
    out=[]
    for f in installed(root):
        rel=f.relative_to(root)
        if f.name=='SHA256SUMS':out.append(f'{rel}: SHA256SUMS')
        elif f.is_symlink() or not f.is_file():out.append(f'{rel}: not a regular file')
        elif sha(f) not in known:out.append(f'{rel}: not a repo file')
    return out

if __name__=='__main__':
    found=problems(Path(sys.argv[1]))
    print('\n'.join(found) or 'ok')
    sys.exit(1 if found else 0)
