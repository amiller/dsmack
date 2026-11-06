#!/usr/bin/env python3
"""Build and check the deterministic page payload (before its self-CID label)."""
import base64
import hashlib
import io
from pathlib import Path
import re
import tarfile

def cid(data):
    return 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(data).digest()).decode().lower().rstrip('=')

def payload(dist):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(Path(dist).rglob('*')):
            if path.name == 'page-bundle.tar':
                continue
            if path.is_symlink():
                raise ValueError('Page bundle must not contain symlinks')
            if not path.is_file():
                continue
            data = path.read_bytes()
            if path == Path(dist) / 'index.html':
                data = re.sub(rb'<meta name="page-bundle-cid" content="[^"]*">', b'', data)
            info = tarfile.TarInfo(path.relative_to(dist).as_posix())
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()

def check(dist):
    data = payload(dist)
    own = cid(data)
    if (Path(dist) / 'page-bundle.tar').read_bytes() != data:
        raise ValueError('Page payload changed after build')
    if f'<meta name="page-bundle-cid" content="{own}">' not in (Path(dist) / 'index.html').read_text():
        raise ValueError('Page bundle CID differs from its payload')
    return own

if __name__ == '__main__':
    import sys
    dist = Path(sys.argv[1])
    data = payload(dist)
    (dist / 'page-bundle.tar').write_bytes(data)
    index = dist / 'index.html'
    index.write_text(index.read_text().replace('<head>', f'<head><meta name="page-bundle-cid" content="{cid(data)}">', 1))
    print(check(dist))
