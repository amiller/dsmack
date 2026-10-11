"""Initialize only the runner's named coupon volume, then drop to UID1000."""
import os
import stat
from pathlib import Path


def initialize(volume=Path('/coupon-volume')):
    if (not volume.is_dir() or volume.is_symlink()
            or not (volume / '.abalone-persistent').is_file()):
        raise ValueError('runner named volume required')
    import re
    fd = os.open(volume / '.abalone-persistent', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != 65:
            raise ValueError('runner volume marker required')
        marker = os.read(fd, 66).decode('ascii')
    finally:
        os.close(fd)
    if not re.fullmatch('[0-9a-f]{64}\n', marker):
        raise ValueError('runner volume marker required')
    directory = volume / 'control'
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid not in (0, 1000)):
        raise ValueError('protected coupon control directory required')
    if os.getuid() == 0:
        os.chown(directory, 1000, 1000)
        os.setgroups([]); os.setgid(1000); os.setuid(1000)
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise ValueError('nonroot coupon runtime required')


if __name__ == '__main__':
    try:
        import sys
        initialize()
        os.execv('/usr/local/bin/node', ['/usr/local/bin/node', '/opt/dsmack/node/coupon-node.mjs', *sys.argv[1:]])
    except Exception:
        raise SystemExit('Mac coupon volume initialization refused') from None
