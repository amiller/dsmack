"""Install the exact Linux arm64 CPython 3.11 wheel closure, checking all bytes.

Mac ARM Base-only profile sibling of install_python.py: same bounds (CPython
3.11, files.pythonhosted.org origin only, per-file 20 MiB cap, sha256 check,
pip bootstrapped from the pinned pip wheel, --no-index --no-deps --no-compile),
reading the linux/arm64 closure pinned in python-wheels-mac-base.json. Package
names and versions are identical to python-wheels.json; only the five compiled
wheels are the aarch64 builds published in the same upstream releases.
"""
import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile
import urllib.request

if sys.version_info[:2] != (3, 11):
    raise SystemExit('package profile requires CPython 3.11')
root = Path(__file__).resolve().parents[2]
lock = json.loads((root / 'packaging/coupon/python-wheels-mac-base.json').read_text())
with tempfile.TemporaryDirectory(prefix='coupon-wheels-') as temporary:
    directory = Path(temporary)
    for wheel in lock['wheels']:
        if not wheel['url'].startswith('https://files.pythonhosted.org/'):
            raise SystemExit('unexpected wheel origin')
        with urllib.request.urlopen(wheel['url'], timeout=30) as response:
            data = response.read(20_000_001)
        if len(data) > 20_000_000 or hashlib.sha256(data).hexdigest() != wheel['sha256']:
            raise SystemExit('wheel integrity check failed')
        (directory / wheel['filename']).write_bytes(data)
    pip = next(wheel for wheel in lock['wheels'] if wheel['name'] == 'pip')
    sys.path.insert(0, str(directory / pip['filename']))
    sys.argv = ['pip', 'install', '--no-index', '--no-deps', '--no-compile',
                '--disable-pip-version-check', '--target', str(root / 'python-deps')]
    sys.argv += [str(directory / wheel['filename']) for wheel in lock['wheels'] if wheel['name'] != 'pip']
    runpy.run_module('pip', run_name='__main__')
