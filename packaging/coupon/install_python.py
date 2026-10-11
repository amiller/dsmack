"""Install the exact Linux amd64 CPython 3.11 wheel closure, checking all bytes."""
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
lock = json.loads((root / 'packaging/coupon/python-wheels.json').read_text())
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
