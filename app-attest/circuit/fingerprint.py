import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
files = sorted([*root.rglob('*.nr'), *root.rglob('Nargo.toml'), root/'target/attest_leaf.json'])
print('CHECKER_TREE_SHA256=' + hashlib.sha256(b''.join(str(p.relative_to(root)).encode()+b'\0'+p.read_bytes() for p in files)).hexdigest())
