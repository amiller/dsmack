#!/usr/bin/env python3
"""private_inputs.py MANIFEST OUT TURN TREE < CREDENTIAL: write OUT, a turn's private input disk on the Mac.

The disk (vde, dsmack.private-input-transport/1) holds one runtime-input envelope for MANIFEST's exact bytes, at
envelopes/<name>.envelope.json in a ustar stream zero-padded to 512 bytes. It carries the request and the snapshot
(env `TURN` and the gzipped `TREE_0`, `TREE_1`, ..., base64, for the agent), the credential export_subscription.py pipes in (for the sentinel) and a
fresh sentinel token. Nothing is printed. Runs under the Mac's /usr/bin/python3.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import secrets
import sys
import tarfile

MTIME = 1784592000  # dsmack pt_limits.PT_CANONICAL_MTIME

manifest_path, out, turn, tree = sys.argv[1:5]
manifest = open(manifest_path, 'rb').read()
credential = sys.stdin.buffer.read(65537).decode()
if not 0 < len(credential) <= 65536:
    raise SystemExit('credential missing or too long')
token = secrets.token_hex(16)
b64 = lambda raw: base64.b64encode(raw).decode()
tree_b64 = b64(gzip.compress(open(tree, 'rb').read(), mtime=0))
CHUNK = 96 << 10  # Linux caps one env string at 128 KiB
parts = {'TREE_%d' % i: tree_b64[o:o + CHUNK] for i, o in enumerate(range(0, len(tree_b64), CHUNK))}
envelope = json.dumps({'runtime_input_version': 4, 'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
                       'env': {'TURN': b64(open(turn, 'rb').read()), **parts, 'SENTINEL_ENDPOINT': 'http://sentinel:8100/' + token,
                               'SENTINEL_TOKEN': token, 'SENTINEL_CREDENTIAL': credential}},
                      sort_keys=True, separators=(',', ':')).encode()
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as t:
    name = json.loads(manifest)['name']
    for rel, data in (('envelopes', None), ('envelopes/%s.envelope.json' % name, envelope)):
        info = tarfile.TarInfo(rel)
        info.type, info.mtime, info.mode = (tarfile.DIRTYPE, MTIME, 0o700) if data is None else (tarfile.REGTYPE, MTIME, 0o600)
        info.size = len(data or b'')
        t.addfile(info, data and io.BytesIO(data))
raw = buf.getvalue()
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as f:
    f.write(raw + b'\0' * (-len(raw) % 512))
