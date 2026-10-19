"""Convert an own synthetic P-256 SEC1 DER fixture to Security X9.63 format."""
import os
from pathlib import Path
import sys

def tlv(data, pos):
    tag = data[pos]
    pos += 1
    size = data[pos]
    pos += 1
    if size & 128:
        count = size & 127
        assert 1 <= count <= 2
        size = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + size
    assert end <= len(data)
    return tag, data[pos:end], end

raw = Path(sys.argv[1]).read_bytes()
tag, body, end = tlv(raw, 0)
assert tag == 0x30 and end == len(raw)
fields = {}
pos = 0
while pos < len(body):
    tag, value, pos = tlv(body, pos)
    assert tag not in fields
    fields[tag] = value
assert fields[2] == b"\x01"
# LibreSSL can encode explicit EC parameters; the native probe validates the
# resulting P-256 key against the certificate and an ECIES roundtrip.
assert fields[0xA0]
scalar = fields[4]
tag, bits, end = tlv(fields[0xA1], 0)
assert tag == 3 and end == len(fields[0xA1])
assert len(scalar) == 32 and len(bits) == 66 and bits[:2] == b"\x00\x04"
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as stream:
    assert stream.write(bits[1:] + scalar) == 97
