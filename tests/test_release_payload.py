import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts/release'))
from verify_signed_payload import verify


def pair():
    unsigned = bytearray(20000)
    struct.pack_into('<8I', unsigned, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 72, 0, 0)
    struct.pack_into('<II16sQQQQIIII', unsigned, 32, 0x19, 72, b'__LINKEDIT',
                     0x100004000, 16384, 16384, 3616, 1, 1, 0, 0)
    unsigned[17000:17004] = b'code'
    signed = bytearray(unsigned) + bytes(20000)
    struct.pack_into('<II', signed, 16, 2, 88)
    struct.pack_into('<IIII', signed, 104, 0x1d, 16, len(unsigned), 20000)
    struct.pack_into('<Q', signed, 32 + 32, 32768)
    struct.pack_into('<Q', signed, 32 + 48, len(signed) - 16384)
    return unsigned, signed


def test_accept_only_expected_signing_layout():
    a, b = pair()
    assert verify(a, b)['unsigned_payload_matches_signed']


@pytest.mark.parametrize('offset', [4, 24, 17000, 32 + 40, 32 + 32, 104 + 8, 104 + 12])
def test_reject_changed_code_header_or_signature_extent(offset):
    a, b = pair()
    b[offset] ^= 1
    with pytest.raises((ValueError, struct.error)):
        verify(a, b)


def test_reject_overwriting_nonzero_unsigned_bytes():
    a, b = pair()
    a[104] = 1
    with pytest.raises(ValueError):
        verify(a, b)


def test_reject_trailing_unsigned_data_change():
    a, b = pair()
    b[len(a) - 1] ^= 1
    with pytest.raises(ValueError):
        verify(a, b)


def test_accept_minimal_zero_signature_alignment_padding():
    a, b = pair()
    a = a[:-8]
    struct.pack_into('<Q', a, 32 + 48, len(a) - 16384)
    assert verify(a, b)['zero_alignment_padding'] == 8
    b[len(a)] = 1
    with pytest.raises(ValueError, match='padding'):
        verify(a, b)


def test_reject_extra_signature_padding():
    a, b = pair()
    a = a[:-16]
    struct.pack_into('<Q', a, 32 + 48, len(a) - 16384)
    with pytest.raises(ValueError, match='alignment'):
        verify(a, b)
