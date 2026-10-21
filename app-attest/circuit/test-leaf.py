#!/usr/bin/env python3
"""Generate private parser unit tests; run them with nargo, without signatures."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prepare_leaf', BASE / 'prepare-leaf.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
fixture = json.loads((BASE / 'proofs/leaf/real-apple.json').read_text())
w = p.prepare(fixture)
leaf = bytes(w['leaf'])
auth = bytes(w['auth'])
nonce = hashlib.sha256(auth[:w['auth_len']] + bytes(w['client_hash'])).digest()
workspace = BASE.parents[1] / 'tools/parser-tests'
workspace.mkdir(parents=True, exist_ok=True)
(workspace / 'Nargo.toml').write_text('[workspace]\nmembers = ["suite"]\n')
root = workspace / 'suite'
(root / 'src').mkdir(parents=True, exist_ok=True)
(root / 'Nargo.toml').write_text('[package]\nname = "parser_tests"\ntype = "lib"\nauthors = [""]\n'
                                '[dependencies]\napp_attest = { path = "../../../app-attest/circuit/core" }\n')
code = []
for name, data in [('LEAF', leaf), ('AUTH', auth), ('NONCE', nonce)]:
    code.append(f'global {name}: [u8;{len(data)}] = {list(data)};')


def test(name, body, fail=True):
    code.append(f'#[test{("(should_fail)" if fail else "")}]\nfn {name}() {{ {body} }}')


def parse(name, pos=None, value=None, length=None):
    change = '' if pos is None else f'b[{pos}] = {value};'
    test(name, f'let mut b = LEAF; {change} let _ = app_attest::certificate::parse(b,{length or w["leaf_len"]});')


parse('leaf_positive', length=w['leaf_len'])
# Replace the negative attribute for the valid baseline.
code[-1] = code[-1].replace('(should_fail)', '')
outer = p.children(leaf, p.tlv(leaf, 0))
tbs = p.children(leaf, outer[0])
before, after = p.children(leaf, tbs[4])
pkalg, pk = p.children(leaf, tbs[6])
version = tbs[0]
parse('certificate_size', length=4097)
parse('certificate_trailing', length=w['leaf_len'] + 1)
parse('outer_tag', 0, 0x31)
parse('der_long_tag', 0, 0x3f)
parse('der_indefinite', 1, 0x80)
parse('der_length_count', 1, 0x83)
parse('der_length_leading_zero', 2, 0)
parse('der_truncated', length=w['leaf_len'] - 1)
parse('signature_algorithm', outer[1][2] - 1, 3)
parse('signature_unused_bits', outer[2][1], 1)
parse('signature_sequence_tag', outer[2][1] + 1, 0x31)
sig = p.children(leaf, p.tlv(leaf, outer[2][1] + 1))
parse('signature_integer_tag', sig[0][0], 3)
parse('signature_negative', sig[0][1], 0x80)
# All bytes, rather than one byte, must be zero for the scalar test.
body = 'let mut b = LEAF;' + ''.join(f'b[{i}] = 0;' for i in range(sig[0][1], sig[0][2]))
test('zero_scalar', body + f'let _ = app_attest::certificate::parse(b,{w["leaf_len"]});')
parse('version', version[2] - 1, 1)
parse('serial_negative', tbs[1][1], 0x80)
parse('inner_algorithm', tbs[2][2] - 1, 3)
parse('validity_tag', before[0], 0x18)
parse('utc_digit', before[1], 0x2f)
parse('utc_timezone', before[2] - 1, 0x58)
parse('utc_year', before[1], ord('1'))
parse('utc_month', before[1] + 2, ord('2'))
parse('utc_day', before[1] + 4, ord('4'))
parse('utc_hour', before[1] + 6, ord('9'))
parse('utc_minute', before[1] + 8, ord('9'))
parse('utc_second', before[1] + 10, ord('9'))
parse('spki_algorithm', pkalg[2] - 1, 8)
parse('spki_unused_bits', pk[1], 1)
parse('spki_point_prefix', pk[1] + 1, 3)
parse('extension_wrapper_tag', tbs[7][0], 0xa2)

exts = p.children(leaf, p.children(leaf, tbs[7])[0])
by_oid = {}
for ext in exts:
    children = p.children(leaf, ext)
    oid = children[0]
    by_oid[leaf[oid[1]:oid[2]].hex()] = children


def extension(name, edits):
    changes = ''.join(f'b[{pos}] = {value};' for pos, value in edits)
    test(name, f'let mut b = LEAF; {changes} let c = app_attest::certificate::parse(b,{w["leaf_len"]});'
               'let _ = app_attest::certificate::extensions(b,c.ext,NONCE);')


for oid, name in [('551d13', 'constraints'), ('551d0f', 'usage'), ('551d25', 'eku'),
                  ('2a864886f763640802', 'nonce')]:
    nodes = by_oid[oid]
    extension(name + '_value', [(nodes[-1][2] - 1, leaf[nodes[-1][2] - 1] ^ 1)])
    extension(name + '_missing', [(nodes[0][2] - 1, 0x7e)])
for oid, name in [('551d13', 'constraints'), ('551d0f', 'usage')]:
    nodes = by_oid[oid]
    extension(name + '_critical_false', [(nodes[1][1], 0)])
extension('unknown_critical', [(by_oid['551d13'][0][2] - 1, 0x7e)])
extension('extension_value_tag', [(by_oid['551d25'][-1][0], 5)])
# OIDs 2.5.29.19 and 2.5.29.15 have equal widths.
extension('duplicate_oid', [(by_oid['551d0f'][0][2] - 1, 0x13)])

_, point, _ = p.parts(leaf[:w['leaf_len']])
x, y = list(point[:32]), list(point[32:])
auth_call = f'let _ = app_attest::auth::check(b,{{length}},{x},{y});'


def auth_test(name, edits=(), length=None, fail=True):
    changes = ''.join(f'b[{pos}] = {value};' for pos, value in edits)
    test(name, 'let mut b = AUTH;' + changes + auth_call.format(length=length if length is not None else w['auth_len']), fail)


auth_test('auth_positive', fail=False)
auth_test('auth_short', length=36)
auth_test('auth_long', length=1025)
auth_test('flags_reserved', [(32, auth[32] | 2)])
auth_test('flags_extensions', [(32, auth[32] & 0x7f)])
auth_test('flags_attested', [(32, auth[32] & 0xbf)])
auth_test('counter', [(36, 1)])
auth_test('credential_length', [(54, 31)])
auth_test('credential_kid', [(55, auth[55] ^ 1)])
auth_test('cose_prefix', [(87, 0xa4)])
auth_test('cose_x', [(97, auth[97] ^ 1)])
auth_test('cose_y', [(132, auth[132] ^ 1)])
auth_test('map_type', [(164, 0x83)])
auth_test('map_count', [(164, 0xa5)])
auth_test('map_missing', [(164, 0xa0)])
auth_test('map_truncated', length=164)
auth_test('auth_trailing', length=w['auth_len'] + 1)
count, at = p.cbor_head(auth, 164)
for i in range(count):
    key_at = at
    size, start = p.cbor_head(auth, at)
    key = auth[start:start + size].decode()
    value_at = start + size
    size, value = p.cbor_head(auth, value_at)
    at = value + size
    auth_test(f'key_unknown_{i}', [(start, ord('z'))])
    auth_test(f'key_type_{i}', [(key_at, auth[key_at] ^ 0x20)])
    auth_test(f'value_type_{i}', [(value_at, auth[value_at] ^ 0x20)])
    if key == 'apple_cd_hash_type_01':
        auth_test('cdhash_type_value', [(value, 3)])
    if key == 'apple_cd_hash_hash_01':
        auth_test('cdhash_length', [(value_at + 1, 31)])


def wrap(tag, body):
    n = len(body)
    size = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + size + body


def raw(n):
    return leaf[n[0]:n[2]]


def leaf_fields(name, changes, trailing=b''):
    fields = [changes.get(i, raw(n)) for i, n in enumerate(tbs)]
    der = wrap(0x30, wrap(0x30, b''.join(fields) + trailing) + raw(outer[1]) + raw(outer[2]))
    test(name, f'let b: [u8;4096] = {list(der.ljust(4096, bytes([0])))}; let _ = app_attest::certificate::parse(b,{len(der)});')


leaf_fields('serial_width', {1: wrap(2, bytes([1]) * 21)})
leaf_fields('serial_padded', {1: wrap(2, bytes([0, 1]))})
leaf_fields('serial_empty', {1: wrap(2, b'')})
leaf_fields('validity_trailing', {4: wrap(0x30, raw(before) + raw(after) + bytes([0]))})
leaf_fields('tbs_trailing', {}, bytes([0]))
leaf_fields('extensions_trailing', {7: wrap(0xa3, wrap(0x30, b''.join(raw(n) for n in exts)) + bytes([0]))})
leaf_fields('public_key_length', {6: wrap(0x30, raw(pkalg) + wrap(3, leaf[pk[1]:pk[2]-1]))})


def auth_bytes(name, b, fail=True):
    test(name, f'let b: [u8;1024] = {list(b.ljust(1024, bytes([0])))};' + auth_call.format(length=len(b)), fail)


original = auth[:w['auth_len']]
auth_bytes('map_nonminimal24', original[:164] + bytes([0xb8, 3]) + original[165:])
auth_bytes('map_nonminimal25', original[:164] + bytes([0xb9, 0, 3]) + original[165:])
auth_bytes('map_length_profile', original[:164] + bytes([0xba]) + original[165:])
auth_bytes('head_truncated24', original[:164] + bytes([0xb8]))
auth_bytes('head_truncated25', original[:164] + bytes([0xb9, 1]))
auth_bytes('key_nonminimal24', original[:165] + bytes([0x78, 21]) + original[166:])
auth_bytes('item_bounds', original[:165] + bytes([0x78, 0xff]) + original[166:])
entries = []
count, at = p.cbor_head(auth, 164)
for _ in range(count):
    start = at
    size, at = p.cbor_head(auth, at)
    at += size
    size, at = p.cbor_head(auth, at)
    at += size
    entries.append(original[start:at])
auth_bytes('map_duplicate', original[:164] + bytes([0xa4]) + b''.join(entries + [entries[0]]))
auth_bytes('map_reordered_positive', original[:165] + b''.join(reversed(entries)), False)
# Optional bundle text may be empty; the contract imposes no text policy.
bundle_key = b'apple_bundle_version_01'
auth_bytes('bundle_positive', original[:164] + bytes([0xa4]) + b''.join(entries) + bytes([0x60 + len(bundle_key)]) + bundle_key + bytes([0x60]), False)


def ext_bytes(name, body, fail=True):
    der = wrap(0x30, body)
    test(name, f'let b: [u8;4096] = {list(der.ljust(4096, bytes([0])))};'
               f'let n = app_attest::der::expect(b,0,{len(der)},0x30);'
               'let _ = app_attest::certificate::extensions(b,n,NONCE);', fail)


base_ext = b''.join(raw(n) for n in exts)
unknown = lambda i: wrap(0x30, wrap(6, bytes([0x55, 0, i])) + wrap(4, b''))
ext_bytes('unknown_noncritical_positive', base_ext + unknown(1), False)
ext_bytes('too_many_extensions', base_ext + b''.join(unknown(i) for i in range(17-len(exts))))
ext_bytes('duplicate_unknown_oid', base_ext + unknown(1) * 2)
empty_oid = wrap(0x30, wrap(6, b'') + wrap(4, b''))
ext_bytes('empty_oid_positive', base_ext + empty_oid, False)
ext_bytes('empty_oid_duplicate', base_ext + empty_oid * 2)
acl_oid = bytes.fromhex('2a864886f763640806')
ext_bytes('acl_missing', b''.join(raw(n) for n in exts if acl_oid not in raw(n)))
ext_bytes('critical_length', base_ext + wrap(0x30, wrap(6, bytes([0x55, 0, 99])) + wrap(1, bytes([255, 255])) + wrap(4, b'')))
def signature_test(name, r=None, ss=None, fields=b'', trailing=b'', outer_trailing=b''):
    rb = leaf[sig[0][1]:sig[0][2]] if r is None else r
    sb = leaf[sig[1][1]:sig[1][2]] if ss is None else ss
    signature = wrap(3, bytes([0]) + wrap(0x30, wrap(2, rb) + wrap(2, sb) + fields) + trailing)
    der = wrap(0x30, raw(outer[0]) + raw(outer[1]) + signature + outer_trailing)
    test(name, f'let b: [u8;4096] = {list(der.ljust(4096, bytes([0])))}; let _ = app_attest::certificate::parse(b,{len(der)});')


signature_test('signature_fields_trailing', fields=bytes([5, 0]))
signature_test('signature_sequence_trailing', trailing=bytes([0]))
signature_test('signature_bitstring_trailing', outer_trailing=bytes([0]))
signature_test('signature_integer_empty', r=b'')
signature_test('signature_scalar_zero', r=bytes([0]))
signature_test('signature_integer_padded', r=bytes([0, 1]))
signature_test('signature_integer_width', r=bytes([1]) * 49)
order = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973')
signature_test('signature_scalar_range', r=bytes([0]) + order)
test('der_bounds', 'let b: [u8;4096] = [0;4096]; let _ = app_attest::der::node(b,1,1);')
test('der_nonminimal_length', 'let mut b: [u8;4096] = [0;4096]; b[0] = 0x30; b[1] = 0x81; b[2] = 127; let _ = app_attest::der::node(b,0,130);')
leaf_fields('utc_length', {4: wrap(0x30, wrap(0x17, leaf[before[1]:before[2]-1]) + raw(after))})
nonce_oid = bytes.fromhex('2a864886f763640802')
ext_bytes('nonce_length', b''.join(raw(n) for n in exts if nonce_oid not in raw(n)) + wrap(0x30, wrap(6, nonce_oid) + wrap(4, bytes([0]) * 37)))
(root / 'src/lib.nr').write_text('\n'.join(code) + '\n')
subprocess.run(['nargo', 'test', '--test-threads', '1', *sys.argv[1:]], cwd=root, check=True)
