"""Bounded uncompressed USTAR reader; never extracts candidate paths to disk.

Only authenticated application source bytes, no candidate imports or execution.
"""
import hashlib
import importlib.util
from pathlib import Path

_PROTOCOL = Path(__file__).resolve().parents[1] / 'bounty-recipes/protocol.py'
_spec = importlib.util.spec_from_file_location('bounty_protocol', _PROTOCOL)
protocol = importlib.util.module_from_spec(_spec)
# This module belongs to the independently pinned application-image closure.
exec(compile(_PROTOCOL.read_bytes(), str(_PROTOCOL), 'exec'), protocol.__dict__)
need = protocol.require
sha = lambda value: hashlib.sha256(value).hexdigest()
MAX_BYTES = 32 * 1024 * 1024
BOARD = ['apps/board/index.html', 'apps/board/logic.js', 'apps/board/ui.js']


def _text(raw):
    head, separator, tail = raw.partition(b'\0')
    need(separator and not any(tail), 'noncanonical tar string')
    return head.decode('ascii')


def decode_source(raw, manifest_raw, expected_tree):
    manifest = protocol.parse_json(manifest_raw, 4 * 1024 * 1024)
    protocol.validate_tree(manifest)
    need(protocol.tree_digest(manifest) == expected_tree, 'source tree identity differs')
    need(len({row['path'].casefold() for row in manifest}) == len(manifest), 'case alias')
    need(1024 <= len(raw) <= MAX_BYTES and len(raw) % 512 == 0, 'tar byte bound')
    offset = 0
    files = {}
    for row in manifest:
        header = raw[offset:offset+512]
        need(len(header) == 512 and any(header), 'missing source tar header')
        need(header[257:265] == b'ustar\x0000', 'USTAR required')
        need(header[156:157] in (b'\0', b'0') and not any(header[157:257]) and not any(header[500:]), 'regular tar member required')
        checksum = header[148:156]
        need(len(checksum) == 8 and checksum[6:] == b'\0 ' and all(c in b'01234567' for c in checksum[:6]), 'tar checksum encoding')
        need(int(checksum[:6], 8) == sum(header[:148]) + 8*32 + sum(header[156:]), 'tar checksum')
        name = _text(header[:100]); prefix = _text(header[345:500])
        name = prefix + '/' + name if prefix else name
        need(name == row['path'], 'tar membership/order differs')
        for field, expected in ((header[100:108], row['mode']), (header[124:136], row['bytes'])):
            need(field[-1:] == b'\0' and field[:-1] and all(c in b'01234567' for c in field[:-1]), 'tar numeric encoding')
            need(int(field[:-1], 8) == expected, 'tar mode/size differs')
        offset += 512
        size = row['bytes']; data = raw[offset:offset+size]
        need(len(data) == size and sha(data) == row['sha256'], 'source file bytes differ')
        offset += size
        padding = (-size) % 512
        need(not any(raw[offset:offset+padding]) and len(raw[offset:offset+padding]) == padding, 'tar padding')
        offset += padding
        files[name] = data
    need(raw[offset:] == bytes(1024), 'tar trailing data/terminator')
    return manifest, files


def admission_relation(base_manifest, base_files, candidate_manifest, candidate_files):
    """External pre-admission gate: BOTH trees already decoded/authenticated.

    This narrower v2 record makes no Git/upstream provenance assertions.
    Stage-local primary audit cannot call it without the retained base tree.
    """
    protocol.validate_tree(base_manifest); protocol.validate_tree(candidate_manifest)
    need(set(base_files) == set(candidate_files) == {r['path'] for r in base_manifest} == {r['path'] for r in candidate_manifest}, 'source add/delete')
    base = {r['path']:r for r in base_manifest}; candidate = {r['path']:r for r in candidate_manifest}
    changed = []
    for name in sorted(base):
        need(base[name]['mode'] == candidate[name]['mode'], 'source mode change')
        for row, files in ((base[name], base_files),(candidate[name],candidate_files)):
            need(len(files[name]) == row['bytes'] and sha(files[name]) == row['sha256'], 'relation unauthenticated file bytes')
        if base_files[name] != candidate_files[name]:
            need(name in BOARD, 'source replacement outside fixed board allowlist')
            changed.append(name)
    need(bool(changed), 'empty admission transform')
    return {'schema':'dsmack-bounty-admission-transform/2','operation':'allowlisted-existing-file-replacement',
            'base_tree_manifest_sha256':protocol.tree_digest(base_manifest),
            'candidate_tree_manifest_sha256':protocol.tree_digest(candidate_manifest),
            'allowed_paths':BOARD,'changed_files':changed}
