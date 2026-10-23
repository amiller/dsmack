"""Positive publication closure; engineering fixtures confer no Apple provenance."""
import hashlib
import json
import re
from .errors import Refusal, need
from .frozen import canonical_bytes, load_json_bytes

PREFIX = b'DSMACK_RESULT_CLOSED_V1 '
HEX = re.compile(r'^[0-9a-f]{64}$')

def _name(value):
    need(isinstance(value, str) and 1 <= len(value) <= 128 and
         all(33 <= ord(c) <= 126 and c not in '/\\' for c in value),
         'closure_bad_name')

def validate_context(context):
    need(isinstance(context, dict) and set(context) == {'schema','attempt_id','selectors'}, 'closure_context_keys')
    need(context['schema'] == 'dsmack-result-closure-context/1', 'closure_context_schema')
    need(isinstance(context['attempt_id'], str) and re.fullmatch('[0-9a-f]{32}', context['attempt_id']) is not None, 'closure_attempt_id')
    names = context['selectors']
    need(isinstance(names, list) and 1 <= len(names) <= 32, 'closure_selector_count')
    for name in names: _name(name)
    need(names == sorted(set(names)), 'closure_selector_order')
    need(len(canonical_bytes(context)) <= 8192, 'closure_context_size')
    return context

def make_frame(context, entries, ending=b'\n'):
    validate_context(context)
    body = {'schema':'dsmack-result-closure/1', 'attempt_context_sha256':hashlib.sha256(canonical_bytes(context)).hexdigest(), 'result_device':'vdd', 'closure':'synced-unmounted', 'selectors':entries}
    frame = PREFIX + canonical_bytes(body) + ending
    # Use the consumer grammar even for engineering fixture generation.
    parse(frame, context)
    return frame

def parse(console, context):
    validate_context(context)
    need(isinstance(console, bytes), 'closure_console_type')
    frames = [line for line in console.split(b'\n') if line.startswith(PREFIX)]
    need(len(frames) == 1, 'closure_frame_count')
    line = frames[0]
    # A frame must actually end at LF, not the last unterminated fragment.
    need(not (console.split(b'\n')[-1].startswith(PREFIX)), 'closure_truncated')
    need(len(line) + 1 <= 16384, 'closure_frame_size')
    body = line[len(PREFIX):]
    if body.endswith(b'\r'): body = body[:-1]
    need(b'\r' not in body and b'\x00' not in body and body.isascii(), 'closure_wire_bytes')
    try:
        obj = load_json_bytes(body, max_bytes=16384)
    except Exception as exc:
        raise Refusal("closure_bad_json", str(exc)) from exc
    need(canonical_bytes(obj) == body, 'closure_not_canonical')
    need(isinstance(obj, dict) and set(obj) == {'schema','attempt_context_sha256','result_device','closure','selectors'}, 'closure_keys')
    need(obj['schema'] == 'dsmack-result-closure/1' and obj['result_device'] == 'vdd' and obj['closure'] == 'synced-unmounted', 'closure_protocol')
    need(obj['attempt_context_sha256'] == hashlib.sha256(canonical_bytes(context)).hexdigest(), 'closure_context_mismatch')
    entries = obj['selectors']
    need(isinstance(entries, list) and 1 <= len(entries) <= 32, 'closure_entry_count')
    names = []
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == {'selector','run_id','receipt_sha256','index_sha256'}, 'closure_entry_keys')
        _name(entry['selector']); _name(entry['run_id'])
        for key in ('receipt_sha256','index_sha256'):
            need(isinstance(entry[key], str) and HEX.fullmatch(entry[key]) is not None, 'closure_digest')
        names.append(entry['selector'])
    need(names == context['selectors'], 'closure_selector_mismatch')
    return obj

def reconcile(console, context, retained):
    obj = parse(console, context)
    need(set(retained) == set(context['selectors']), 'closure_retained_selectors')
    for entry in obj['selectors']:
        receipt_bytes, index_bytes = retained[entry['selector']]
        receipt = load_json_bytes(receipt_bytes)
        index = load_json_bytes(index_bytes)
        need(entry['run_id'] == receipt['run_id'] == index['run_id'], 'closure_run_id_mismatch')
        need(entry['receipt_sha256'] == hashlib.sha256(receipt_bytes).hexdigest(), 'closure_receipt_mismatch')
        need(entry['index_sha256'] == hashlib.sha256(index_bytes).hexdigest(), 'closure_index_mismatch')
    return obj
