#!/usr/bin/env python3
"""Observe a bounded subset of native registry identities; never a peer census."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from check_participation_release import CheckFailure, DEFAULT_MANIFEST, Reader, need

ZERO = '0x' + '0' * 64
HEX32 = re.compile(r'0x[0-9a-fA-F]{64}')
QUANTITY = re.compile(r'0x(?:0|[1-9a-f][0-9a-f]*)')

def quantity(value):
    need(isinstance(value, str) and QUANTITY.fullmatch(value) is not None, 'malformed quantity')
    return int(value, 16)

def word_bytes(value, count):
    need(isinstance(value, str) and re.fullmatch(r'0x[0-9a-fA-F]{' + str(count * 64) + '}', value) is not None,
         'malformed ABI result')
    raw = bytes.fromhex(value[2:])
    return [raw[n:n + 32] for n in range(0, len(raw), 32)]

def boolean(word):
    value = int.from_bytes(word, 'big')
    need(value in (0, 1), 'malformed ABI boolean')
    return bool(value)

def base(state, now):
    return {'version': 1, 'state': state,
        'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'max_age': 90, 'observation_source': 'operator-rpc-relay',
        'members': [], 'independent_operator_count': None, 'independent_device_count': None, 'liveness': 'unknown'}

def observe(manifest, reader, roster=None, now=None):
    live_clock = now is None
    now = int(time.time()) if live_clock else now
    result = base('unknown', now)
    try:
        chain = manifest['chain']
        category = manifest['category'].lower()
        roster = [] if roster is None else roster
        need(HEX32.fullmatch(category) is not None and isinstance(roster, list) and len(roster) <= 64,
             'invalid coverage configuration')
        need(all(isinstance(member, str) and HEX32.fullmatch(member) for member in roster), 'invalid opted-in identity')
        ids = sorted(set(member.lower() for member in roster))
        need(len(ids) == len(roster), 'duplicate opt-in identity')
        def rpc(method, params):
            value = reader.json(chain['rpc'], {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
            need(isinstance(value, dict) and value.get('jsonrpc') == '2.0' and value.get('id') == 1
                 and 'error' not in value and 'result' in value, 'RPC refused')
            return value['result']
        need(quantity(rpc('eth_chainId', [])) == chain['id'], 'wrong chain')
        block_hex = rpc('eth_blockNumber', [])
        height = quantity(block_hex)
        need(height <= 2**53 - 1, 'unsupported block height')
        def get_header():
            header = rpc('eth_getBlockByNumber', [block_hex, False])
            need(isinstance(header, dict) and header.get('number') == block_hex
                 and isinstance(header.get('hash'), str) and HEX32.fullmatch(header['hash']), 'malformed header')
            stamp = quantity(header.get('timestamp'))
            need(-15 <= now - stamp <= 120, 'stale chain')
            return header, stamp
        header, stamp = get_header()
        def contract(data, count):
            return word_bytes(rpc('eth_call', [{'to': chain['registry'], 'data': data}, block_hex]), count)
        paused = boolean(contract('0x5c975abb', 1)[0])
        epoch = int.from_bytes(contract('0xd71779d9' + ZERO[2:], 1)[0], 'big')
        need(epoch < 2**64, 'invalid epoch')
        shared = contract('0xd5b7abaf' + ZERO[2:], 4)
        committed = boolean(shared[3])
        fingerprint = hashlib.sha256(b'\x04' + shared[0] + shared[1]).hexdigest() if committed else None
        members = []
        for member in ids:
            fields = contract('0x1f718bf4' + member[2:], 4)
            need(fields[0][:12] == b'\0' * 12, 'invalid owner encoding')
            registered = fields[0] != b'\0' * 32
            member_category = '0x' + fields[1].hex()
            checked = int.from_bytes(fields[2], 'big')
            revoked = boolean(fields[3])
            need(checked < 2**64 and checked <= stamp and (not registered or member_category == category), 'invalid member state')
            need(registered or (checked == 0 and fields[1] == b'\0' * 32 and not revoked), 'inconsistent absent member')
            members.append({'member_id': member, 'category': member_category, 'registered': registered,
                'last_checked': checked if registered else None, 'revoked': revoked, 'liveness': 'unknown',
                'source': 'operator-opt-in'})
        info = reader.json(manifest['relay'] + '/info')
        status = reader.json(manifest['relay'] + '/status')
        need(isinstance(info, dict) and info.get('chainId') == chain['id']
             and str(info.get('registry')).lower() == chain['registry'].lower()
             and info.get('protocolVersion') == manifest['protocolVersion'], 'relay mismatch')
        need(isinstance(status, dict) and type(status.get('sponsorWritesPaused')) is bool, 'invalid relay status')
        final_header, final_stamp = get_header()
        need(final_header['hash'] == header['hash'] and final_stamp == stamp, 'chain changed during observation')
        # A slow scan must not produce a newly dated green observation of old state.
        final_now = int(time.time()) if live_clock else now
        need(-15 <= final_now - stamp <= 120, 'observation expired')
        result.update({'state': 'observed', 'chain_id': chain['id'], 'registry': chain['registry'],
            'protocol_version': manifest['protocolVersion'],
            'block': {'number': height, 'hash': header['hash'], 'timestamp': stamp},
            'coverage': {'from_block': height, 'to_block': height, 'opt_in_identities': len(ids),
                'complete_census': False, 'selection': 'operator-supplied-public-opt-in-roster'},
            'network_paused': paused, 'relay': {'state': 'observed', 'sponsor_writes_paused': status['sponsorWritesPaused']},
            'shared_key': {'scope': ZERO, 'epoch': str(epoch), 'committed': committed, 'public_key_sha256': fingerprint},
            'members': members})
        need(len(json.dumps(result).encode()) <= 65536, 'output limit')
        return result
    except (CheckFailure, KeyError, TypeError, ValueError, AttributeError):
        result = base('unknown', now)
        result['reason'] = 'observation-unavailable'
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--roster', type=Path, help='Reviewed public opt-in roster: JSON array of member IDs; default empty')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text())
        roster = [] if args.roster is None else json.loads(args.roster.read_text())
        result = observe(manifest, Reader(), roster=roster)
    except (OSError, ValueError):
        result = base('unknown', int(time.time()))
        result['reason'] = 'observation-unavailable'
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        # Atomic replacement prevents the dashboard reading a partial feed.
        temporary = args.output.with_name(args.output.name + '.tmp')
        temporary.write_text(encoded)
        temporary.replace(args.output)
    print(encoded, end='')
    return 0 if result['state'] == 'observed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
