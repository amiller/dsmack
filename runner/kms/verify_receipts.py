"""Verify a runner output directory: the boot binding (clientData: compose_hash, receipt_pub)
and every receipt in receipts.jsonl (signature under receipt_pub, seq, prev chain, compose_hash), and for receipts
that carry provider_quote_sha256, that OUT_DIR/provider-quote-<sha16>.json holds report bytes with exactly that sha256.

usage: verify_receipts.py OUT_DIR --compose app-compose.json (--dev-unattested | --cdhash HEX)
The output names the app the boot clientData (for --task, the peer's enrollment) was released under.
--cdhash verifies OUT_DIR/attest.json (a /attest response; the runner keeps enrollment evidence in RAM only) against
the verifier/macos_policy.py policy with that CDHash allowlisted, and requires its enrollment to bind the boot's compose_hash and receipt_pub.
--dev-unattested (DEV-ONLY) accepts a clientData with attested=false; nothing binds receipt_pub to a binary.

usage: verify_receipts.py COLLECT_DIR --task --peer-compose peer-app-compose.json (--dev-unattested | --cdhash HEX)
COLLECT_DIR is an extracted /task/collect tar (guest/, out/). guest/attest.json is the runner's assertion over
sha256(guest/clientData.bin) (domain mac-compose-task-boot/1, never an /attest mac-compose-assert/1 wrapper) under the peer's App Attest enrollment, which must bind the peer compose; the task image must
be in its tasks.images; clientData.compose_hash must be sha256(guest/app-compose.json); receipts carry `event`, start with
task-start and end with exit, whose out_sha256 must equal sha256 of the deterministic tar rebuilt from out/ (det_tar,
the same bytes as Tasks.swift detTar).
"""
import argparse, base64, hashlib, json, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from verifier.core import Reject, require, unb64, unique_json, verify_assertion, verify_attestation
from verifier.macos_policy import policy, root

p = argparse.ArgumentParser()
p.add_argument('out', type=Path)
p.add_argument('--compose', type=Path)
p.add_argument('--task', action='store_true')
p.add_argument('--peer-compose', type=Path)
g = p.add_mutually_exclusive_group(required=True)
g.add_argument('--dev-unattested', action='store_true')
g.add_argument('--cdhash')
a = p.parse_args()
require(a.task == (a.peer_compose is not None) and a.task == (a.compose is None), 'need --compose, or --task with --peer-compose')


def det_tar(entries):
    """[(name, mode, data or None for a directory)] -> ustar bytes, as Tasks.swift detTar."""
    t = b''
    for name, mode, data in sorted(entries, key=lambda e: e[0].encode()):
        n, prefix = name.encode(), b''
        if len(n) > 100:
            i = next((i for i, c in enumerate(n) if c == 0x2f and len(n) - i - 1 <= 100), None)
            require(i is not None and i <= 155 and i < len(n) - 1, f'path_does_not_fit_ustar {name}')
            prefix, n = n[:i], n[i + 1:]
        o = lambda v, w: format(v, 'o').zfill(w - 1).encode() + b'\0'
        h = bytearray(512)
        for off, b in ((0, n), (100, o(mode, 8)), (108, o(0, 8)), (116, o(0, 8)), (124, o(0 if data is None else len(data), 12)),
                       (136, o(0, 12)), (148, b' ' * 8), (156, b'5' if data is None else b'0'), (257, b'ustar\x0000'), (345, prefix)):
            h[off:off + len(b)] = b
        h[148:156] = o(sum(h), 7) + b' '
        t += bytes(h) + (b'' if data is None else data + b'\0' * ((512 - len(data) % 512) % 512))
    return t + b'\0' * 1024


def out_entries(root):
    e = [('out/', 0o755, None)]
    for f in sorted(root.rglob('*')):
        rel = 'out/' + f.relative_to(root).as_posix()
        require(not f.is_symlink() and (f.is_dir() or f.is_file()), f'out_not_file_or_dir {rel}')
        e.append((rel + '/', 0o755, None) if f.is_dir() else (rel, 0o755 if f.stat().st_mode & 0o111 else 0o644, f.read_bytes()))
    return e


g = a.out / 'guest' if a.task else a.out
compose = g / 'app-compose.json' if a.task else a.compose
client_data = (g / 'clientData.bin').read_bytes()
client = unique_json(client_data)
# A task binding must be a task-boot clientData; an /attest response (mac-compose-assert/1, data chosen by the peer) is not one.
require(client['domain'] == ('mac-compose-task-boot/1' if a.task else 'mac-compose-boot/1'), f"wrong_boot_domain {client.get('domain')}")
require(client['compose_hash'] == hashlib.sha256(compose.read_bytes()).hexdigest(), 'compose_hash_mismatch')
if a.task:
    peer_bytes = a.peer_compose.read_bytes()
    ev = unique_json((g / 'attest.json').read_bytes())
    require(unique_json(unb64(ev['assertClientData'])).get('domain') == 'mac-compose-task-boot/1', 'task_binding_not_task_boot_domain')
    require(unb64(ev['assertClientData']) == client_data, 'evidence_not_over_task_clientData')
    enroll_bytes = unb64(ev['bootClientData'])
    enroll = unique_json(enroll_bytes)
    require(enroll['compose_hash'] == hashlib.sha256(peer_bytes).hexdigest(), 'peer_compose_hash_mismatch')
    peer, task = unique_json(peer_bytes), unique_json(compose.read_bytes())
    image = [s['image'] for s in json.loads(task['docker_compose_file'])['services'].values()]
    require(len(image) == 1 and image[0] in peer['tasks']['images'], 'task_image_not_admitted_by_peer')
    eg = task['egress']
    require(task['kms_enabled'] is False and eg['allow'] == [] and eg.get('tcp', []) == [] and eg['max_requests'] == eg['max_tokens'] == 0, 'task_compose_not_template')
    if a.dev_unattested:
        require(ev['type'] == 'dev' and client['attested'] is False and enroll['attested'] is False, 'expected_unattested_boot')
        binding = 'DEV-UNATTESTED (receipt_pub not bound to any binary)'
    else:
        require(ev['type'] == 'macrunner' and client['attested'] is True, 'boot_not_attested')
        pol = policy(bytes.fromhex(a.cdhash))
        att = verify_attestation(unb64(ev['attestation']), ev['keyId'], enroll_bytes, pol, root())
        require(enroll['domain'] in ('mac-compose-boot/1', 'mac-compose-enroll/1') and enroll['attested'] is True, 'wrong_enrollment_domain')
        sig = verify_assertion(unb64(ev['assertion']), client_data, att['public_key'], 0, pol)
        require(sig['signals']['cdhash'] == att['signals']['cdhash'], 'assertion_cdhash_differs')
        binding = f'attested (runner assertion under the peer enrollment), cdhash {a.cdhash}'
elif a.dev_unattested:
    require(client['attested'] is False, 'expected_unattested_boot')
    binding = 'DEV-UNATTESTED (receipt_pub not bound to any binary)'
else:
    require(client['attested'] is True, 'boot_not_attested')
    ev = unique_json((a.out / 'attest.json').read_bytes())
    enroll_bytes = unb64(ev['bootClientData'])
    verify_attestation(unb64(ev['attestation']), ev['keyId'], enroll_bytes, policy(bytes.fromhex(a.cdhash)), root())
    enroll = unique_json(enroll_bytes)
    require(enroll['domain'] in ('mac-compose-boot/1', 'mac-compose-enroll/1') and enroll['attested'] is True, 'wrong_enrollment_domain')
    require(enroll['receipt_pub'] == client['receipt_pub'] and enroll['compose_hash'] == client['compose_hash'], 'enrollment_not_bound_to_boot')
    binding = f'attested, cdhash {a.cdhash}'

pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client['receipt_pub']))
prev = '0' * 64
lines = (g / 'receipts.jsonl').read_text().splitlines()
quotes, events = {}, []
for seq, line in enumerate(lines, 1):
    r = unique_json(line)
    body = r['body'].encode()
    try:
        pub.verify(bytes.fromhex(r['sig']), body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Reject(f'bad_signature seq={seq}') from None
    b = unique_json(body)
    require(b['domain'] == 'mac-compose-receipt/1', f'wrong_receipt_domain seq={seq}')
    require(b['seq'] == seq, f'seq_gap expected={seq} got={b["seq"]}')
    require(b['prev'] == prev, f'broken_prev_chain seq={seq}')
    require(b['compose_hash'] == client['compose_hash'], f'compose_hash_mismatch seq={seq}')
    if a.task:
        require(b.get('event') in ('task-start', 'attach', 'detach', 'exit'), f'unknown_event seq={seq}')
        events.append(b)
    if 'provider_quote_sha256' in b:
        q = quotes.setdefault(b['provider_quote_sha256'], unique_json((a.out / f'provider-quote-{b["provider_quote_sha256"][:16]}.json').read_bytes()))
        require(hashlib.sha256(base64.b64decode(q['report_b64'], validate=True)).hexdigest() == b['provider_quote_sha256'], f'provider_quote_bytes_mismatch seq={seq}')
        require(b.get('onchain') == q.get('onchain'), f'provider_quote_onchain_mismatch seq={seq}')
    prev = hashlib.sha256(body).hexdigest()
task = {}
if a.task:
    names = [e['event'] for e in events]
    require(names[0] == 'task-start' and names[-1] == 'exit' and names.count('exit') == 1 and names.count('task-start') == 1, f'bad_event_order {names}')
    require(names[1:-1] == ['attach', 'detach'] * (len(names[1:-1]) // 2), f'attach_detach_not_paired {names}')
    out_sha = hashlib.sha256(det_tar(out_entries(a.out / 'out'))).hexdigest()
    require(events[-1]['out_sha256'] == out_sha, f'out_sha256_mismatch receipt={events[-1]["out_sha256"]} out={out_sha}')
    task = {'events': names, 'inputs_sha256': events[0]['inputs_sha256'], 'exit': {k: events[-1][k] for k in ('exit_code', 'wall_seconds', 'reason', 'out_sha256')}}
print(json.dumps({'ok': True, 'receipts': len(lines), **task, 'provider_quotes': {h: {k: q.get(k) for k in ('kind', 'tcb_status', 'tls_spki_sha256', 'onchain')} for h, q in quotes.items()},
                  'app': (enroll if a.task else client)['app'], 'compose_hash': client['compose_hash'],
                  'receipt_pub': client['receipt_pub'], 'boot_binding': binding, 'head': prev}, indent=2))
