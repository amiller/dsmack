#!/usr/bin/env python3
"""Live remote-agent probes and exhaustive host marker scans.

The owner starts/stops VMs. These probes use the client transport and its verifier;
marker values stay in client memory or enter the scan command through stdin.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

NAMES = ('credential', 'repo', 'prompt')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def new_markers():
    return {name: secrets.token_bytes(32) for name in NAMES}


def plant(markers, repo, credential, prompt):
    """Keep provider tokens unchanged; put a marker in accepted credential metadata."""
    require(set(markers) == set(NAMES) and all(len(v) == 32 for v in markers.values()), 'three 32-byte markers required')
    selected = copy.deepcopy(credential)
    selected['claudeAiOauth']['rateLimitTier'] = markers['credential'].hex()
    path = Path(repo)/'private-marker.bin'
    with path.open('xb') as stream:
        stream.write(markers['repo'])
    text = prompt + '\nInclude this exact text as a comment in the patch and in your final response: ' + markers['prompt'].hex()
    return selected, text


def scan(roots, markers, control=False, chunk_size=4 << 20):
    """Read every regular file, with overlap to find encodings across chunk boundaries."""
    require(set(markers) == set(NAMES) and all(len(v) == 32 for v in markers.values()), 'three 32-byte markers required')
    patterns = [(name, encoding, value) for name, marker in markers.items() for encoding, value in
                [('raw', marker), ('hex', marker.hex().encode()), ('HEX', marker.hex().upper().encode()),
                 ('base64', base64.b64encode(marker))]]
    overlap = max(len(value) for _, _, value in patterns) - 1
    require(chunk_size > overlap, 'scan chunk is too short')
    hits, files, size = [], 0, 0
    special = []
    roots = [Path(p).resolve(strict=True) for p in roots]
    require(roots and all(p.is_dir() for p in roots), 'scan roots must be directories')
    for root in roots:
        for parent, directories, names in os.walk(root, onerror=lambda e: (_ for _ in ()).throw(e)):
            # A directory symlink can escape a run or make a cycle. A run-owned
            # directory must be an actual directory to be part of this scan.
            for name in directories:
                path = Path(parent)/name
                require(not path.is_symlink(), 'directory symlink in scan root: ' + str(path))
            for name in names:
                path = Path(parent)/name
                mode = path.stat().st_mode
                if not stat.S_ISREG(mode):
                    special.append(str(path))
                    continue
                files += 1
                found = set()
                with path.open('rb') as stream:
                    tail = b''
                    while True:
                        raw = stream.read(chunk_size)
                        if not raw:
                            break
                        size += len(raw)
                        data = tail + raw
                        for marker, encoding, value in patterns:
                            if value in data:
                                found.add((marker, encoding))
                        tail = data[-overlap:]
                hits.extend({'file': str(path), 'marker': marker, 'encoding': encoding} for marker, encoding in sorted(found))
    seen = {hit['marker'] for hit in hits}
    passed = seen == set(NAMES) if control else not hits
    return {'passed': passed, 'control': control, 'roots': [str(p) for p in roots], 'files': files,
            'bytes': size, 'hits': hits, 'nonregular': special, 'markers_seen': sorted(seen)}


def admission_refused(client, node, grant, job_id=None, error='grant'):
    """Send only the public control frame; never send a bundle after refusal."""
    job_id = job_id or secrets.token_hex(16)
    with client.connect(node) as exchange:
        exchange.send({'job_id': job_id, 'grant': grant})
        response = exchange.recv()
        require(response == {'status': 'refused', 'error': error}, 'unexpected admission response')
    return {'passed': True, 'response': response, 'job_id': job_id, 'bundle_sent': False}


def replay_same_run(client, node, grant, job_id):
    attempts = [admission_refused(client, node, grant, job_id, 'replay') for _ in range(2)]
    return {'passed': True, 'attempts': attempts}


def replay_other_run(client, node, grant, job_id, sealed):
    """A fresh target-bound grant isolates the boot key's replay protection."""
    with client.connect(node) as exchange:
        exchange.send({'job_id': job_id, 'grant': grant})
        ready = exchange.recv()
        require(ready == {'status': 'ready'}, 'second run did not admit replay probe')
        exchange.send(sealed)
        response = exchange.recv()
        require(response == {'status': 'refused', 'error': 'bundle'}, 'captured bundle opened in another run')
    return {'passed': True, 'response': response, 'job_id': job_id, 'captured_bundle_sent': True,
            'credential_released': False}


def exhaust(client, node, grant, sealed):
    """Consume a real one-second grant with a failed upload, then test admission."""
    require(grant['seconds'] == 1, 'exhaustion probe requires a one-second grant')
    job_id = secrets.token_hex(16)
    with client.connect(node) as exchange:
        exchange.send({'job_id': job_id, 'grant': grant})
        require(exchange.recv() == {'status': 'ready'}, 'exhaustion probe not admitted')
        # This capture is bound to a different job ID. The failed decryption
        # consumes the admitted second without reading any credential.
        exchange.send(sealed)
        require(exchange.recv() == {'status': 'refused', 'error': 'bundle'}, 'exhaustion upload unexpectedly opened')
    result = admission_refused(client, node, grant)
    result['consumed_grant_id'] = grant['grant_id']
    return result


def expired(client, node, grant, wait=False):
    remaining = grant['expires_at'] - time.time()
    require(wait or remaining <= 0, 'grant has not expired')
    while time.time() < grant['expires_at']:
        time.sleep(min(1, max(0, grant['expires_at'] - time.time())))
    result = admission_refused(client, node, grant)
    result['expires_at'] = grant['expires_at']
    result['checked_at'] = time.time()
    return result


def policy_refused(client, node, expected=None):
    """Exercise the same policy verification used before the client's upload."""
    before = client.bundles_sent
    try:
        client.policy.verify_registration(node)
    except ValueError as error:
        reason = str(error)
        require(expected is None or expected in reason, 'policy refusal was for a different reason')
    else:
        raise ValueError('client accepted the disallowed node')
    require(client.bundles_sent == before, 'policy probe sent a bundle')
    return {'passed': True, 'reason': reason, 'bundle_sent': False}


def flip_output(disk, artifact_path, debugfs='/usr/sbin/debugfs'):
    """Flip one encrypted-output byte on a stopped, owned ext4 result disk.

    The caller confirms the VM/helper have stopped before making this call. The
    artifact is read back from the disk after the change, before client fetch.
    """
    disk = Path(disk).resolve(strict=True)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', artifact_path) and '..' not in artifact_path.split('/'), 'artifact path')
    def debug(command):
        return subprocess.run([debugfs, '-R', command, str(disk)], check=True, capture_output=True).stdout
    original = debug('cat ' + artifact_path)
    result = json.loads(original)
    ciphertext = result['outputs']['patch']['ct'].encode()
    require(len(ciphertext) >= 32 and original.count(ciphertext) == 1, 'patch ciphertext not unique')
    offset = original.index(ciphertext) + len(ciphertext)//2
    replacement = ord('0') if original[offset] != ord('0') else ord('1')
    stats = debug('stats').decode()
    block_size = int(re.search(r'Block size:\s+(\d+)', stats).group(1))
    block = int(debug('bmap ' + artifact_path + ' ' + str(offset//block_size)).strip())
    require(block > 0, 'artifact byte is not allocated')
    physical = block * block_size + offset % block_size
    with disk.open('r+b', buffering=0) as stream:
        stream.seek(physical)
        require(stream.read(1) == original[offset:offset+1], 'debugfs byte mapping mismatch')
        stream.seek(physical)
        require(stream.write(bytes([replacement])) == 1, 'disk byte write failed')
        os.fsync(stream.fileno())
    tampered = debug('cat ' + artifact_path)
    require(len(original) == len(tampered) and sum(a != b for a, b in zip(original, tampered)) == 1, 'tamper did not change exactly one byte')
    json.loads(tampered)
    return original, tampered, {'artifact_path': artifact_path, 'artifact_byte': offset, 'disk_byte': physical,
                                'original_sha256': hashlib.sha256(original).hexdigest(),
                                'tampered_sha256': hashlib.sha256(tampered).hexdigest(), 'bytes_changed': 1}


def verify_tamper(verify, original, tampered):
    """The same verifier must first accept the original encrypted result."""
    from cryptography.exceptions import InvalidSignature, InvalidTag
    verify(json.loads(original))
    try:
        verify(json.loads(tampered))
    except (ValueError, InvalidSignature, InvalidTag) as error:
        return {'passed': True, 'original_accepted': True, 'tampered_refused': True,
                'error_type': type(error).__name__}
    raise ValueError('client accepted the changed result')


def assemble(conditions, out):
    require(set(conditions) == {str(i) for i in range(1, 8)}, 'SC1 through SC7 are required')
    result = {'passed': all(v.get('passed') is True for v in conditions.values()), 'conditions': conditions}
    Path(out).write_bytes(canonical(result))
    return result


def load_client(config):
    import client as remote
    paths = {name: Path(config[name]).expanduser().resolve() for name in ('binary', 'client_key', 'manifest', 'enrollment')}
    policy = remote.Policy(paths['manifest'].read_bytes(), paths['enrollment'], config['cdhash'],
                           config.get('rpc', 'https://sepolia.base.org'), config.get('attest', remote.ATTEST),
                           config.get('canary', remote.CANARY))
    return remote.Client(paths['binary'], paths['client_key'], config.get('broker', remote.BROKER),
                         config['broker_key'], policy)


def primary(config, out):
    """Run the marked real model turn and probes from the stand-in client host."""
    import client as remote
    from cryptography.hazmat.primitives import serialization
    out = Path(out).resolve()
    out.mkdir(mode=0o700)
    repo = out/'repo'; repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    (repo/'toy.py').write_text('def add(a, b):\n    return a - b\n')
    markers = ({k: bytes.fromhex(v) for k, v in json.loads(Path(config['marker_file']).expanduser().read_bytes()).items()}
               if 'marker_file' in config else new_markers())
    # This is user-side state, outside every owner/operator directory scanned
    # for SC2. It allows later scans and the independent current-path control.
    (out/'markers.json').write_bytes(canonical({k: v.hex() for k, v in markers.items()}))
    credential_path = Path(config.get('credential', remote.export_subscription.validator().default_credential_path(Path.home()/'.dsmack/private-inputs'))).expanduser()
    client = load_client(config)
    node = client.discover(config.get('node_peer'))
    discovery, _ = client.policy.verify_registration(node)
    grant = client.grant(node, config.get('seconds', 240))
    job_id = secrets.token_hex(16)
    (out/'job.json').write_bytes(canonical({'job_id': job_id, 'grant_id': grant['grant_id']}))
    prompt = 'Fix add in toy.py so it adds the two arguments. Keep the function name and argument names.'
    with client.connect(node) as exchange:
        client.check_grant(node, grant)
        exchange.admit(job_id, grant)
        credential, prompt = plant(markers, repo, remote.read_credential(credential_path), prompt)
        sealed, output_key = client.prepare(node, job_id, grant, credential, repo, prompt)
        del credential
        for name, value in [('discovery', node), ('grant', grant), ('sealed-input', sealed)]:
            (out/(name + '.json')).write_bytes(canonical(value))
        (out/'output-key.pem').write_bytes(output_key.private_bytes(serialization.Encoding.PEM,
              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        exchange.send(sealed)
        client.bundles_sent += 1
        result = exchange.recv()
    (out/'result.json').write_bytes(canonical(result))
    plain, turn = client.verify_result(node, discovery, result, job_id, grant, sealed, output_key)
    for name, raw in plain.items():
        (out/name).write_bytes(raw)
    subprocess.run(['git', '-C', str(repo), 'apply', '--check', str(out/'patch')], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'apply', str(out/'patch')], check=True, capture_output=True)
    values = {}
    exec((repo/'toy.py').read_text(), values)
    require(values['add'](7, 4) == 11 and values['add'](-2, 3) == 1, 'patch did not fix addition')
    require(markers['prompt'].hex().encode() in plain['patch'] and markers['prompt'].hex().encode() in plain['transcript'],
            'prompt marker did not reach patch and transcript')
    turn['patch_applied'] = True
    (out/'turn.json').write_bytes(canonical(turn))
    same_run = replay_same_run(client, node, grant, job_id)
    other_config = dict(config, client_key=str(out/'wrong-client.key'))
    wrong = admission_refused(load_client(other_config), node, grant)
    exhausted = exhaust(client, node, client.grant(node, 1), sealed)
    check = {'passed': True, 'correct_patch': True, 'per_job_attestation_verified': True,
             'receipt_verified': True, 'turn_verified': True, 'model': turn['observed_models'],
             'job_id': job_id, 'same_run_replay': same_run, 'wrong_client': wrong,
             'exhausted_grant': exhausted, 'bundles_sent': client.bundles_sent,
             'credential_source': 'local Mac stand-in client memory', 'transport': 'broker HTTP and libp2p relay'}
    (out/'check.json').write_bytes(canonical(check))
    return check


def second_run(config, capture, out):
    client = load_client(config)
    capture = Path(capture)
    original_node = json.loads((capture/'discovery.json').read_bytes())
    job_id = json.loads((capture/'job.json').read_bytes())['job_id']
    node = client.discover(config.get('node_peer'))
    require(node['manifest_sha256'] == original_node['manifest_sha256'], 'second run compose changed')
    require(node['secret_key'] != original_node['secret_key'], 'second run reused the job decryption key')
    grant = client.grant(node, config.get('seconds', 120))
    result = replay_other_run(client, node, grant, job_id,
                              json.loads((capture/'sealed-input.json').read_bytes()))
    result['second_run_replay'] = replay_same_run(client, node, grant, job_id)
    Path(out).write_bytes(canonical(result))
    return result


def verify_capture_tamper(config, capture, original, tampered, out):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    client = load_client(config)
    capture = Path(capture)
    node = json.loads((capture/'discovery.json').read_bytes())
    discovery, _ = client.policy.verify_registration(node)
    grant = json.loads((capture/'grant.json').read_bytes())
    sealed = json.loads((capture/'sealed-input.json').read_bytes())
    key = load_pem_private_key((capture/'output-key.pem').read_bytes(), password=None)
    job_id = json.loads((capture/'result.json').read_bytes())['statement']['job_id']
    result = verify_tamper(lambda value: client.verify_result(node, discovery, value, job_id, grant, sealed, key),
                           Path(original).read_bytes(), Path(tampered).read_bytes())
    Path(out).write_bytes(canonical(result))
    return result


def check_egress(probe, turn, proxy):
    from urllib.parse import urlsplit
    endpoint = urlsplit(proxy)
    port = endpoint.port or 80
    blocked_port = 18080 if port != 18080 else 18081
    require(probe == {'1.1.1.1:443': 'refused', f'{endpoint.hostname}:{blocked_port}': 'refused',
                      f'{endpoint.hostname}:{port}': 'connected'}, 'guest egress probe failed')
    require(turn['observed_models'] == ['claude-opus-4-8'] and turn['num_turns'] > 0, 'real model turn missing')
    return {'passed': True, 'guest': probe, 'real_model_turn': turn['job_id'], 'observed_models': turn['observed_models']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    scanner = commands.add_parser('scan', help='read marker-name -> 32-byte hex JSON from stdin')
    scanner.add_argument('--root', type=Path, action='append', required=True)
    scanner.add_argument('--control', action='store_true')
    scanner.add_argument('--out', type=Path, required=True)
    disk = commands.add_parser('flip-output', help='change one output byte on a stopped owned result disk')
    disk.add_argument('--disk', type=Path, required=True)
    disk.add_argument('--artifact', required=True)
    disk.add_argument('--out', type=Path, required=True)
    disk.add_argument('--stopped', action='store_true', required=True)
    disk.add_argument('--debugfs', default='/usr/sbin/debugfs')
    aggregate = commands.add_parser('assemble', help='combine SC1 through SC7 evidence')
    aggregate.add_argument('--conditions', type=Path, required=True)
    aggregate.add_argument('--out', type=Path, required=True)
    run = commands.add_parser('primary', help='Mac stand-in client: marked model turn and admission probes')
    run.add_argument('--config', type=Path, required=True)
    run.add_argument('--out', type=Path, required=True)
    second = commands.add_parser('second-run', help='replay a captured job into another boot of the same compose')
    second.add_argument('--config', type=Path, required=True)
    second.add_argument('--capture', type=Path, required=True)
    second.add_argument('--out', type=Path, required=True)
    expiry = commands.add_parser('expire', help='wait for the original signed grant expiry, then test refusal')
    expiry.add_argument('--config', type=Path, required=True)
    expiry.add_argument('--capture', type=Path, required=True)
    expiry.add_argument('--out', type=Path, required=True)
    verify = commands.add_parser('verify-tamper', help='client verifies original disk output and refuses changed output')
    verify.add_argument('--config', type=Path, required=True)
    verify.add_argument('--capture', type=Path, required=True)
    verify.add_argument('--original', type=Path, required=True)
    verify.add_argument('--tampered', type=Path, required=True)
    verify.add_argument('--out', type=Path, required=True)
    refusal = commands.add_parser('policy-refusal', help='client refuses a real variant registration before sending')
    refusal.add_argument('--config', type=Path, required=True)
    refusal.add_argument('--node', type=Path, required=True)
    refusal.add_argument('--out', type=Path, required=True)
    egress = commands.add_parser('egress', help='join guest network probes with a verified real model turn')
    egress.add_argument('--proxy', required=True, help='measured HTTP proxy URL')
    egress.add_argument('--probe', type=Path, required=True)
    egress.add_argument('--turn', type=Path, required=True)
    egress.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'scan':
        markers = {k: bytes.fromhex(v) for k, v in json.load(sys.stdin).items()}
        result = scan(args.root, markers, args.control)
        args.out.write_bytes(canonical(result))
    elif args.command == 'flip-output':
        args.out.mkdir()
        original, tampered, result = flip_output(args.disk, args.artifact, args.debugfs)
        (args.out/'original.json').write_bytes(original)
        (args.out/'tampered.json').write_bytes(tampered)
        (args.out/'change.json').write_bytes(canonical(result))
    elif args.command == 'primary':
        result = primary(json.loads(args.config.read_bytes()), args.out)
    elif args.command == 'second-run':
        result = second_run(json.loads(args.config.read_bytes()), args.capture, args.out)
    elif args.command == 'expire':
        client = load_client(json.loads(args.config.read_bytes()))
        node = json.loads((args.capture/'discovery.json').read_bytes())
        grant = json.loads((args.capture/'grant.json').read_bytes())
        result = expired(client, node, grant, wait=True)
        args.out.write_bytes(canonical(result))
    elif args.command == 'verify-tamper':
        result = verify_capture_tamper(json.loads(args.config.read_bytes()), args.capture,
                                       args.original, args.tampered, args.out)
    elif args.command == 'policy-refusal':
        result = policy_refused(load_client(json.loads(args.config.read_bytes())), json.loads(args.node.read_bytes()))
        args.out.write_bytes(canonical(result))
    elif args.command == 'egress':
        result = check_egress(json.loads(args.probe.read_bytes()), json.loads(args.turn.read_bytes()), args.proxy)
        args.out.write_bytes(canonical(result))
    else:
        result = assemble(json.loads(args.conditions.read_bytes()), args.out)
    print(json.dumps(result))
    if result.get('passed') is False:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
