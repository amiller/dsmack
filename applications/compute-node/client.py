#!/usr/bin/env python3
"""Release one job to a verified compute guest over the broker and libp2p relay."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tarfile
import time
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'dstack-compat'), str(ROOT/'applications/agent-turns'),
                str(ROOT/'applications/pilot-client/workload')]
import guest_attest
import find
import export_subscription
from verifier.core import require, unb64, unique_json, verify_assertion, verify_key
from verifier.macos_policy import APP_ID, policy, root

MODEL = 'claude-opus-4-8'
TOOLS = ['Read', 'Grep', 'Glob', 'Edit', 'Write']
OUTPUTS = {'patch', 'transcript', 'verdict'}
BROKER = 'https://pod.dstack.soc1024.com/relay-broker'
ATTEST = '0xFF8393e6D4c3dF89e826A5BF14829733B953c948'
CANARY = '0xdC66c90291973167126a3c4455D5A6064634f3B1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request(url, value=None, limit=256 << 10):
    req = Request(url, data=canonical(value) if value is not None else None,
                  headers={'Content-Type': 'application/json', 'User-Agent': 'dsmack-agent/1'})
    with urlopen(req, timeout=30) as response:
        raw = response.read(limit + 1)
    require(len(raw) <= limit, 'HTTP response bound')
    return unique_json(raw)


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def box_key(private, remote, epk, recipient, task):
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + remote)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32),
                info=b'dsmack.secret-release/1' + epk + recipient + task.encode()).derive(private.exchange(ec.ECDH(), peer))


def seal(recipient, task, raw):
    key = ec.generate_private_key(ec.SECP256R1()); epk = public(key); iv = os.urandom(12)
    ct = AESGCM(box_key(key, recipient, epk, recipient, task)).encrypt(iv, raw, None)
    return dict(epk=epk.hex(), iv=iv.hex(), ct=ct.hex())


def decrypt(key, task, box):
    require(set(box) == {'epk', 'iv', 'ct'}, 'sealed output fields')
    epk, iv, ct = (bytes.fromhex(box[k]) for k in ('epk', 'iv', 'ct'))
    require(len(epk) == 64 and len(iv) == 12 and len(ct) >= 16, 'sealed output lengths')
    return AESGCM(box_key(key, epk, epk, public(key), task)).decrypt(iv, ct, None)


def peer_bytes(text):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    require(isinstance(text, str) and 32 <= len(text) <= 100, 'PeerId')
    n = 0
    for c in text:
        require(c in alphabet, 'PeerId base58')
        n = n * 58 + alphabet.index(c)
    raw = bytes(len(text) - len(text.lstrip('1'))) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    require((len(raw) == 38 and raw[:6] == bytes.fromhex('002408011220')) or
            (len(raw) == 34 and raw[:2] == bytes.fromhex('1220')), 'PeerId multihash')
    return raw


class Policy:
    def __init__(self, manifest, enrollment, cdhash, rpc='https://sepolia.base.org', attest=ATTEST, canary=CANARY, model=MODEL):
        self.manifest, self.cdhash, self.rpc, self.attest, self.canary, self.model = manifest, cdhash, rpc, attest, canary, model
        self.measurement = sha(manifest)
        self.image = json.loads(manifest)['base_vm']['os_image_hash']
        services = json.loads(json.loads(manifest)['docker_compose_file'])['services']
        require(set(services) == {'node'}, 'compute compose must contain only node')
        self.service = services['node']
        require(self.service['entrypoint'] == ['/usr/local/bin/dsmack-compute'], 'compute entrypoint')
        require(model == MODEL, 'model is not approved')
        require(self.service['environment']['MODEL'] == model, 'compose model is not approved')
        self.rule = policy(bytes.fromhex(cdhash))
        self.kid = (enrollment/'keyId.txt').read_text().strip()
        self.key = verify_key((enrollment/'attestation.cbor').read_bytes(), self.kid,
                              (enrollment/'clientData.bin').read_bytes(), self.rule, root(), time.time())['public_key']
        self.live_checked = False

    def call(self, address, data):
        reply = request(self.rpc, {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
                                  'params': [{'to': address, 'data': data}, 'latest']})
        require('error' not in reply and isinstance(reply.get('result'), str), 'chain eth_call failed')
        return bytes.fromhex(reply['result'][2:])

    def check_live(self):
        registry = '0x' + self.call(self.attest, '0xb4eb10ce')[-20:].hex()
        rp = self.call(registry, '0x65f4df9c' + self.cdhash)
        require(rp == hashlib.sha256(APP_ID.encode()).digest(), 'build is not approved in CDRegistry')
        require(int.from_bytes(self.call(self.attest, '0x5523509a'), 'big') == 3, 'chain validation category')
        build = self.call(registry, '0xb7b014b6')
        require(self.call(self.canary, '0xe62b7cbd' + self.image) == bytes(32), 'image canary burned')
        require(self.call(self.canary, '0xda746951' + build.hex()) == bytes(32), 'build canary burned')
        self.live_checked = True

    def verify(self, blob, report_data, counter=0):
        a = guest_attest.verify(bytes.fromhex(blob))
        require(a['key_id'] == unb64(self.kid), 'node key is not the Apple enrolled key')
        signed = verify_assertion(a['assertion'], guest_attest.client_data(a['os_image_hash'], a['manifest_sha256'],
                                  a['run'], a['head'], a['caller'], a['report_data']), self.key, counter, self.rule)
        require(a['manifest_sha256'].hex() == self.measurement, 'node compose is not approved')
        require(a['os_image_hash'].hex() == self.image, 'node image is not approved')
        require(a['caller'] == hashlib.sha256(b'node').digest(), 'Attest caller is not node')
        require(a['report_data'] == report_data, 'Attest report_data mismatch')
        a['counter'] = signed['counter']
        return a, signed

    def verify_registration(self, node):
        require(node['kind'] == 'compute' and node['cdhash'] == self.cdhash, 'node build is not approved')
        require(node['manifest_sha256'] == self.measurement and node['os_image_hash'] == self.image,
                'node measurements are not approved')
        peer = peer_bytes(node['relay_peer'])
        require(node['relay_maddr'].endswith('/p2p-circuit/p2p/' + node['relay_peer']), 'node circuit target')
        secret, receipt = bytes.fromhex(node['secret_key']), bytes.fromhex(node['receipt_key'])
        require(len(secret) == 64 and len(receipt) == 32, 'node key lengths')
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + secret)
        rd = hashlib.sha256(b'dsmack-compute-node/1' + peer + secret + receipt).digest() + bytes(32)
        proof = node['proof'] if 'proof' in node else node['attestation']
        return self.verify(proof, rd)


def send(stream, value):
    raw = canonical(value)
    require(0 < len(raw) <= 48 << 20, 'frame bound')
    stream.write(struct.pack('>I', len(raw)) + raw); stream.flush()


def exact(stream, count):
    raw = bytearray()
    while len(raw) < count:
        chunk = stream.read(count - len(raw))
        require(chunk, 'relay stream closed')
        raw.extend(chunk)
    return bytes(raw)


def recv(stream, max_bytes=48 << 20):
    size = struct.unpack('>I', exact(stream, 4))[0]
    require(0 < size <= max_bytes, 'frame bound')
    return unique_json(exact(stream, size))


class Refused(ValueError):
    pass


class Exchange:
    def __init__(self, binary, node, key):
        self.process = subprocess.Popen([str(binary), 'exchange', node['relay_maddr'], str(key)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.bundles_sent = 0

    def send(self, value):
        send(self.process.stdin, value)
        if set(value) == {'epk', 'iv', 'ct'}:
            self.bundles_sent += 1

    def recv(self, max_bytes=48 << 20):
        return recv(self.process.stdout, max_bytes)

    def admit(self, job_id, grant):
        self.send(dict(job_id=job_id, grant=grant))
        response = self.recv(4096)
        if response != {'status': 'ready'}:
            raise Refused('node admission refused: ' + str(response.get('error', 'protocol')))
        return response

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate(); self.process.wait(timeout=5)
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Client:
    def __init__(self, binary, key, broker, broker_key, policy):
        self.binary, self.key, self.broker, self.broker_key, self.policy = binary.resolve(), key, broker.rstrip('/'), broker_key, policy
        require(len(bytes.fromhex(broker_key)) == 32, 'broker key length')
        command = policy.service['command']
        require(len(command) == 7 and command[0] == 'serve' and command[4] == broker_key and command[5] == policy.cdhash,
                'compose does not measure broker key and build')
        if not key.exists():
            subprocess.run([str(self.binary), 'keygen', str(key)], check=True, capture_output=True)
        self.peer = subprocess.check_output([str(self.binary), 'id', str(key)], text=True).strip()
        self.bundles_sent = 0

    def discover(self, peer=None):
        self.policy.check_live()
        nodes = request(self.broker + '/nodes')
        candidates = [n for n in nodes if n['kind'] == 'compute' and (peer is None or n['relay_peer'] == peer)]
        require(candidates, 'no registered compute node')
        # Pin the expected compose before dialing an address from discovery.
        node = next((n for n in candidates if n['manifest_sha256'] == self.policy.measurement), candidates[0])
        self.policy.verify_registration(node)
        raw = subprocess.check_output([str(self.binary), 'discover', node['relay_maddr'], str(self.key)], timeout=45)
        require(len(raw) <= 150000, 'node discovery bound')
        direct = unique_json(raw)
        for name in ('kind', 'relay_peer', 'relay_maddr', 'secret_key', 'receipt_key', 'manifest_sha256', 'os_image_hash', 'cdhash'):
            require(direct[name] == node[name], 'node discovery changed ' + name)
        self.policy.verify_registration(direct)
        return direct

    def grant(self, node, seconds):
        fields = dict(client_peer=self.peer, relay_peer=node['relay_peer'], unit='seconds', amount=seconds, nonce=secrets.token_hex(16))
        signed = unique_json(subprocess.check_output([str(self.binary), 'sign', str(self.key)], input=canonical(fields)))
        grant = request(self.broker + '/grant', signed)
        self.check_grant(node, grant)
        return grant

    def check_grant(self, node, grant):
        body = {k: v for k, v in grant.items() if k != 'sig'}
        require(set(body) == {'client_peer', 'expires_at', 'grant_id', 'relay_peer', 'seconds', 'unit', 'v'}, 'grant fields')
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.broker_key)).verify(bytes.fromhex(grant['sig']), canonical(body))
        require(body['client_peer'] == self.peer and body['relay_peer'] == node['relay_peer'], 'grant peer mismatch')
        require(body['unit'] == 'seconds' and body['v'] == 1 and type(body['seconds']) is int and 0 < body['seconds'] <= 1800,
                'grant seconds')
        require(type(body['expires_at']) is int and body['expires_at'] > time.time(), 'grant expired')
        require(len(bytes.fromhex(body['grant_id'])) == 16, 'grant ID')
        return body

    def connect(self, node):
        return Exchange(self.binary, node, self.key)

    def prepare(self, node, job_id, grant, credential, repo, prompt):
        output_key = ec.generate_private_key(ec.SECP256R1())
        raw = dict(job_id=job_id, grant_id=grant['grant_id'], credential=credential,
                   repo_tar=base64.b64encode(snapshot(repo)).decode(), prompt=prompt, output_pub=public(output_key).hex())
        return seal(bytes.fromhex(node['secret_key']), job_id, canonical(raw)), output_key

    def verify_result(self, node, discovery, result, job_id, grant, sealed, output_key):
        require(result.get('status') == 'complete', 'node job did not complete')
        statement = result['statement']
        require(set(statement) == {'job_id', 'bundle_sha256', 'outputs', 'grant_id', 'seconds_used'}, 'job statement fields')
        require(statement['job_id'] == job_id and statement['grant_id'] == grant['grant_id'], 'result IDs')
        require(statement['bundle_sha256'] == sha(canonical(sealed)), 'input bundle digest')
        require(type(statement['seconds_used']) is int and 0 < statement['seconds_used'] <= grant['seconds'], 'result seconds')
        a, signed = self.policy.verify(result['attestation'], hashlib.sha256(canonical(statement)).digest() + bytes(32), discovery['counter'])
        require(a['run'] == discovery['run'] and a['head'] == discovery['head'], 'result is from another node run')
        receipt = result['receipt']; body = {k: v for k, v in receipt.items() if k != 'sig'}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(node['receipt_key'])).verify(bytes.fromhex(receipt['sig']), canonical(body))
        require(body == dict(client_peer=self.peer, node_peer=node['relay_peer'], run=a['run'].hex(),
                             report_sha256=sha(canonical(statement)), grant_id=grant['grant_id'], job_id=job_id,
                             seconds_used=statement['seconds_used']), 'receipt does not bind job')
        require(set(result['outputs']) == OUTPUTS and set(statement['outputs']) == OUTPUTS, 'output set')
        plain = {name: decrypt(output_key, job_id + '/' + name, box) for name, box in result['outputs'].items()}
        for name, raw in plain.items():
            require(sha(raw) == statement['outputs'][name], 'plaintext output digest')
        summary, models, turns = find.observe(plain['transcript'], {'model': self.policy.model, 'tools': TOOLS})
        verdict = unique_json(plain['verdict'])
        require(verdict == dict(answer=None, summary=summary[:1000], num_turns=turns, observed_models=models), 'turn verdict mismatch')
        turn = dict(job_id=job_id, grant_id=grant['grant_id'], run=a['run'].hex(), manifest_sha256=self.policy.measurement,
                    os_image_hash=self.policy.image, outputs=statement['outputs'], observed_models=models, num_turns=turns,
                    seconds_used=statement['seconds_used'], counter=signed['counter'])
        return plain, turn

    def run(self, repo, prompt, credential, out, seconds=240, node_peer=None):
        out.mkdir(parents=True, mode=0o700)
        require(not (out/'turn.json').exists(), 'output already contains a turn')
        node = self.discover(node_peer)
        discovery, _ = self.policy.verify_registration(node)
        grant = self.grant(node, seconds); job_id = secrets.token_hex(16)
        for name, value in [('discovery', node), ('grant', grant)]:
            (out/(name + '.json')).write_bytes(canonical(value))
        with self.connect(node) as stream:
            self.check_grant(node, grant)
            stream.admit(job_id, grant)
            # Read the credential only after local policy and remote admission pass.
            document = read_credential(credential)
            sealed, output_key = self.prepare(node, job_id, grant, document, repo, prompt)
            del document
            (out/'sealed-input.json').write_bytes(canonical(sealed))
            stream.send(sealed); self.bundles_sent += 1
            result = stream.recv()
        (out/'result.json').write_bytes(canonical(result))
        plain, turn = self.verify_result(node, discovery, result, job_id, grant, sealed, output_key)
        for name, raw in plain.items():
            (out/name).write_bytes(raw)
        patch = (out/'patch').resolve()
        subprocess.run(['git', '-C', str(repo), 'apply', '--check', str(patch)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(repo), 'apply', str(patch)], check=True, capture_output=True)
        turn['patch_applied'] = True
        (out/'turn.json').write_bytes(canonical(turn))
        return turn


def read_credential(path):
    validator = export_subscription.validator()
    store = unique_json(path.read_bytes())['claudeAiOauth']
    document = {'claudeAiOauth': {k: store[k] for k in validator.ACCEPTED_OAUTH_FIELDS if k in store}}
    validator.parse_subscription_document(canonical(document))
    return document


def snapshot(repo):
    paths = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z', '-co', '--exclude-standard', '--deduplicate']).decode().split('\0')
    raw = io.BytesIO(); size = 0
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(filter(None, paths)):
            path = repo/name
            require(not path.is_symlink(), 'snapshot symlink')
            if not path.exists():
                continue
            require(path.is_file(), 'snapshot requires regular files')
            size += path.stat().st_size
            require(size <= 16 << 20, 'snapshot bound')
            tar.add(path, arcname=name, recursive=False)
    require(len(raw.getvalue()) <= 16 << 20, 'repo archive bound')
    return raw.getvalue()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'out', 'manifest', 'enrollment', 'binary', 'client-key'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--prompt', required=True)
    p.add_argument('--credential', type=Path, default=Path.home()/'.dsmack/private-inputs/claude-subscription.json')
    p.add_argument('--broker', default=BROKER)
    p.add_argument('--broker-key', required=True)
    p.add_argument('--cdhash', required=True)
    p.add_argument('--rpc', default='https://sepolia.base.org')
    p.add_argument('--attest', default=ATTEST)
    p.add_argument('--canary', default=CANARY)
    p.add_argument('--model', default=MODEL)
    p.add_argument('--seconds', type=int, default=240)
    p.add_argument('--node-peer')
    args = p.parse_args(argv)
    os.umask(0o077)
    selected = Policy(args.manifest.read_bytes(), args.enrollment, args.cdhash, args.rpc, args.attest, args.canary, args.model)
    client = Client(args.binary, args.client_key, args.broker, args.broker_key, selected)
    result = client.run(args.repo.resolve(), args.prompt, args.credential, args.out.resolve(), args.seconds, args.node_peer)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
