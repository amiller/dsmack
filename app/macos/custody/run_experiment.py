"""Disposable Mac custody experiment. Authority/category secrets stay in RAM.

SSH is only transport and lab process control. App Attest binds the receiver key;
the signed, encrypted parcel is independently authenticated by the app.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from check_evidence import code_directory_hash, policy, root
from verifier.core import Reject, verify_attestation


def b64(data): return base64.b64encode(data).decode()
def point(key): return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
def write_json(path, obj): path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n')


def main():
    run = 'custody-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    local = HERE / run
    local.mkdir()
    home = subprocess.check_output(['ssh', '-o', 'BatchMode=yes', 'mini', 'printf %s "$HOME"'], text=True)
    remote = home + '/' + run
    def ssh(command, **kwargs):
        result = subprocess.run(['ssh', '-o', 'BatchMode=yes', 'mini', command], capture_output=True, **kwargs)
        if result.returncode:
            error = result.stderr if isinstance(result.stderr, str) else result.stderr.decode(errors='replace')
            raise RuntimeError('Mac command failed: ' + command + '\n' + error)
        return result
    def upload(path, target):
        subprocess.run(['scp', '-q', str(path), 'mini:' + target], check=True)
    def fetch(step):
        subprocess.run(['scp', '-q', '-r', 'mini:' + remote + '/captures/' + step, str(local)], check=True)
    def wait_file(path, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(['ssh', '-o', 'BatchMode=yes', 'mini', 'test -f ' + shlex.quote(path)], capture_output=True)
            if result.returncode == 0: return
            time.sleep(1)
        raise RuntimeError('Timed out waiting for ' + path)

    authority = ec.generate_private_key(ec.SECP256R1())
    category = ec.generate_private_key(ec.SECP256R1())
    category_raw = category.private_numbers().private_value.to_bytes(32, 'big')
    network_source = local / 'NetworkKey.swift'
    network_source.write_text('let networkPublicKeyBase64 = "' + b64(point(authority)) + '"\n')
    ssh('mkdir -p ' + shlex.quote(remote))
    upload(HERE / 'Custody.swift', remote + '/main.swift')
    upload(HERE / 'build.sh', remote + '/build.sh')
    upload(network_source, remote + '/NetworkKey.swift')
    # Same lab credential and unlock method explicitly approved by the user.
    # Keep unlock and signing within one session; do not alter keychain ACLs.
    build_program = '''import pathlib,re,subprocess
home=pathlib.Path.home()
match=re.search(r'PW=([A-Za-z0-9]+)',(home/'dsmack-signing/build-probe.sh').read_text())
assert match
unlock=subprocess.run(['security','unlock-keychain','-p',match.group(1),str(home/'Library/Keychains/dsmack.keychain-db')],capture_output=True)
assert unlock.returncode == 0, 'lab keychain unlock failed'
for kind,variant in [('persistent','honest'),('persistent','modified'),('volatile','honest'),('volatile','modified')]:
 subprocess.run(['/bin/bash',BUILD,variant,kind],check=True)
'''.replace('BUILD', repr(remote + '/build.sh'))
    ssh('python3 -c ' + shlex.quote(build_program))
    print('built four custody variants', flush=True)
    plaintext = b'disposable ciphertext: recover only after approved interactive check-in'
    nonce = secrets.token_bytes(12)
    stored = nonce + AESGCM(hashlib.sha256(category_raw).digest()).encrypt(nonce, plaintext, None)
    (local / 'stored-ciphertext.bin').write_bytes(stored)
    upload(local / 'stored-ciphertext.bin', remote + '/stored-ciphertext.bin')
    account = 'custody-test-' + secrets.token_hex(12)
    configs, public_keys, decisions = {}, {}, []

    def start(step, kind, variant, mode):
        cfg = {'session': run + '/' + step, 'nonce': secrets.token_hex(32),
               'account': account, 'mode': mode,
               'ciphertext': remote + '/captures/persist-store/sealed.bin',
               'data_ciphertext': remote + '/stored-ciphertext.bin'}
        configs[step] = cfg
        path = local / (step + '.config.json'); write_json(path, cfg); upload(path, remote + '/' + path.name)
        app = remote + '/active/CodeBindingProbe.app'; capture = remote + '/captures/' + step
        source = remote + '/build/' + kind + '-' + variant + '/CodeBindingProbe.app'
        ssh('mkdir -p ' + shlex.quote(capture) + ' ' + shlex.quote(remote + '/active') +
            ' && ditto ' + shlex.quote(source) + ' ' + shlex.quote(app) +
            ' && codesign --verify --strict ' + shlex.quote(app) +
            ' && cp ' + shlex.quote(app + '/Contents/MacOS/probe') + ' ' + shlex.quote(capture + '/probe') +
            ' && codesign -d --verbose=4 ' + shlex.quote(app) + ' 2> ' + shlex.quote(capture + '/codesign.txt') +
            ' && open -n ' + shlex.quote(app) + ' --args ' + shlex.quote(capture) + ' ' + shlex.quote(remote + '/' + path.name))
        wait_file(capture + '/ready.txt')
        fetch(step)
        print('attestation ready', step, flush=True)
        return local / step

    def verify(step, accepted_digest=None):
        folder = local / step
        client = (folder / 'clientData.bin').read_bytes()
        fields = json.loads(client)
        assert fields['nonce'] == configs[step]['nonce'] and fields['session'] == configs[step]['session']
        own_digest = code_directory_hash((folder / 'probe').read_bytes())
        verified = verify_attestation((folder / 'attestation.cbor').read_bytes(),
            (folder / 'keyId.txt').read_text(), client, policy(own_digest), root())
        # Claims/key are authenticated before comparison against the independently selected policy.
        accepted = own_digest == (accepted_digest or own_digest)
        decisions.append({'step': step, 'apple_chain_acl_and_code_valid': True,
                          'cdhash': own_digest.hex(), 'admission': accepted})
        public_keys[step] = verified['public_key']
        return fields, own_digest, accepted

    p = start('persist-store', 'persistent', 'honest', 'store')
    _, persistent_digest, _ = verify('persist-store')
    wait_file(remote + '/captures/persist-store/done.txt')
    p = start('persist-replaced', 'persistent', 'modified', 'read')
    _, _, admitted = verify('persist-replaced', persistent_digest)
    assert not admitted
    first = json.loads((local / 'persist-store/custody.json').read_text())
    second = json.loads((p / 'custody.json').read_text())
    assert first['public_key'] == second['public_key']
    assert first['plaintext_sha256'] == second['plaintext_sha256']
    persistent_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(first['public_key']))
    for step in ('persist-store', 'persist-replaced'):
        persistent_pub.verify((local / step / 'signature.der').read_bytes(), configs[step]['nonce'].encode(), ec.ECDSA(hashes.SHA256()))
    print('CONFIRMED: modified app recovered Keychain key and decrypted stored ciphertext', flush=True)

    def parcel(fields):
        receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(fields['ephemeral_public_key']))
        sender = ec.generate_private_key(ec.SECP256R1())
        shared = sender.exchange(ec.ECDH(), receiver)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(fields['nonce'].encode()).digest(), info=b'custody-volatile/v1').derive(shared)
        nonce = secrets.token_bytes(12)
        ciphertext = nonce + AESGCM(key).encrypt(nonce, category_raw, fields['session'].encode())
        body = {'sender_public_key': b64(point(sender)), 'ciphertext': b64(ciphertext)}
        signed = ('custody-parcel/v1.' + body['sender_public_key'] + '.' + body['ciphertext'] + '.' + fields['session']).encode()
        body['authorization'] = b64(authority.sign(signed, ec.ECDSA(hashes.SHA256())))
        return body

    def deliver(step, index, body):
        path = local / (step + '-parcel-' + str(index) + '.json'); write_json(path, body)
        target = remote + '/captures/' + step + '/parcel-' + str(index) + '.json'
        upload(path, target + '.pending')
        ssh('mv ' + shlex.quote(target + '.pending') + ' ' + shlex.quote(target))
        wait_file(remote + '/captures/' + step + '/result-' + str(index) + '.json', 30)
        fetch(step)
        return json.loads((local / step / ('result-' + str(index) + '.json')).read_text())

    def check_delivery(step, result):
        assert result['accepted'] is True and result['public_key'] == b64(point(category))
        category.public_key().verify(base64.b64decode(result['signature']), configs[step]['nonce'].encode(), ec.ECDSA(hashes.SHA256()))
        assert result['plaintext_sha256'] == b64(hashlib.sha256(plaintext).digest())

    p = start('volatile-first', 'volatile', 'honest', 'receive')
    fields, volatile_digest, _ = verify('volatile-first')
    original_parcel = parcel(fields)
    check_delivery('volatile-first', deliver('volatile-first', 1, original_parcel))
    pid = int(json.loads((p / 'runtime.json').read_text())['pid'])
    # Kill only the captured isolated probe PID after confirming its executable path.
    command = ssh('ps -p ' + str(pid) + ' -o command=', text=True).stdout
    assert remote + '/active/CodeBindingProbe.app/Contents/MacOS/probe' in command
    ssh('kill -KILL ' + str(pid))
    print('terminated volatile holder after successful decrypt/sign', flush=True)

    p = start('volatile-restart', 'volatile', 'honest', 'receive')
    # No category-key release has been authorized for this new process yet.
    # Stronger negative control: re-authorize the old ciphertext for the new
    # session, without re-encrypting or releasing the category key. This must
    # pass the network signature check and still fail transport decryption.
    replay_parcel = dict(original_parcel)
    signed = ('custody-parcel/v1.' + replay_parcel['sender_public_key'] + '.' + replay_parcel['ciphertext'] + '.' + configs['volatile-restart']['session']).encode()
    replay_parcel['authorization'] = b64(authority.sign(signed, ec.ECDSA(hashes.SHA256())))
    stale = deliver('volatile-restart', 1, replay_parcel)
    assert stale['accepted'] is False and stale['category_key_present'] is False
    assert stale['stage'] == 'transport_decryption'
    restarted, digest, admitted = verify('volatile-restart', volatile_digest)
    assert admitted and restarted['ephemeral_public_key'] != fields['ephemeral_public_key']
    check_delivery('volatile-restart', deliver('volatile-restart', 2, parcel(restarted)))
    print('CONFIRMED: restart rejects old delivery; fresh attested check-in restores decrypt/sign', flush=True)

    p = start('volatile-modified', 'volatile', 'modified', 'receive')
    _, _, admitted = verify('volatile-modified', volatile_digest)
    assert not admitted
    stale_modified = deliver('volatile-modified', 1, original_parcel)
    assert stale_modified['accepted'] is False and stale_modified['category_key_present'] is False
    ssh('touch ' + shlex.quote(remote + '/captures/volatile-modified/stop.txt'))
    wait_file(remote + '/captures/volatile-modified/done.txt', 20)
    fetch('volatile-modified')
    print('CONFIRMED: modified restart denied new delivery; old delivery unusable', flush=True)

    # Search only this experiment's output for accidental raw-secret serialization.
    assert all(category_raw not in f.read_bytes() for f in local.rglob('*') if f.is_file())
    summary = {'run': run, 'persistent_replacement_can_use_key': True,
        'old_ciphertext_reauthorized_for_new_session_still_rejected': True,
        'volatile_restart_stale_delivery_rejected': True, 'fresh_checkin_restores_same_category_key': True,
        'modified_restart_denied_release': True, 'category_public_key': b64(point(category)),
        'authority_public_key': b64(point(authority)), 'raw_category_key_found_in_outputs': False,
        'decisions': decisions, 'persistent_test_keychain_account': account,
        'limitations': ['single Mac and same signing credential', 'no OS/kernel, swap, hibernation or core-dump attack',
                        'Python coordinator is a trusted test authority, not a TEE peer or smart contract',
                        'old delivery fails under fresh session/key; no general forensic erasure claim']}
    write_json(local / 'summary.json', summary)
    write_json(local / 'manifest.json', {str(f.relative_to(local)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(local.rglob('*')) if f.is_file() and f.name != 'manifest.json'})
    print('RESULTS', local, flush=True)


if __name__ == '__main__':
    main()
