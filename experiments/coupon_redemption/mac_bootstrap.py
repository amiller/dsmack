"""Protected guest-to-launcher metadata; no public log may receive this pipe."""
import base64
import hashlib
import json
import secrets
import sys

from eth_keys import keys
from .mac_issuer_identity import MacIssuerIdentity, RunnerClient
from .mac_live_worker import MacLiveWorker
from .staging_approval import canonical


CONTROL_DOMAIN = 'dsmack-coupon-mac-control-v1'


def bootstrap(challenge=None):
    client = RunnerClient()
    collector = MacIssuerIdentity(client)
    evidence = client.request('/attest', {'data': 'dsmack-coupon-mac-bootstrap-v1|' + secrets.token_hex(32)})
    enrollment = json.loads(base64.b64decode(evidence['bootClientData'], validate=True))
    if (enrollment.get('attested') is not True
            or enrollment.get('domain') not in ('mac-compose-boot/1', 'mac-compose-enroll/1')):
        raise ValueError('attested Mac runner required')
    public = collector.public_key_hex()
    result = {'noise_seed_hex': client.key(MacLiveWorker.noise_key_path).hex(),
            'issuer_public_key_hex': public,
            'issuer_public_key_sha256': hashlib.sha256(bytes.fromhex(public)).hexdigest(),
            'guard_issuer_address': '0x' + keys.PrivateKey(client.key(MacLiveWorker.guard_key_path)).public_key.to_canonical_address().hex(),
            'runtime_app': enrollment.get('app'), 'runtime_app_attested': 'app' in enrollment,
            'compose_hash': enrollment['compose_hash'], 'runner_evidence': evidence,
            'custody': 'operator-kms-readable', 'private_issuance_qualified': False,
            'rollback_qualified': False}
    if challenge is not None:
        import re
        if type(challenge) is not str or not re.fullmatch('[0-9a-f]{64}', challenge):
            raise ValueError('invalid control nonce')
        binding = {'version': 1, 'challenge_hex': challenge,
                   'public_key_hex': public, 'compose_hash': enrollment['compose_hash']}
        data = CONTROL_DOMAIN + '|' + hashlib.sha256(canonical(binding)).hexdigest()
        result['control_binding'] = binding
        result['control_evidence'] = client.request('/attest', {'data': data})
        result['control_possession_signature_hex'] = collector._signer.sign(
            CONTROL_DOMAIN.encode() + b'\0' + data.encode()).hex()
    return result


if __name__ == '__main__':
    try:
        if len(sys.argv) not in (1, 3) or (len(sys.argv) == 3 and sys.argv[1] != '--control-challenge'):
            raise ValueError('unsupported bootstrap invocation')
        print(json.dumps(bootstrap(sys.argv[2] if len(sys.argv) == 3 else None)), flush=True)
    except Exception:
        raise SystemExit('Mac issuer bootstrap unavailable') from None
