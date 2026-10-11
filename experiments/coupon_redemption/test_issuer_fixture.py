"""EXPLICIT SYNTHETIC TEST FACTORY. Never packaged or approved as live policy.

The quote bytes are JSON, not an Intel quote. The normal DCAP verifier rejects
these bytes. Only a named synthetic verifier adapter may interpret them.
"""
import hashlib
import json
from types import SimpleNamespace

from .dstack_issuer_identity import DstackIssuerIdentity
from .offer_v2 import canonical
from .peer_worker import Worker as RealWorker, SyntheticProvider, _private_file
from .spike import RedemptionError

COMPOSE = '{"name":"SYNTHETIC ONLY COUPON CLIENT FIXTURE","services":{}}'
IDENTITY_POLICY = {'version': 2, 'challenge_ttl_ms': 30000, 'approved_measurements': [{
    'compose_sha256': hashlib.sha256(COMPOSE.encode()).hexdigest(),
    'mr_td': '01' * 48, 'rtmr0': '02' * 48, 'rtmr1': '03' * 48, 'rtmr2': '04' * 48,
    'runtime_events': {'app-id': '05' * 20, 'key-provider': '06' * 32, 'os-image-hash': '07' * 32}}]}
IDENTITY_POLICY_HASH = hashlib.sha256(b'dsmack-coupon-issuer-policy-v2\0' + canonical(IDENTITY_POLICY)).hexdigest()
ISSUANCE_POLICY_HASH = 'ab' * 32  # Synthetic label, never live approval.


class SyntheticGuest:
    def get_quote(self, data):
        measurement = IDENTITY_POLICY['approved_measurements'][0]
        def event(name, payload):
            preimage = bytes.fromhex('01000008') + (':' + name + ':').encode() + bytes.fromhex(payload)
            return {'imr': 3, 'event_type': 0x08000001, 'event': name, 'event_payload': payload,
                    'digest': hashlib.sha384(preimage).hexdigest()}
        events = [event('compose-hash', measurement['compose_sha256'])]
        events += [event(name, payload) for name, payload in measurement['runtime_events'].items()]
        events += [event('system-ready', '')]
        mr = bytes(48)
        for entry in events:
            mr = hashlib.sha384(mr + bytes.fromhex(entry['digest'])).digest()
        quote = {'quoteVersion': 4, 'reportType': 'td10', 'status': 'UpToDate', 'reportData': data.hex(),
            'tdAttributes': '0000001000000000', 'mrTd': measurement['mr_td'], 'rtMr0': measurement['rtmr0'],
            'rtMr1': measurement['rtmr1'], 'rtMr2': measurement['rtmr2'], 'rtMr3': mr.hex()}
        return SimpleNamespace(quote=canonical(quote).hex(), event_log=json.dumps(events, separators=(',', ':')))


def synthetic_worker(config_path):
    config = json.loads(_private_file(config_path))
    profile = config.get('issuer_evidence')
    if (config['provider'] != {'mode': 'synthetic'} or profile is None
            or profile['identity_policy_sha256'] != IDENTITY_POLICY_HASH
            or profile['issuance_policy_sha256'] != ISSUANCE_POLICY_HASH
            or _private_file(profile['compose_file']).decode() != COMPOSE):
        raise RedemptionError('synthetic fixture profile required')
    worker = None
    def authorize(digest, peer, public, accepted_hash, binding):
        if (worker is None or not isinstance(worker.service_v4.provider, SyntheticProvider)
                or binding['issuance_policy_sha256'] != ISSUANCE_POLICY_HASH):
            raise RedemptionError('synthetic fixture cannot authorize near credentials')
    worker = RealWorker(config_path,
        issuer_collector_factory=lambda socket_path, signing_key: DstackIssuerIdentity(SyntheticGuest(), signing_key),
        issuance_authorizer=authorize)
    return worker


if __name__ == '__main__':
    print(json.dumps({'environment': 'synthetic-only-not-hardware', 'identity_policy': IDENTITY_POLICY,
        'identity_policy_sha256': IDENTITY_POLICY_HASH, 'issuance_policy_sha256': ISSUANCE_POLICY_HASH,
        'app_compose': COMPOSE}, sort_keys=True))
