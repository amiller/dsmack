"""EXPLICIT SYNTHETIC LIVE-WORKER FIXTURE. Never packaged or approved as live.

A wrapper process installs deterministic test doubles for the SDK collector,
the provider adapter and the finalized-issuance guard so the real LiveWorker
startup boundary, signed admission and async /4 behavior can be exercised
without hardware, provider credentials or chain access. The approval root used
here is a published test key: it is not the measured image root, not a staging
authority and cannot admit live credentials.

The fixture guard is steered by a gate file next to the finality profile:
absent or "grant" permits the provider effect, "hold" blocks as if waiting for
finalized consumption, "fail" refuses, "crash" exits after the durable intent.
"""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_keys import keys as eth_keys

from .dstack_issuer_identity import DstackIssuerIdentity
from .near import Near
from .offer_v2 import canonical as offer_canonical
from .spike import IssuedKey, RedemptionError
from .staging_approval import (APPROVAL_DOMAIN, CONFIG_DOMAIN, POWERS, canonical,
                               payload_hash)

SIGNING_SEED = bytes.fromhex('99' * 32)
ISSUER_SEED = bytes.fromhex('41' * 32)
NOISE_SEED = bytes.fromhex('42' * 32)
GUARD_SEED = bytes.fromhex('43' * 32)
APP_ID = '05' * 20
COMPOSE_HASH = '01' * 32
COMPOSE = '{"name":"SYNTHETIC LIVE WORKER TEST ONLY","services":{}}'
GUEST_VERSION = '0.5.9'
PROVIDER = {'workspace_id': '11111111-1111-4111-8111-111111111111',
            'organization_id': '22222222-2222-4222-8222-222222222222',
            'session_jwt': 'SYNTHETIC-NOT-CREDENTIAL', 'reporting_token': 'SYNTHETIC-NOT-CREDENTIAL'}
GATE_NAME = 'async-issuance-gate'


def signing_key():
    return Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)


def signing_public():
    return signing_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def issuer_address():
    return '0x' + eth_keys.PrivateKey(GUARD_SEED).public_key.to_canonical_address().hex()


class FakeClient:
    def __init__(self, *, app_id=APP_ID, compose_hash=COMPOSE_HASH, issuer_seed=ISSUER_SEED):
        self.app_id, self.compose_hash, self.issuer_seed = app_id, compose_hash, issuer_seed
        self.keys = {}

    def info(self):
        return SimpleNamespace(app_id=self.app_id, compose_hash=self.compose_hash,
            tcb_info=SimpleNamespace(compose_hash=self.compose_hash, app_compose=COMPOSE))

    def version(self):
        return SimpleNamespace(version=GUEST_VERSION)

    def get_key(self, path, **_kwargs):
        if path not in ('dsmack/coupon-noise/v1/ed25519', 'dsmack/coupon-guard/v1/secp256k1',
                        'dsmack/coupon-issuer/v2/ed25519'):
            raise ValueError('unexpected fixture key path')
        seed = {'dsmack/coupon-noise/v1/ed25519': NOISE_SEED,
                'dsmack/coupon-guard/v1/secp256k1': GUARD_SEED,
                'dsmack/coupon-issuer/v2/ed25519': self.issuer_seed}[path]
        return SimpleNamespace(decode_key=lambda: seed)

    def get_quote(self, _data):
        # Issuer evidence collection is deliberately unavailable in this fixture;
        # the /issuer/2 route answers with the generic refusal.
        raise ValueError('synthetic fixture provides no quote')


class FakeDstackIdentity(DstackIssuerIdentity):
    def __init__(self, client=None, signing_key=None):
        if signing_key is None:
            signing_key = Ed25519PrivateKey.from_private_bytes(
                (client or FakeClient()).issuer_seed)
        super().__init__(client or FakeClient(), signing_key)

    @classmethod
    def from_socket(cls, socket_path='/var/run/dstack.sock', signing_key=None):
        if socket_path != '/var/run/dstack.sock':
            raise RedemptionError('dstack issuer Unix socket unavailable')
        return cls(signing_key=signing_key)


class FakeNear(Near):
    """Records construction; never contacts a provider or logs credentials."""
    constructed = []

    def __init__(self, workspace_id, organization_id, session_jwt, reporting_token, transport):
        super().__init__(workspace_id, organization_id, session_jwt, reporting_token, transport)
        type(self).constructed.append({'workspace_id': workspace_id,
            'organization_id': organization_id,
            'credential_markers': (session_jwt, reporting_token)})

    def create_key(self, name, budget):
        return IssuedKey('synthetic-live-' + name.split('-')[-1], 'synthetic-live-secret')

    def usage_rows(self, key_id, start, end):
        return [{'source': 'inference', 'id': 'synthetic-live-row', 'api_key_id': key_id,
                 'total_cost_nano_usd': 5_000_000_000}]


def await_gate(gate):
    """Shared gate-file protocol for the synthetic live and async fixtures.

    An absent file or "grant" permits the effect, "hold" blocks as if waiting
    for finalized consumption, "fail" refuses, and "crash" exits after the
    durable intent was committed. Only test fixtures read this file.
    """
    while True:
        mode = gate.read_text() if gate.exists() else 'grant'
        if mode == 'grant':
            return
        if mode == 'fail':
            raise RedemptionError('synthetic fixture authorization refused')
        if mode == 'crash':
            os._exit(77)  # Durable intent committed; no delivery acknowledgement.
        time.sleep(0.05)  # 'hold': bound by the job deadline signal.


class FixtureGuard:
    """Gate-file double for the finalized-issuance guard. No chain, no checker."""
    def __init__(self, *, profile, profile_path, binary, private_key, gas_price_wei,
                 deadline_seconds=3600, poll_seconds=15, rpc=None):
        if not str(binary).endswith('/bin/dsmack-ethereum-finality'):
            raise RedemptionError('fixture guard binary pin')
        self.profile, self.profile_path = dict(profile), profile_path
        self.gate = Path(profile_path).parent / GATE_NAME

    def __call__(self, digest, peer, delivery_key, accepted_hash, issuer):
        if issuer['issuance_policy_sha256'] != self.profile['issuance_policy_hash'].removeprefix('0x'):
            raise RedemptionError('guard policy mismatch')
        await_gate(self.gate)


def install():
    """Install the test doubles into this process's live worker module.

    Returns a restore callable: in-process tests must restore before teardown
    so the doubles never leak into unrelated test modules.
    """
    import experiments.coupon_redemption.live_worker as live_worker
    saved = (live_worker.approval_root, live_worker.DstackIssuerIdentity,
             live_worker.Near, live_worker.FinalizedIssuanceGuard)
    FakeNear.constructed = []  # Fresh per install; holds synthetic markers only.
    live_worker.approval_root = lambda: signing_public()
    live_worker.DstackIssuerIdentity = FakeDstackIdentity
    live_worker.Near = FakeNear
    live_worker.FinalizedIssuanceGuard = FixtureGuard

    def restore():
        (live_worker.approval_root, live_worker.DstackIssuerIdentity,
         live_worker.Near, live_worker.FinalizedIssuanceGuard) = saved
    return restore


def approval_payload(**overrides):
    issuer = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = {'version': 1, 'profile': 'debug-staging', 'app_id': APP_ID,
        'compose_hash': COMPOSE_HASH,
        'identity_policy_sha256': '02' * 32, 'issuance_policy_sha256': '03' * 32,
        'issuer_public_key_sha256': hashlib.sha256(issuer).hexdigest(),
        'provider_scope_commitment': scope_commitment(),
        'guard': {'chain_id': 11155111, 'address': '0x' + '11' * 20,
            'code_hash': '0x' + '22' * 32, 'issuer_address': issuer_address()},
        'powers': POWERS, 'prompt_policy': 'synthetic-only',
        'max_coupon_nano_usd': '5000000000', 'max_total_nano_usd': '5000000000',
        'expires_at': '2099-01-01T00:00:00Z', 'generation': 1}
    for name, value in overrides.items():
        payload[name] = value
    return payload


def scope_commitment(salt='66' * 32):
    binding = {'mode': 'near', **{k: PROVIDER[k] for k in ('workspace_id', 'organization_id')}}
    return hashlib.sha256(b'dsmack-coupon-scope-v2\0' + bytes.fromhex(salt)
                          + offer_canonical(binding)).hexdigest()


def config_payload(directory, issuer_peer_id='IssuerPeer00000001', **overrides):
    payload = {'version': 1,
        'approval_sha256': None,  # filled by envelopes()
        'issuer_peer_id': issuer_peer_id, 'state_dir': str(Path(directory) / 'state'),
        'sponsor_subject': 'operator:sponsor', 'observer_subject': 'operator:observer',
        'peers': {'SponsorPeer0000001': {'subject': 'operator:sponsor', 'roles': ['sponsor']},
                  'ObserverPeer0001': {'subject': 'operator:observer', 'roles': ['observer']}},
        'provider': dict(PROVIDER), 'scope_salt_hex': '66' * 32,
        'finality_profile': {'version': 1,
            'trust_profile': 'helios-ethereum-sepolia-finalized-experiment',
            'chain_id': 11155111, 'genesis_validators_root': '0x' + '77' * 32,
            'bootstrap_checkpoint': '0x' + '88' * 32,
            'consensus_rpc': 'https://example.invalid', 'execution_rpc': 'https://example.invalid',
            'guard_address': '0x' + '11' * 20, 'guard_code_hash': '0x' + '22' * 32,
            'issuer_address': issuer_address(), 'issuance_policy_hash': '0x' + '03' * 32,
            'max_finalized_age_seconds': 1200, 'timeout_seconds': 30},
        'gas_price_wei': 1000, 'job_deadline_seconds': 120, 'max_active_jobs': 1}
    for name, value in overrides.items():
        payload[name] = value
    return payload


def sign(payload, domain):
    message = domain.encode('ascii') + b'\0' + canonical(payload)
    return canonical({'domain': domain, 'payload': payload,
                      'signature_hex': signing_key().sign(message).hex()})


def envelopes(directory, issuer_peer_id='IssuerPeer00000001', *, approval_overrides=None,
              config_overrides=None):
    """Build and sign a matched approval/config pair (signing only)."""
    approved = approval_payload(**(approval_overrides or {}))
    config = config_payload(directory, issuer_peer_id, **(config_overrides or {}))
    config['approval_sha256'] = payload_hash(APPROVAL_DOMAIN, approved)
    return sign(approved, APPROVAL_DOMAIN), sign(config, CONFIG_DOMAIN), approved


def write_envelopes(directory, issuer_peer_id='IssuerPeer00000001', *, approval_overrides=None,
                    config_overrides=None, expect_valid=True):
    """Write a signed pair; expect_valid pairs must parse under the real
    validators first. Refusal-path tests pass expect_valid=False."""
    approval_envelope, config_envelope, approved = envelopes(directory, issuer_peer_id,
        approval_overrides=approval_overrides, config_overrides=config_overrides)
    if expect_valid:
        from .staging_approval import approval, configuration
        assert approval(approval_envelope, signing_public()) == json.loads(approval_envelope)['payload']
        assert configuration(config_envelope, signing_public(), approved) == json.loads(config_envelope)['payload']
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    (directory / 'approval.json').write_bytes(approval_envelope)
    (directory / 'approval.json').chmod(0o600)
    (Path(directory) / 'config.json').write_bytes(config_envelope)
    (Path(directory) / 'config.json').chmod(0o600)
    return {'approval_sha256': payload_hash(APPROVAL_DOMAIN, approved),
            'approval': str(directory / 'approval.json'),
            'config': str(directory / 'config.json')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('envelopes', 'worker'))
    parser.add_argument('--dir', help='operator directory for envelope output')
    parser.add_argument('--issuer-peer-id', default='IssuerPeer00000001')
    parser.add_argument('--config', help='worker configuration path (worker mode)')
    args = parser.parse_args(argv)
    if args.operation == 'envelopes':
        if not args.dir:
            raise SystemExit('explicit operator directory required')
        print(json.dumps(write_envelopes(args.dir, args.issuer_peer_id)))
        return 0
    if args.config is None:
        raise SystemExit('explicit worker configuration required')
    install()
    from .peer_worker import main as worker_main
    return worker_main(['--config', args.config])


if __name__ == '__main__':
    raise SystemExit(main())
