"""Mac App Attest identity-only, operator-readable Base coupon worker."""
import base64
import hashlib
import json
import secrets
from pathlib import Path

from .live_worker import LiveWorker
from .mac_issuer_identity import MacIssuerIdentity, MacIssuerEvidenceService, RunnerClient, POLICY
from .mac_transport import MacNearHTTPS, MacGuardRPC
from .peer_worker import _private_file
from .spike import RedemptionError
from .staging_approval import (signed_payload, validate_approval_payload,
                               validate_configuration_payload)

APPROVAL_DOMAIN = 'dsmack-coupon-mac-approval-v1'
CONFIG_DOMAIN = 'dsmack-coupon-mac-config-v1'


class MacLiveWorker(LiveWorker):
    approval_domain = APPROVAL_DOMAIN
    issuer_policy = POLICY
    noise_key_path = 'dsmack/coupon-noise/mac/v1/ed25519'
    guard_key_path = 'dsmack/coupon-guard/mac/v1/secp256k1'

    def _authorization(self, path, root):
        approved = validate_approval_payload(signed_payload(
            _private_file(Path(path).parent / 'approval.json'), APPROVAL_DOMAIN, root), mac=True)
        if approved['guard']['chain_id'] != 8453:
            raise RedemptionError('Mac Base-only runtime required')
        payload = signed_payload(_private_file(path), CONFIG_DOMAIN, root)
        if type(payload.get('app_compose')) is not str or not 0 < len(payload['app_compose'].encode()) <= 131072:
            raise RedemptionError('Mac signed compose required')
        compose = payload['app_compose']
        config = validate_configuration_payload({k: v for k, v in payload.items() if k != 'app_compose'},
                                                approved, approval_domain=APPROVAL_DOMAIN)
        return approved, {**config, 'app_compose': compose}

    def _collector(self, config):
        return MacIssuerIdentity(RunnerClient())

    def _runtime_info(self, collector, config):
        compose = config['app_compose']
        if hashlib.sha256(compose.encode()).hexdigest() != self.approved['compose_hash']:
            raise RedemptionError('Mac signed compose mismatch')
        # Current runner response proves its compose to the remote verifier.
        # Local metadata is checked as a precondition, not treated as independent
        # Apple verification. Optional app remains administrative when absent.
        evidence = collector._client.request('/attest', {'data': 'dsmack-coupon-mac-startup-v1|' + secrets.token_hex(32)})
        enrollment = json.loads(base64.b64decode(evidence['bootClientData'], validate=True))
        if (enrollment.get('compose_hash') != self.approved['compose_hash']
                or enrollment.get('attested') is not True
                or ('app' in enrollment and enrollment['app'] != self.approved['app_id'])):
            raise RedemptionError('Mac application metadata mismatch')
        return compose

    def _key(self, collector, path, algorithm):
        return collector._client.key(path)

    def _rpc(self, config):
        return MacGuardRPC(config['finality_profile']['execution_rpc'])

    def _transport(self):
        return MacNearHTTPS()

    def _evidence_service(self, collector, app_compose):
        return MacIssuerEvidenceService(issuer_peer=self.issuer_peer, signing_key=collector._signer,
            identity_policy_sha256=self.approved['identity_policy_sha256'],
            issuance_policy_sha256=self.approved['issuance_policy_sha256'],
            collector=collector, app_compose=app_compose)
