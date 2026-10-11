"""Synthetic binding/egress refusals; never labelled hardware verification."""
import base64
import copy
import hashlib
import json
import ssl
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .mac_issuer_identity import (MacIssuerIdentity, MacIssuerEvidenceService, assertion_data,
                                  POSSESSION_DOMAIN, KEY_PATH)
from .mac_transport import RunnerHTTPS, MacGuardRPC
from .spike import RedemptionError
from .staging_approval import canonical

class FakeRunner:
    compose = '{"synthetic":true}'
    calls = []
    def key(self, path):
        if path != KEY_PATH: raise ValueError()
        return bytes.fromhex('12'*32)
    def request(self, endpoint, body):
        self.calls.append((endpoint,body))
        return {'type':'macrunner','bootClientData':base64.b64encode(canonical({
            'attested':True,'compose_hash':hashlib.sha256(self.compose.encode()).hexdigest()})).decode()}

class MacIssuerTests(unittest.TestCase):
    def setUp(self):
        self.runner=FakeRunner();self.runner.calls=[];self.identity=MacIssuerIdentity(self.runner)
        self.binding={'version':1,'peer_id':'IssuerPeer00000001','recipient_peer_id':'RecipientPeer00001',
            'public_key_hex':self.identity.public_key_hex(),'challenge_hex':'11'*32,
            'identity_policy_sha256':'22'*32,'issuance_policy_sha256':'33'*32}
        self.service=MacIssuerEvidenceService(issuer_peer=self.binding['peer_id'],signing_key=self.identity._signer,
            identity_policy_sha256='22'*32,issuance_policy_sha256='33'*32,
            collector=self.identity,app_compose=self.runner.compose)
    def dispatch(self,binding,local=None,remote=None):
        return json.loads(self.service.dispatch(canonical({'id':'check','op':'evidence','binding':binding}),
            local_peer=local or self.binding['peer_id'],remote_peer=remote or self.binding['recipient_peer_id']))
    def test_possession_commits_all_actual_context(self):
        result=self.dispatch(self.binding);self.assertTrue(result['ok'])
        evidence=result['result'];data=assertion_data(self.binding)
        self.assertEqual(self.runner.calls,[('/attest',{'data':data})])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.binding['public_key_hex'])).verify(
            bytes.fromhex(evidence['possession_signature_hex']),POSSESSION_DOMAIN+data.encode())
    def test_changed_peer_signer_or_policy_refused_before_assertion(self):
        for field,value in [('peer_id','DifferentPeer00001'),('recipient_peer_id','DifferentPeer00001'),
                            ('public_key_hex','44'*32),('identity_policy_sha256','44'*32),
                            ('issuance_policy_sha256','44'*32),('extra',True),('version',True)]:
            binding=copy.deepcopy(self.binding);binding[field]=value
            with self.subTest(field=field):self.assertFalse(self.dispatch(binding)['ok'])
        self.assertEqual(self.runner.calls,[])
    def test_compose_mismatch_refused(self):
        with self.assertRaises(RedemptionError):self.identity.collect(self.binding,'{}')
    def test_origin_and_tls_not_operator_selectable(self):
        for host,port in [('evil.invalid',443),('cloud-api.near.ai',80),('mainnet.base.org:80',None)]:
            with self.assertRaises(ValueError):RunnerHTTPS(host,port)
        for host in ('cloud-api.near.ai','mainnet.base.org'):
            c=RunnerHTTPS(host,443);self.assertTrue(c._context.check_hostname)
            self.assertEqual(c._context.verify_mode,ssl.CERT_REQUIRED)
        with self.assertRaises(ValueError):MacGuardRPC('https://example.invalid')
    def test_refused_connect_never_starts_tls_or_direct_dns(self):
        class Sock:
            data=iter(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            closed=False
            def settimeout(self,*args):pass
            def connect(self,path):self.path=path
            def sendall(self,request):self.request=request
            def recv(self,n):return bytes([next(self.data)])
            def close(self):self.closed=True
        sock=Sock();connection=RunnerHTTPS('cloud-api.near.ai')
        with patch('socket.socket',return_value=sock),patch('socket.getaddrinfo',side_effect=AssertionError('DNS forbidden')):
            with self.assertRaises(ValueError):connection.connect()
        self.assertTrue(sock.closed);self.assertEqual(sock.path,'/run/egress.sock')
        self.assertNotIn(b'Authorization',sock.request)
if __name__=='__main__':unittest.main()

class MacAuthorizationTests(unittest.TestCase):
    def test_separate_signed_domain_and_profile_are_not_tdx_authority(self):
        from .test_staging_approval import ApprovalTests
        from .staging_approval import signed_payload,validate_approval_payload,approval
        from .mac_live_worker import APPROVAL_DOMAIN
        fixture=ApprovalTests();fixture.setUp();payload=copy.deepcopy(fixture.payload)
        payload.update(version=2,app_id='mac-public-preview',issuer_profile='mac-appattest-coupon-v1',cdhash='aa'*32)
        encoded=fixture.sign(payload,APPROVAL_DOMAIN)
        self.assertEqual(validate_approval_payload(signed_payload(encoded,APPROVAL_DOMAIN,fixture.public),mac=True),payload)
        with self.assertRaises(RedemptionError):approval(encoded,fixture.public)
        for field,value in [('cdhash','aa'*20),('issuer_profile','dstack-tdx-coupon-v1'),('version',1),('prompt_policy','private')]:
            bad=copy.deepcopy(payload);bad[field]=value
            with self.subTest(field=field),self.assertRaises(RedemptionError):validate_approval_payload(bad,mac=True)
