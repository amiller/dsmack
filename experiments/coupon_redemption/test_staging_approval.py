import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .staging_approval import approval, configuration, canonical, payload_hash, APPROVAL_DOMAIN, CONFIG_DOMAIN, POWERS
from .offer_v2 import canonical as offer_canonical
from .live_worker import LiveWorker
from .spike import RedemptionError


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('99'*32))
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.provider={'workspace_id':'11111111-1111-4111-8111-111111111111',
            'organization_id':'22222222-2222-4222-8222-222222222222',
            'session_jwt':'SYNTHETIC-NOT-CREDENTIAL','reporting_token':'SYNTHETIC-NOT-CREDENTIAL'}
        binding={'mode':'near',**{k:self.provider[k] for k in ('workspace_id','organization_id')}}
        scope=hashlib.sha256(b'dsmack-coupon-scope-v2\0'+bytes.fromhex('66'*32)+offer_canonical(binding)).hexdigest()
        self.payload={'version':1,'profile':'debug-staging','app_id':'05'*20,'compose_hash':'01'*32,
            'identity_policy_sha256':'02'*32,'issuance_policy_sha256':'03'*32,
            'issuer_public_key_sha256':'04'*32,'provider_scope_commitment':scope,
            'guard':{'chain_id':11155111,'address':'0x'+'11'*20,'code_hash':'0x'+'22'*32,'issuer_address':'0x'+'33'*20},
            'powers':POWERS,'prompt_policy':'synthetic-only','max_coupon_nano_usd':'5000000000',
            'max_total_nano_usd':'5000000000','expires_at':'2099-01-01T00:00:00Z','generation':1}

    def sign(self, payload, domain=APPROVAL_DOMAIN):
        message=domain.encode()+b'\0'+canonical(payload)
        return canonical({'domain':domain,'payload':payload,'signature_hex':self.key.sign(message).hex()})

    def config(self, directory):
        return {'version':1,'approval_sha256':payload_hash(APPROVAL_DOMAIN,self.payload),
            'issuer_peer_id':'IssuerPeer00000001','state_dir':str(directory/'state'),
            'sponsor_subject':'operator:sponsor','observer_subject':'operator:observer',
            'peers':{'SponsorPeer0000001':{'subject':'operator:sponsor','roles':['sponsor']}},
            'provider':self.provider,'scope_salt_hex':'66'*32,
            'finality_profile':{'version':1,'trust_profile':'helios-ethereum-sepolia-finalized-experiment',
                'chain_id':11155111,'genesis_validators_root':'0x'+'77'*32,'bootstrap_checkpoint':'0x'+'88'*32,
                'consensus_rpc':'https://example.invalid','execution_rpc':'https://example.invalid',
                'guard_address':self.payload['guard']['address'],'guard_code_hash':self.payload['guard']['code_hash'],
                'issuer_address':self.payload['guard']['issuer_address'],'issuance_policy_hash':'0x'+'03'*32,
                'max_finalized_age_seconds':1200,'timeout_seconds':30},
            'gas_price_wei':1000,'job_deadline_seconds':3600,'max_active_jobs':1}

    def test_signature_pin_and_exact_policy(self):
        self.assertEqual(approval(self.sign(self.payload),self.public),self.payload)
        wrong=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        with self.assertRaises(RedemptionError):approval(self.sign(self.payload),wrong)
        for key,value in (('profile','private-issuance-qualified'),('max_coupon_nano_usd','05000000000'),
            ('max_total_nano_usd','1'),('expires_at','2000-01-01T00:00:00Z'),('powers',[]),
            ('generation',2**53),('unexpected',True)):
            bad=copy.deepcopy(self.payload);bad[key]=value
            with self.subTest(key=key),self.assertRaises(RedemptionError):approval(self.sign(bad),self.public)

    def test_base_debug_confirmation_is_signed_exact_and_capped(self):
        from .issuance_guard import BASE_CONFIRMATION, BASE_PROFILE, BASE_RPC
        self.payload['guard']['chain_id'] = 8453
        self.payload['guard']['confirmation'] = copy.deepcopy(BASE_CONFIRMATION)
        approved = approval(self.sign(self.payload), self.public)
        with tempfile.TemporaryDirectory() as directory:
            good = self.config(Path(directory))
            good['finality_profile'] = {'version':1,'trust_profile':BASE_PROFILE,'chain_id':8453,
                'execution_rpc':BASE_RPC,'guard_address':approved['guard']['address'],
                'guard_code_hash':approved['guard']['code_hash'],'issuer_address':approved['guard']['issuer_address'],
                'issuance_policy_hash':'0x'+approved['issuance_policy_sha256'],
                'max_safe_age_seconds':1200,'timeout_seconds':300}
            self.assertEqual(configuration(self.sign(good,CONFIG_DOMAIN),self.public,approved),good)
            for field,value in [('block_tag','latest'),('l1_finality_verified',True),
                                ('rpc_url','https://example.invalid'),('version',True),('extra',1)]:
                bad=copy.deepcopy(self.payload);bad['guard']['confirmation'][field]=value
                with self.subTest(field=field),self.assertRaises(RedemptionError):approval(self.sign(bad),self.public)
            bad=copy.deepcopy(self.payload);bad['max_total_nano_usd']='5000000001'
            with self.assertRaises(RedemptionError):approval(self.sign(bad),self.public)
            bad=copy.deepcopy(good);bad['finality_profile']['chain_id']=11155111
            with self.assertRaises(RedemptionError):configuration(self.sign(bad,CONFIG_DOMAIN),self.public,approved)

    def test_provider_account_and_guard_are_bound_without_public_account_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            good=self.config(Path(directory))
            self.assertEqual(configuration(self.sign(good,CONFIG_DOMAIN),self.public,self.payload),good)
            bad=copy.deepcopy(good);bad['provider']['organization_id']='33333333-3333-4333-8333-333333333333'
            with self.assertRaises(RedemptionError):configuration(self.sign(bad,CONFIG_DOMAIN),self.public,self.payload)
            bad=copy.deepcopy(good);bad['finality_profile']['guard_address']='0x'+'ff'*20
            with self.assertRaises(RedemptionError):configuration(self.sign(bad,CONFIG_DOMAIN),self.public,self.payload)
            self.assertNotIn('workspace_id',json.dumps(self.payload))

    def test_malformed_signed_config_members_refuse_stably(self):
        # Review L2: an authority-signed config with malformed members must
        # refuse with the named stable error — never TypeError/ValueError from
        # a regex on None or from canonicalizing an uncanonicalizable approval.
        # Review F2: state_dir must be a precise absolute path string and
        # issuer_peer_id a valid identity-domain string — previously they
        # passed validation and crashed downstream (Path()/sqlite3 INSERT).
        with tempfile.TemporaryDirectory() as directory:
            good=self.config(Path(directory))
            cases={'scope_salt_hex':('signed provider configuration refused',None),
                'approval_sha256':('signed staging configuration refused',None),
                'version':('signed staging configuration refused','1'),
                'state_dir':('signed staging configuration refused',123),
                'issuer_peer_id':('signed staging configuration refused',['IssuerPeer00000001'])}
            for field,(message,value) in cases.items():
                bad=copy.deepcopy(good);bad[field]=value
                with self.subTest(field=field):
                    with self.assertRaises(RedemptionError) as raised:
                        configuration(self.sign(bad,CONFIG_DOMAIN),self.public,self.payload)
                    self.assertEqual(str(raised.exception),message)
            for field,value in (('state_dir','relative/state'),('state_dir','/a/../b'),
                                ('state_dir',None),('issuer_peer_id','Short'),
                                ('issuer_peer_id',None)):
                bad=copy.deepcopy(good);bad[field]=value
                with self.subTest(field=field,value=value):
                    with self.assertRaises(RedemptionError) as raised:
                        configuration(self.sign(bad,CONFIG_DOMAIN),self.public,self.payload)
                    self.assertEqual(str(raised.exception),'signed staging configuration refused')
            bad=copy.deepcopy(good);bad['scope_salt_hex']='zz'*32
            with self.assertRaises(RedemptionError) as raised:
                configuration(self.sign(bad,CONFIG_DOMAIN),self.public,self.payload)
            self.assertEqual(str(raised.exception),'signed provider configuration refused')
            with self.assertRaises(RedemptionError) as raised:
                configuration(self.sign(good,CONFIG_DOMAIN),self.public,{'uncanonicalizable':object()})
            self.assertEqual(str(raised.exception),'signed staging configuration refused')

    def test_actual_sdk_application_mismatch_stops_before_provider_or_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'approval.json').write_bytes(self.sign(self.payload));(root/'approval.json').chmod(0o600)
            path=root/'config.json';path.write_bytes(self.sign(self.config(root),CONFIG_DOMAIN));path.chmod(0o600)
            fake=SimpleNamespace(_client=SimpleNamespace(info=lambda:SimpleNamespace(app_id='ff'*20,compose_hash='01'*32)))
            with patch('experiments.coupon_redemption.live_worker.approval_root',return_value=self.public), \
                 patch('experiments.coupon_redemption.live_worker.DstackIssuerIdentity.from_socket',return_value=fake), \
                 patch('experiments.coupon_redemption.live_worker.Near',side_effect=AssertionError('must not use credentials')):
                with self.assertRaises(RedemptionError):LiveWorker(path)
            self.assertFalse((root/'state').exists())

    def test_shared_signed_staging_primitive_vector(self):
        """Byte-exact shared vector: the schema coordination contract for the client lane."""
        from .staging_approval import APPROVAL_DOMAIN,CONFIG_DOMAIN
        vector=json.loads((Path(__file__).parent/'fixtures'/'staging-approval-vector.json').read_text())
        self.assertEqual(vector['authority_public_key_hex'],self.public.hex())
        def resign(payload,domain,seed=bytes.fromhex('99'*32)):
            key=Ed25519PrivateKey.from_private_bytes(seed)
            return canonical({'domain':domain,'payload':payload,
                'signature_hex':key.sign(domain.encode('ascii')+b'\0'+canonical(payload)).hex()})
        # The published envelopes reproduce exactly from the stated procedure.
        self.assertEqual(resign(vector['approval']['payload'],APPROVAL_DOMAIN).decode(),
                         vector['approval']['envelope'])
        self.assertEqual(resign(vector['config']['payload'],CONFIG_DOMAIN).decode(),
                         vector['config']['envelope'])
        # Both parse under the real validators with the pinned test authority.
        approved=approval(vector['approval']['envelope'].encode(),self.public)
        self.assertEqual(payload_hash(APPROVAL_DOMAIN,approved),vector['approval']['sha256'])
        self.assertEqual(configuration(vector['config']['envelope'].encode(),self.public,approved),
                         vector['config']['payload'])
        self.assertNotIn('workspace_id',json.dumps(approved))
        # Every refused variant fails the named validator with no partial state.
        for refused in vector['refused']:
            with self.subTest(name=refused['name']):
                raw=refused['envelope'].encode()
                with self.assertRaises(RedemptionError):
                    approval(raw,self.public) if refused['validator']=='approval' \
                        else configuration(raw,self.public,approved)


if __name__=='__main__':unittest.main()
