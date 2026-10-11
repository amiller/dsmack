import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import rlp
from eth_keys import keys

from .issuance_guard import GuardRPC, FinalizedIssuanceGuard, PROFILE, UPSTREAM, keccak, commitment, run_checker
from .spike import RedemptionError
from .staging_approval import canonical


class Courier:
    def __init__(self, fail=False):self.transactions=[];self.fail=fail
    def call(self, method, params):
        if method=='eth_getTransactionCount':return '0x0'
        self.transactions.append(bytes.fromhex(params[0][2:]))
        if self.fail:raise RedemptionError('ambiguous courier')
        return '0x'+keccak(self.transactions[-1]).hex()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        self.seed=bytes.fromhex('11'*32);self.key=keys.PrivateKey(self.seed)
        self.profile={'version':1,'trust_profile':PROFILE,'chain_id':11155111,
            'genesis_validators_root':'0x'+'77'*32,'bootstrap_checkpoint':'0x'+'88'*32,
            'execution_rpc':'https://example.invalid','consensus_rpc':'https://example.invalid',
            'guard_address':'0x'+'33'*20,'guard_code_hash':'0x'+'44'*32,
            'issuer_address':'0x'+self.key.public_key.to_canonical_address().hex(),
            'issuance_policy_hash':'0x'+'22'*32,'max_finalized_age_seconds':1200,'timeout_seconds':1}
        self.path=self.root/'profile.json';self.path.write_bytes(canonical(self.profile));self.path.chmod(0o600)
        self.rpc=Courier()
        self.guard=self.make()
        self.intent={'version':1,'coupon_digest':'0x'+'aa'*32,'recipient_commitment':'0x'+'bb'*32,
            'accepted_offer_hash':'0x'+'cc'*32,'process_nonce':'0x'+'dd'*32}

    def make(self):return FinalizedIssuanceGuard(profile=self.profile,profile_path=self.path,
        binary='/unavailable-test-binary',private_key=self.seed,gas_price_wei=1000,deadline_seconds=30,rpc=self.rpc)
    def tearDown(self):self.temporary.cleanup()

    def test_courier_identifies_service_without_auth_and_preserves_exact_rpc(self):
        # The live RPC's browser-integrity rule refuses urllib's default UA.
        # An honest service identity must preserve the unauthenticated courier
        # boundary and the exact JSON-RPC method/arguments.
        class Response:
            def __enter__(self):return self
            def __exit__(self, *_args):pass
            def read(self, limit):return b'{"jsonrpc":"2.0","id":1,"result":"0xaa36a7"}'
        class Opener:
            def open(self, request, timeout):
                headers = dict(request.header_items())
                if headers.get('User-agent', '').startswith('Python-urllib/'):
                    raise RedemptionError('browser-integrity refusal')
                self.request, self.timeout = request, timeout
                return Response()
        rpc = GuardRPC('https://example.invalid'); rpc.opener = Opener()
        self.assertEqual(rpc.call('eth_chainId', []), '0xaa36a7')
        headers = dict(rpc.opener.request.header_items())
        self.assertEqual(headers, {'Content-type':'application/json','User-agent':'dsmack-coupon-guard/1'})
        self.assertEqual(json.loads(rpc.opener.request.data), {'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]})
        self.assertEqual(rpc.opener.timeout, 15)

    def test_standard_eip155_signature_calldata_and_currentboot_nonce_serialization(self):
        with ThreadPoolExecutor(2) as pool:list(pool.map(self.guard._send,[self.intent,self.intent]))
        decoded=[rlp.decode(raw) for raw in self.rpc.transactions]
        self.assertEqual([int.from_bytes(tx[0],'big') for tx in decoded],[0,1])
        for tx in decoded:
            v=int.from_bytes(tx[6],'big');r=int.from_bytes(tx[7],'big');s=int.from_bytes(tx[8],'big')
            digest=keccak(rlp.encode(tx[:6]+[11155111,0,0]))
            recovered=keys.Signature(vrs=(v-35-11155111*2,r,s)).recover_public_key_from_msg_hash(digest)
            self.assertEqual(recovered,self.key.public_key)
            self.assertEqual(tx[3],bytes.fromhex('33'*20))
            self.assertEqual(tx[5],keccak(b'consume(bytes32,(bytes32,bytes32,bytes32))')[:4]+
                b''.join(bytes.fromhex(self.intent[k][2:]) for k in ('coupon_digest','recipient_commitment','accepted_offer_hash','process_nonce')))

    def test_unknown_submission_never_retries_or_invokes_finality(self):
        self.rpc.fail=True
        with patch('experiments.coupon_redemption.issuance_guard.run_checker',side_effect=AssertionError('not reached')):
            with self.assertRaises(RedemptionError):self.guard('aa'*32,'UnknownPeer00001',bytes.fromhex('55'*32),'cc'*32,
                {'issuance_policy_sha256':'22'*32})
        self.assertEqual(len(self.rpc.transactions),1)

    def verdict(self):
        return {'version':1,'trust_profile':PROFILE,'upstream_sha':UPSTREAM,'chain_id':11155111,
            'genesis_validators_root':self.profile['genesis_validators_root'],
            'bootstrap_checkpoint':self.profile['bootstrap_checkpoint'],'verified_at_ms':int(time.time()*1000),
            'freshness_basis':'local-system-time-assumed',
            'finalized_block':{'hash':'0x'+'01'*32,'number':1,'timestamp':int(time.time()),'state_root':'0x'+'02'*32,'receipts_root':'0x'+'03'*32},
            'guard':{'address':self.profile['guard_address'],'code_hash':self.profile['guard_code_hash'],
                'issuer':self.profile['issuer_address'],'policy_hash':self.profile['issuance_policy_hash'],
                'coupon_digest':self.intent['coupon_digest'],'consumed_commitment':'0x'+commitment(self.profile,self.intent).hex()}}

    def test_wrong_nonce_authority_and_freshness_are_refused(self):
        good=self.verdict();expected=good['guard']['consumed_commitment'];self.guard._validate(good,'aa'*32,expected)
        for kind in ('nonce','code','policy','stale','future','clock','profile'):
            bad=copy.deepcopy(good)
            if kind=='nonce':bad['guard']['consumed_commitment']='0x'+'ff'*32
            elif kind=='code':bad['guard']['code_hash']='0x'+'ff'*32
            elif kind=='policy':bad['guard']['policy_hash']='0x'+'ff'*32
            elif kind=='stale':bad['finalized_block']['timestamp']-=1201
            elif kind=='future':bad['finalized_block']['timestamp']+=60
            elif kind=='clock':bad['freshness_basis']='authenticated-wall-clock'
            else:bad['trust_profile']='rpc-latest'
            with self.subTest(kind=kind),self.assertRaises(RedemptionError):self.guard._validate(bad,'aa'*32,expected)

    def test_checker_pipe_output_limit_timeout_and_reap(self):
        for source in ('import sys; sys.stdout.write("x"*10000)','import time; time.sleep(20)'):
            script=self.root/'checker';script.write_text('#!/usr/bin/python3\n'+source+'\n');script.chmod(0o700)
            started=time.monotonic()
            with self.assertRaises(RedemptionError):run_checker(str(script),self.path,self.intent,.1)
            self.assertLess(time.monotonic()-started,2)


if __name__=='__main__':unittest.main()
