"""RPC-trusted Base path: exact live submission only, no historical permission."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import rlp
from eth_keys import keys
from .issuance_guard import (BASE_PROFILE, BASE_RPC, BaseSafeIssuanceGuard,
    commitment, keccak, validate_finality_profile)
from .spike import RedemptionError
from .staging_approval import canonical


class BaseRPCFixture:
    def __init__(self, profile):
        self.profile = profile; self.sent = []; self.calls = []; self.change = None; self.safe_reads = 0
    def call(self, method, params):
        self.calls.append((method, params))
        if method == 'eth_chainId': return '0x2105' if self.change != 'chain' else '0x1'
        if method == 'eth_getTransactionCount': return '0x0'
        if method == 'eth_sendRawTransaction':
            raw = bytes.fromhex(params[0][2:]); self.sent.append(raw)
            if self.change == 'ambiguous': raise RedemptionError('ambiguous send')
            self.txhash = '0x' + keccak(raw).hex(); self.tx = rlp.decode(raw)
            return self.txhash
        mined_hash = '0x' + '11' * 32; safe_hash = '0x' + '22' * 32
        if method == 'eth_getTransactionReceipt':
            return {'transactionHash':self.txhash,'from':self.profile['issuer_address'],
                'to':self.profile['guard_address'],'status':'0x0' if self.change == 'revert' else '0x1',
                'blockNumber':'0x5','blockHash':mined_hash}
        if method == 'eth_getTransactionByHash':
            return {'hash':self.txhash,'from':self.profile['issuer_address'],'to':self.profile['guard_address'],
                'value':'0x0','chainId':'0x2105','blockHash':mined_hash,'blockNumber':'0x5',
                'input':'0x' + (self.tx[5] if self.change != 'input' else b'wrong').hex()}
        if method == 'eth_getBlockByNumber':
            if params[0] == '0x5': return {'hash':mined_hash if self.change != 'receipt_reorg' else safe_hash}
            if params[0] == 'safe': self.safe_reads += 1
            timestamp = int(time.time()) - (1201 if self.change == 'stale' else 0)
            wrong_hash = ((self.change == 'safe_reorg' and params[0] != 'safe')
                or (self.change == 'same_height_reorg' and params[0] == 'safe' and self.safe_reads > 1))
            return {'hash':mined_hash if wrong_hash else safe_hash,
                'number':'0x4' if self.change == 'safe_downgrade' and self.safe_reads > 1 else '0x7','timestamp':hex(timestamp)}
        if method == 'eth_getCode': return '0x6000' if self.change != 'code' else '0x6001'
        if method == 'eth_call':
            if params[0]['data'] == '0x' + keccak(b'issuer()')[:4].hex():
                return '0x' + '00' * 12 + self.profile['issuer_address'][2:]
            return self.profile['issuance_policy_hash'] if self.change != 'policy' else '0x' + 'ff' * 32
        if method == 'eth_getStorageAt':
            data = self.tx[5][4:]
            intent = dict(zip(('coupon_digest','recipient_commitment','accepted_offer_hash','process_nonce'),
                ['0x'+data[i:i+32].hex() for i in range(0,128,32)]))
            return '0x'+commitment(self.profile,intent).hex() if self.change != 'nonce' else '0x'+'ff'*32
        raise AssertionError(method)


class BaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.path = Path(self.temp.name)/'profile.json'
        self.seed = bytes.fromhex('11'*32)
        self.profile = {'version':1,'trust_profile':BASE_PROFILE,'chain_id':8453,'execution_rpc':BASE_RPC,
            'guard_address':'0x'+'33'*20,'guard_code_hash':'0x'+keccak(bytes.fromhex('6000')).hex(),
            'issuer_address':'0x'+keys.PrivateKey(self.seed).public_key.to_canonical_address().hex(),
            'issuance_policy_hash':'0x'+'44'*32,'max_safe_age_seconds':1200,'timeout_seconds':300}
        self.path.write_bytes(canonical(self.profile)); self.path.chmod(0o600)
        self.rpc = BaseRPCFixture(self.profile)
    def tearDown(self): self.temp.cleanup()
    def guard(self):
        return BaseSafeIssuanceGuard(profile=self.profile,profile_path=self.path,binary='/unused',
            private_key=self.seed,gas_price_wei=6000000,deadline_seconds=30,rpc=self.rpc)
    def claim(self): self.guard()('aa'*32,'ActualPeer0000001',b'\x55'*32,'cc'*32,{'issuance_policy_sha256':'44'*32})
    def test_safe_exact_state_after_one_current_submission(self):
        self.claim(); self.assertEqual(len(self.rpc.sent),1)
        tx=rlp.decode(self.rpc.sent[0]); v=int.from_bytes(tx[6],'big')
        signature=keys.Signature(vrs=(v-35-8453*2,int.from_bytes(tx[7],'big'),int.from_bytes(tx[8],'big')))
        self.assertEqual(signature.recover_public_key_from_msg_hash(keccak(rlp.encode(tx[:6]+[8453,0,0]))),keys.PrivateKey(self.seed).public_key)
        frozen=[p[-1] for m,p in self.rpc.calls if m in ('eth_getCode','eth_call','eth_getStorageAt')]
        self.assertEqual(frozen,[{'blockHash':'0x'+'22'*32,'requireCanonical':True}]*4)
    def test_mismatch_reorg_and_unknown_submission_quarantine_without_resubmission(self):
        for change in ('chain','ambiguous','revert','input','receipt_reorg','safe_reorg','same_height_reorg','safe_downgrade','stale','code','policy','nonce'):
            with self.subTest(change=change):
                self.rpc=BaseRPCFixture(self.profile);self.rpc.change=change
                with self.assertRaises(RedemptionError):self.claim()
                self.assertLessEqual(len(self.rpc.sent),1)
    def test_tampered_protected_profile_refused_before_send(self):
        self.path.write_bytes(b'{}')
        with self.assertRaises(RedemptionError):self.claim()
        self.assertEqual(self.rpc.sent,[])
    def test_exact_profile_never_accepts_latest_other_rpc_or_chain(self):
        validate_finality_profile(self.profile)
        for name,value in [('chain_id',84532),('execution_rpc','https://example.invalid'),
                           ('trust_profile','rpc-latest'),('extra',1),('version',True)]:
            bad=copy.deepcopy(self.profile);bad[name]=value
            with self.subTest(name=name),self.assertRaises(ValueError):validate_finality_profile(bad)

if __name__ == '__main__': unittest.main()
