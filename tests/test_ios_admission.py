"""Opt-in admission integration test against a dedicated disposable Anvil chain."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from web3 import Web3
from eth_account import Account
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
RPC = os.environ.get('ATTEST_ADMISSION_TEST_RPC')
# Published Anvil development key, never use on a real chain.
KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'


@unittest.skipUnless(RPC, 'Set ATTEST_ADMISSION_TEST_RPC to a dedicated Anvil instance')
class IOSAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if urlparse(RPC).hostname not in ('localhost', '127.0.0.1', '::1'):
            raise RuntimeError('Test RPC must be a disposable loopback Anvil instance')
        cls.w = Web3(Web3.HTTPProvider(RPC))
        if cls.w.eth.chain_id != 31337:
            raise RuntimeError('This test requires disposable chain 31337')
        # Repeated deployment scripts intentionally bid above current gas price;
        # replenish only the public development account on this local test chain.
        response = cls.w.provider.make_request('anvil_setBalance', [Account.from_key(KEY).address, hex(10**40)])
        if 'error' in response:
            raise RuntimeError('Anvil fixture funding failed')
        cls.tmp = tempfile.TemporaryDirectory(prefix='ios-admission-')
        cls.path = Path(cls.tmp.name)
        cls.env = dict(os.environ, PRIVATE_KEY=KEY)
        for script, args in [
            ('deploy_network.py', ['--build', 'contracts/fixtures/cd-args-developer-id.json', '--out', str(cls.path/'mac.json'), '--publisher-team', 'DC9JH5DRMY', '--activate']),
            ('prepare_ios_category.py', ['--existing', str(cls.path/'mac.json'), '--out', str(cls.path/'ios.json')]),
        ]:
            r = subprocess.run([sys.executable, 'scripts/release/'+script, '--rpc', RPC, *args], cwd=ROOT, env=cls.env, capture_output=True, text=True)
            if r.returncode:
                raise RuntimeError(r.stderr)
        cls.ios = json.loads((cls.path/'ios.json').read_text())
        cls.mac = json.loads((cls.path/'mac.json').read_text())
        cls.count = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_admit(self, *, ios=None, build=None, execute=False, out=None):
        type(self).count += 1
        ios_path = self.path/f'input-{self.count}.json'
        ios_path.write_text(json.dumps(self.ios if ios is None else ios))
        build_path = ROOT/'contracts/fixtures/resign/iphone-honest.json'
        if build is not None:
            build_path = self.path/f'build-{self.count}.json'
            build_path.write_text(json.dumps(build))
        out = out or self.path/f'result-{self.count}.json'
        cmd = [sys.executable, 'scripts/release/admit_ios_release.py', '--rpc', RPC,
               '--ios', str(ios_path), '--mac', str(self.path/'mac.json'), '--build', str(build_path), '--out', str(out)]
        if execute:
            cmd.append('--execute')
        env = dict(self.env)
        if not execute:
            env.pop('PRIVATE_KEY', None)
        return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True), out

    def test_01_read_only_requires_no_key_and_sends_nothing(self):
        block = self.w.eth.block_number
        r, out = self.run_admit()
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(out.read_text())
        self.assertTrue(result['readOnly'])
        self.assertFalse(result['enabled'])
        self.assertFalse(result['admitted'])
        self.assertEqual(result['transactions'], [])
        self.assertEqual(self.w.eth.block_number, block)

    def test_02_bad_inputs_send_no_transactions(self):
        block = self.w.eth.block_number
        cases = [dict(self.ios, iosCDRegistry=self.mac['macCDRegistry']),
                 dict(self.ios, iosAdapter=self.mac['macAdapter']),
                 dict(self.ios, chainId=84532),
                 dict(self.ios, iosCategory=self.mac['macCategory'])]
        for ios in cases:
            with self.subTest(ios=ios):
                r, out = self.run_admit(ios=ios, execute=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse(out.exists())
        build = json.loads((ROOT/'contracts/fixtures/resign/iphone-honest.json').read_text())
        build['cdhash'] = '0x'+'00'*32
        r, out = self.run_admit(build=build, execute=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(out.exists())
        self.assertEqual(self.w.eth.block_number, block)

    def test_03_admission_preserves_active_mac_and_disabled_iphone(self):
        r, out = self.run_admit(execute=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(out.read_text())
        self.assertTrue(result['admitted'])
        self.assertFalse(result['enabled'])
        self.assertFalse(result['before']['paused'])
        self.assertEqual(result['before'], result['after'])
        self.assertEqual(len(result['transactions']), 2)
        self.assertTrue(all(tx['status']=='confirmed' for tx in result['transactions']))
        block = self.w.eth.block_number
        r, _ = self.run_admit(execute=True, out=out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('reconcile', r.stderr)
        self.assertEqual(self.w.eth.block_number, block)

    def test_04_enabled_category_is_rejected(self):
        abi = json.loads((ROOT/'contracts/out/DemoV2.sol/DemoV2.json').read_text())['abi']
        network = self.w.eth.contract(address=self.ios['DemoV1'], abi=abi)
        category = bytes.fromhex(self.ios['iosCategory'][2:])
        admin = self.ios['admin']
        self.w.eth.wait_for_transaction_receipt(network.functions.setCategoryEnabled(category, True).transact({'from':admin}))
        try:
            block = self.w.eth.block_number
            r, out = self.run_admit(execute=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('must be disabled', r.stderr)
            self.assertFalse(out.exists())
            self.assertEqual(self.w.eth.block_number, block)
        finally:
            self.w.eth.wait_for_transaction_receipt(network.functions.setCategoryEnabled(category, False).transact({'from':admin}))

    def test_05_pending_administrator_transaction_is_rejected(self):
        self.w.provider.make_request('evm_setAutomine', [False])
        try:
            self.w.eth.send_transaction({'from':self.ios['admin'], 'to':self.ios['admin'], 'value':0, 'gas':21000})
            nonce = self.w.eth.get_transaction_count(self.ios['admin'], 'pending')
            r, out = self.run_admit(execute=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('pending transactions', r.stderr)
            self.assertFalse(out.exists())
            self.assertEqual(self.w.eth.get_transaction_count(self.ios['admin'], 'pending'), nonce)
        finally:
            self.w.provider.make_request('evm_setAutomine', [True])
            self.w.provider.make_request('evm_mine', [])


if __name__ == '__main__':
    unittest.main()
