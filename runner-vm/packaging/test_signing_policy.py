import plistlib, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing_policy as sp

ENTS = {'com.apple.application-identifier': sp.TEAM_ID + '.' + sp.BUNDLE_ID,
        'com.apple.developer.team-identifier': sp.TEAM_ID,
        'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash'],
        'keychain-access-groups': [sp.TEAM_ID + '.' + sp.BUNDLE_ID],
        'com.apple.security.hypervisor': True}

META = ('Executable=DsmackRunner.app/Contents/MacOS/dsmack-runner\n'
        f'Identifier={sp.BUNDLE_ID}\n'
        'CodeDirectory v=20500 size=104383 flags=0x10000(runtime) hashes=3251+7 location=embedded\n'
        'CandidateCDHashFull sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n'
        f'TeamIdentifier={sp.TEAM_ID}\n'
        'Authority=Apple Development: Jane Developer (ABCDEFGHIJ)\n')


class SigningPolicyTests(unittest.TestCase):
    def test_accepts_real_shape(self):
        sp.check_entitlements(plistlib.dumps(ENTS))
        self.assertEqual(sp.check_metadata(META)['flags'], sp.RUNTIME_BIT)

    def test_rejects_dangerous_entitlement(self):
        with self.assertRaises(sp.Reject):
            sp.check_entitlements(plistlib.dumps({**ENTS, 'com.apple.security.cs.disable-library-validation': True}))

    def test_rejects_unhardened_signature(self):
        with self.assertRaises(sp.Reject):
            sp.check_metadata(META.replace('flags=0x10000(runtime)', 'flags=0x2(adhoc)'))


if __name__ == '__main__':
    unittest.main()
