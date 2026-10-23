"""Synthetic tests for signing_policy. No codesign, no keychain, no credentials.
Entitlements are passed as raw plist bytes, matching build.sh's f.read() contract."""
import plistlib, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing_policy as sp

ENTS = {'com.apple.application-identifier': sp.TEAM_ID + '.' + sp.BUNDLE_ID,
        'com.apple.developer.team-identifier': sp.TEAM_ID,
        'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash'],
        'keychain-access-groups': [sp.TEAM_ID + '.' + sp.BUNDLE_ID],
        'com.apple.security.virtualization': True}

# Realistic codesign -d --verbose=4 output: flags live in the CodeDirectory line,
# there is no separate flags= or Application-identifier= line.
META = (f'Executable=DsmackRunner.app/Contents/MacOS/dsmack-runner\n'
        f'Identifier=dev.dsmack.provider\n'
        'Format=bundle with Mach-O thin (arm64)\n'
        'CodeDirectory v=20500 size=104383 flags=0x10000(runtime) hashes=3251+7 location=embedded\n'
        'SignatureSize=8976\n'
        'CandidateCDHashFull sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n'
        f'TeamIdentifier={sp.TEAM_ID}\n'
        'Authority=Apple Development: Jane Developer (ABCDEFGHIJ)\n'
        'Authority=Apple Worldwide Developer Relations Certification Authority\n')


class SigningPolicyTests(unittest.TestCase):
    def p(self, ents):
        return plistlib.dumps(ents)

    def test_accepts_real_shape(self):
        ents = sp.check_entitlements(self.p(ENTS))
        self.assertEqual(ents['com.apple.developer.team-identifier'], sp.TEAM_ID)
        info = sp.check_metadata(META)
        self.assertEqual(info['flags'], sp.RUNTIME_BIT)
        self.assertEqual(len(info['cdhash_full']), 64)

    def test_accepts_multiple_keychain_groups(self):
        groups = [sp.TEAM_ID + '.dev.dsmack.provider', sp.TEAM_ID + '.shared']
        sp.check_entitlements(self.p({**ENTS, 'keychain-access-groups': groups}))

    def test_rejects_dangerous_and_unknown(self):
        bad = [{'get-task-allow': True}, {'com.apple.cs.debugger': True},
               {'com.apple.security.cs.allow-jit': True}, {'com.apple.private.foo': True},
               {'com.apple.security.temporary-exception.mcd-entitlements': True},
               {'some.random.key': 1}]
        for e in bad:
            with self.assertRaises(sp.Reject):
                sp.check_entitlements(self.p({**ENTS, **e}))

    def test_rejects_missing_or_wrong_values(self):
        for e in [{'com.apple.security.virtualization': False},
                  {'com.apple.developer.team-identifier': 'ZZZZZZZZZZ'},
                  {'com.apple.application-identifier': 'OTHER.' + sp.BUNDLE_ID},
                  {'com.apple.developer.devicecheck.app-attest-opt-in': 'runtime'},
                  {'com.apple.developer.devicecheck.app-attest-opt-in': 'CDhash'},
                  {'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash', 'other']},
                  {'keychain-access-groups': ['OTHERTEAM9.x']},
                  {'keychain-access-groups': []},
                  {'keychain-access-groups': '*'},
                  {'keychain-access-groups': sp.TEAM_ID + '.' + sp.BUNDLE_ID}]:
            with self.assertRaises(sp.Reject):
                sp.check_entitlements(self.p({**ENTS, **e}))

    def test_rejects_missing_required_key(self):
        for key in sp.REQUIRED_ENTITLEMENTS:
            with self.assertRaises(sp.Reject):
                sp.check_entitlements(self.p({k: v for k, v in ENTS.items() if k != key}))

    def test_rejects_bad_plist_and_type(self):
        for b in [b'not a plist', 'string', plistlib.dumps([])]:
            with self.assertRaises(sp.Reject):
                sp.check_entitlements(b)

    def test_metadata_requirements(self):
        for m in [META.replace('flags=0x10000', 'flags=0x0'),
                  META.replace('flags=0x10000(runtime)', 'flags=0x2(adhoc|runtime)'),
                  META.replace('flags=0x10000(runtime)', 'flags=0x20000(linker-signed)'),
                  META.replace('flags=0x10000(runtime)', 'flags=0x20200(adhoc|linker-signed)'),
                  META.replace(f'Identifier={sp.BUNDLE_ID}', 'Identifier=other.bundle'),
                  META.replace(f'TeamIdentifier={sp.TEAM_ID}', 'TeamIdentifier=OTHERTEAM9'),
                  META.replace('Authority=Apple Development: ', 'Authority=Developer ID Application: '),
                  META.replace('CodeDirectory v=20500', 'NoCodeDirectory v=20500'),
                  META.replace('CandidateCDHashFull sha256=', 'CDHash='),
                  'garbage']:
            with self.assertRaises(sp.Reject):
                sp.check_metadata(m)
        with self.assertRaises(sp.Reject):
            sp.check_metadata(META.encode())

    def test_trusted_identity_is_explicit(self):
        alt = {'com.apple.application-identifier': 'OTHERTEAM9.other.bundle',
               'com.apple.developer.team-identifier': 'OTHERTEAM9',
               'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash'],
               'keychain-access-groups': ['OTHERTEAM9.other.bundle'],
               'com.apple.security.virtualization': True}
        sp.check_entitlements(plistlib.dumps(alt), team_id='OTHERTEAM9', bundle_id='other.bundle')
        sp.check_metadata(META.replace(f'Identifier={sp.BUNDLE_ID}', 'Identifier=other.bundle')
                            .replace(f'TeamIdentifier={sp.TEAM_ID}', 'TeamIdentifier=OTHERTEAM9'),
                          team_id='OTHERTEAM9', bundle_id='other.bundle')
        with self.assertRaises(sp.Reject):
            sp.check_metadata(META, team_id='OTHERTEAM9')


HVFN = {key: value for key, value in ENTS.items()
        if key != 'com.apple.security.virtualization'}
HVFN['com.apple.security.hypervisor'] = True


class HVFProfileTests(unittest.TestCase):
    """Policy v2 (POLICY_VERSION_HVF): identical to v1 except the virtualization ->
    hypervisor key swap. Nothing else may loosen: no security.cs.*, same exact-set
    equality, same identity/attest/keychain/runtime checks."""

    def p(self, ents):
        return plistlib.dumps(ents)

    def hvf(self, ents):
        return sp.check_entitlements_version(self.p(ents), sp.POLICY_VERSION_HVF)

    def test_accepts_exact_hvf_five(self):
        ents = self.hvf(HVFN)
        self.assertEqual(ents['com.apple.security.hypervisor'], True)

    def test_accepts_multiple_keychain_groups(self):
        groups = [sp.TEAM_ID + '.dev.dsmack.provider', sp.TEAM_ID + '.shared']
        self.hvf({**HVFN, 'keychain-access-groups': groups})

    def test_legacy_default_unchanged(self):
        # v1 default still requires VZ and still rejects the HVF plist...
        sp.check_entitlements(self.p(ENTS))
        with self.assertRaises(sp.Reject):
            sp.check_entitlements(self.p(HVFN))
        # ...and the HVF profile rejects the VZ plist: the swap is exact, not additive.
        with self.assertRaises(sp.Reject):
            self.hvf(ENTS)

    def test_rejects_forbidden_and_unknown_under_hvf(self):
        bad = [{'com.apple.security.cs.disable-library-validation': True},
               {'com.apple.security.cs.allow-jit': True},
               {'com.apple.security.cs.allow-unsigned-executable-memory': True},
               {'get-task-allow': True},
               {'com.apple.cs.debugger': True},
               {'com.apple.private.foo': True},
               {'com.apple.security.temporary-exception.mcd-entitlements': True},
               {'com.apple.vm.hypervisor': True},      # wrong key name, not the real entitlement
               {'com.apple.security.virtualization': True},  # VZ key must not ride along
               {'some.random.key': 1}]
        for e in bad:
            with self.assertRaises(sp.Reject):
                self.hvf({**HVFN, **e})

    def test_rejects_wrong_or_missing_hypervisor_value(self):
        with self.assertRaises(sp.Reject):
            self.hvf({**HVFN, 'com.apple.security.hypervisor': False})
        with self.assertRaises(sp.Reject):
            self.hvf({**HVFN, 'com.apple.security.hypervisor': 'true'})
        missing = {k: v for k, v in HVFN.items() if k != 'com.apple.security.hypervisor'}
        with self.assertRaises(sp.Reject):
            self.hvf(missing)

    def test_rejects_identity_attest_and_group_violations(self):
        for e in [{'com.apple.developer.team-identifier': 'ZZZZZZZZZZ'},
                  {'com.apple.application-identifier': 'OTHER.' + sp.BUNDLE_ID},
                  {'com.apple.developer.devicecheck.app-attest-opt-in': 'runtime'},
                  {'keychain-access-groups': ['OTHERTEAM9.x']},
                  {'keychain-access-groups': []}]:
            with self.assertRaises(sp.Reject):
                self.hvf({**HVFN, **e})

    def test_rejects_unknown_versions(self):
        for v in [3, 0, -1, '2', None, 2.0]:
            with self.assertRaises(sp.Reject):
                sp.check_entitlements_version(self.p(HVFN), v)

    def test_metadata_rules_are_profile_independent(self):
        # Same hardened-runtime / identity / authority checks govern both profiles.
        info = sp.check_metadata(META)
        self.assertEqual(info['flags'], sp.RUNTIME_BIT)
        with self.assertRaises(sp.Reject):
            sp.check_metadata(META.replace('flags=0x10000(runtime)', 'flags=0x0'))
        with self.assertRaises(sp.Reject):
            sp.check_metadata(META.replace(f'TeamIdentifier={sp.TEAM_ID}', 'TeamIdentifier=OTHERTEAM9'))


if __name__ == '__main__':
    unittest.main()
