import unittest
from alpha_signing_policy import check_metadata,POLICY_VERSION,AUTHORITY
HASH='a'*64
TEXT='\n'.join(['Identifier=dev.dsmack.provider','TeamIdentifier=DC9JH5DRMY','Authority='+AUTHORITY,'Authority=Developer ID Certification Authority','Authority=Apple Root CA','CodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+0 location=embedded','CandidateCDHashFull sha256='+HASH,'Timestamp=Oct 22, 2026 at 10:00:00 AM'])
def check(text=TEXT,**kw):return check_metadata(text,policy_version=POLICY_VERSION,expected_cdhash=HASH,**kw)
class Policy(unittest.TestCase):
 def test_explicit_profile_metadata_only(self):
  r=check();self.assertEqual(r['attestation_category'],6);self.assertFalse(r['launch_ready']);self.assertFalse(r['apple_signature_verified'])
 def test_wrong_profile_refused(self):
  with self.assertRaises(ValueError):check_metadata(TEXT,policy_version='engineering',expected_cdhash=HASH)
 def test_detecting_mutations(self):
  for text in [TEXT.replace(AUTHORITY,'Apple Development: Test'),TEXT.replace('Timestamp=','Signed Time='),TEXT.replace('Timestamp=Oct 22, 2026 at 10:00:00 AM','Timestamp=none'),TEXT.replace('0x10000(runtime)','0x10002(runtime,adhoc)'),TEXT.replace('0x10000(runtime)','0x30000(runtime,linker-signed)'),TEXT.replace('TeamIdentifier=DC9JH5DRMY','TeamIdentifier=OTHER'),TEXT.replace(HASH,'b'*64),TEXT+'\nTimestamp=other',TEXT+'\nIdentifier=other']:
   with self.subTest(text=text):
    with self.assertRaises(ValueError):check(text)
if __name__=='__main__':unittest.main()
