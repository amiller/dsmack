import unittest
from .app_binding import app_binding_allowed, key_parcel

class AppBindingTests(unittest.TestCase):
    def test_explicit_legacy_requires_exact_genesis_and_absent_app(self):
        c={'compose_hash':'22'*32};h='11'*32;app=h+'|'+c['compose_hash']
        self.assertTrue(app_binding_allowed(c,app,h,legacy_genesis=True))
        for changed,namespace,hashvalue in [({**c,'app':app},app,h),(c,'admin-name',h),(c,app,'33'*32),({'compose_hash':'44'*32},app,h)]:
            self.assertFalse(app_binding_allowed(changed,namespace,hashvalue,legacy_genesis=True))
        self.assertEqual(set(key_parcel('synthetic','admin-name','synthetic',legacy_genesis=True)),{'api_key','app_key'})
    def test_default_still_requires_attested_app_and_three_field_parcel(self):
        self.assertTrue(app_binding_allowed({'app':'expected'},'expected','11'*32))
        self.assertFalse(app_binding_allowed({},'expected','11'*32))
        self.assertFalse(app_binding_allowed({'app':'other'},'expected','11'*32))
        self.assertEqual(set(key_parcel('synthetic','expected','synthetic')),{'api_key','app_key','app'})
