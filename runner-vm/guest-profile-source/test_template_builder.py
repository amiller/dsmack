import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('role_template_builder',HERE/'build_disk_templates.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TemplateBuilderControls(unittest.TestCase):
 def test_independent_role_boundaries_and_unchanged_defaults(self):
  self.assertEqual(m.PROD_SCRATCH_BYTES,1<<30);self.assertEqual(m.PROD_RESULT_BYTES,256<<20)
  for role,cap in [('scratch',4<<30),('result',1<<30)]:
   self.assertEqual(m.validate_capacity(role,512),cap);self.assertEqual(m.validate_capacity(role,cap),cap)
   for n in (0,-512,cap+1,cap+512):
    with self.subTest(role=role,n=n),self.assertRaises(SystemExit):m.validate_capacity(role,n)
  for role in ('private','system','workload','unknown'):
   with self.subTest(role=role),self.assertRaises(SystemExit):m.validate_capacity(role,512)
 def test_existing_or_linked_output_is_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'template.ext4';p.write_bytes(b'preserved')
   for role,n in [('result',4096),('scratch',4*(1<<30)+512),('unknown',4096)]:
    with self.assertRaises(SystemExit):m.build_template(str(p),n,m.RESULT_UUID,'label',role=role)
    self.assertEqual(p.read_bytes(),b'preserved')
   link=Path(tmp)/'link.ext4';link.symlink_to('/does-not-exist')
   with self.assertRaises(SystemExit):m.build_template(str(link),4096,m.RESULT_UUID,'label',role='result')
   self.assertTrue(link.is_symlink())
 def test_descriptor_uses_role_ceiling(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'tiny.ext4'
   with mock.patch.object(m.subprocess,'run',return_value=mock.Mock(returncode=0)):
    result=m.build_template(str(p),4096,m.SCRATCH_UUID,'label',role='scratch')
   self.assertEqual(result['capacity_role'],'scratch');self.assertEqual(result['template_bytes_max'],4<<30)

if __name__=='__main__':unittest.main()
