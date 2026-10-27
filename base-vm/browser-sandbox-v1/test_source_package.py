import importlib.util,pathlib,subprocess,unittest
here=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('base_deriver',here/'derive.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class Derive(unittest.TestCase):
 def test_container_is_offline_with_readonly_inputs(self):
  argv=d.command('/base','/templates','/out','dsmack-builder','/kernel.tar.xz')
  self.assertEqual(argv[argv.index('--network')+1],'none')
  for dst in ('/w/source','/prior-image','/selected-templates','/derive.sh','/linux.tar.xz'):
   self.assertTrue(any(a.endswith(f'dst={dst},readonly') for a in argv),dst)
 def test_scripts_parse(self):
  for s in ('derive-in-container.sh','source/build/assemble_leg.sh','source/profile/dstack-trixie-arm64-minimal/kernel-cmdline.sh'):subprocess.run(['bash','-n',here/s],check=True)
if __name__=='__main__':unittest.main()
