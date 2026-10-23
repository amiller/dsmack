import json,unittest
import prepare_generation_reliability as p
class TestPacket(unittest.TestCase):
 def ref(self):
  return p.canonical({'docker_compose_file':json.dumps({'services':{'old':{'image':'x@sha256:'+p.IMAGE}}}),'network':{'mode':'nat','listen_ports':[]},'harness':{'sha256':'304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc'}})
 def test_closed_transport_and_outputs(self):
  m=p.configure(self.ref(),b'd',b'b',b's','a'*64);c=json.loads(m['docker_compose_file'])['services']['diagnostic']
  self.assertEqual(m['limits']['timeout_s'],550)
  self.assertEqual([r['slot'] for r in m['allowed_files']],['driver','base','spec'])
  self.assertEqual(c['command'],['/workspace/inputs/driver','--public','/workspace/inputs','--flat-public','--snapshot-sha256','a'*64])
  self.assertEqual(m['outputs']['artifacts'],[{'name':'generation-reliability','path':'/workspace/artifacts/generation-reliability.json'}])
  self.assertTrue(all(v.endswith(':ro') for v in c['volumes'][:3]))
 def test_unknown_image_refused(self):
  r=json.loads(self.ref());r['docker_compose_file']=r['docker_compose_file'].replace(p.IMAGE,'0'*64)
  with self.assertRaises(ValueError):p.configure(p.canonical(r),b'd',b'b',b's','a'*64)
 def test_network_refused(self):
  r=json.loads(self.ref());r['network']['mode']='none'
  with self.assertRaises(ValueError):p.configure(p.canonical(r),b'd',b'b',b's','a'*64)
 def test_harness_refused(self):
  r=json.loads(self.ref());r['harness']['sha256']='0'*64
  with self.assertRaises(ValueError):p.configure(p.canonical(r),b'd',b'b',b's','a'*64)
if __name__=='__main__':unittest.main()
