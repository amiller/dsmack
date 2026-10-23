import sys
sys.dont_write_bytecode=True
import base64,copy,hashlib,importlib.util,json,pathlib,sys,tempfile,unittest
HERE=pathlib.Path(__file__).parent;ROOT=HERE.parents[1]
BASE=HERE.parent/'browser-sandbox-v1/source/runner-content'
sys.path[:0]=[str(BASE),str(BASE/'lib')]
from dsmack_compose_contract.runtime_inputs import compute_commitment,validate_runtime_inputs_bytes
spec=importlib.util.spec_from_file_location('public_commitment_channel',HERE/'public_inputs.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Controls(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.r=pathlib.Path(self.t.name);self.public=self.r/'public-inputs';self.public.mkdir();self.private=self.r/'private';self.private.mkdir();self.mf=self.r/'probe.app-compose.json';self.ef=self.public/'probe.envelope.json'
  self.m=json.loads((ROOT/'applications/pilot-client/browser-postrun/fixtures/browser-probe-manifest.json').read_bytes())
  self.e={'runtime_input_version':4,'manifest_sha256':'','files':[{'slot':x['slot'],'content_base64':base64.b64encode(('public-'+x['slot']).encode()).decode()} for x in self.m['allowed_files']]}
  self.write();self.commit()
 def write(self):
  raw=json.dumps(self.m,sort_keys=True,separators=(',',':')).encode();self.mf.write_bytes(raw);self.e['manifest_sha256']=hashlib.sha256(raw).hexdigest();self.ef.write_text(json.dumps(self.e))
 def commit(self):
  self.e['commitments']={'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(x['slot'] for x in self.m['allowed_files'])},'inputs_sha256':'0'*64};self.e['commitments']['inputs_sha256']=compute_commitment(self.e,self.m);self.write()
 def choose(self):return p.choose(self.public,self.mf,self.private)
 def refused(self):
  self.ef.write_text(json.dumps(self.e))
  with self.assertRaises(Exception):self.choose()
 def test_complete_original_commitment(self):
  self.assertEqual(self.choose(),str(self.ef));summary=validate_runtime_inputs_bytes(self.mf.read_bytes(),self.ef.read_bytes());self.assertEqual(summary['commitment'],self.e['commitments'])
 def test_legacy_absent(self):del self.e['commitments'];self.write();self.assertEqual(self.choose(),str(self.ef))
 def test_changed_decoded_file(self):self.e['files'][0]['content_base64']=base64.b64encode(b'tamper').decode();self.refused()
 def test_wrong_digest(self):self.e['commitments']['inputs_sha256']='0'*64;self.refused()
 def test_partial_even_valid_digest(self):
  self.e['commitments']['scope']['file_slots'].pop();self.e['commitments']['inputs_sha256']=compute_commitment(self.e,self.m);self.refused()
 def test_secret_even_valid_digest(self):
  self.e['commitments']['alg']='dsmack.secret-commitment/3';self.e['commitments']['inputs_sha256']=compute_commitment(self.e,self.m);self.refused()
 def test_null_unknown(self):
  for value in [None,{}, {'alg':'other'}, {**self.e['commitments'],'extra':True}]:
   self.e['commitments']=value;self.refused()
 def test_optional_declared_slot(self):self.m['allowed_files'][0]['required']=False;self.write();self.commit();self.refused()
 def test_empty_files(self):self.m['allowed_files']=[];self.e['files']=[];self.write();self.refused()
 def test_env_scope(self):self.e['commitments']['scope']={'include':['env'],'env_names':['INJECT']};self.refused()
 def test_extra_scope_slot(self):self.e['commitments']['scope']['file_slots'].append('unknown');self.refused()
 def test_broker_still_refused(self):self.m['allowed_files'][0]['audience']='broker';self.write();self.refused()
 def test_private_competitor(self):
  (self.private/'envelopes').mkdir();(self.private/'envelopes'/self.ef.name).write_text('{}');self.refused()
 def test_wrong_manifest(self):self.e['manifest_sha256']='0'*64;self.refused()
if __name__=='__main__':unittest.main()
