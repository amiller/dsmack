import json,pathlib,shlex,tempfile,unittest
from unittest.mock import patch
P=pathlib.Path(__file__).parent
scope={'__name__':'progress_test','__file__':str(P/'progress.py')};exec(compile((P/'progress.py').read_bytes(),str(P/'progress.py'),'exec'),scope)
client={'__name__':'client_test','__file__':str(P/'client.py')};exec(compile((P/'client.py').read_bytes(),str(P/'client.py'),'exec'),client)
describe=scope['describe'];NATIVE='b'*32
A={'id':'a'*32,'task_slug':'board-search','candidate_commit':'c'*40,'payee':'0x'+'1'*40,'created_at':1000}
C=scope['commands'](['python3','-I','/opt/r/client.py','--config',"/Users/o'neil/My Config.json"],'/Users/x/ATTEMPT.json','/Users/x/REG.json')
def fs(**k):return {'local_dir':False,'task':False,'control':False,'plan':False,'launch_requested_at':None,'controller':None,'submitted':False,'cleaned':False,**k}
PLAN=dict(local_dir=True,task=True,control=True,plan=True)
run=lambda state,f=None,claim=None,mode='self',now=2000,**a:describe({**A,'state':state,**a},claim,f or fs(),mode,now,C)
stage=lambda *a,**k:run(*a,**k)[0]
class Progress(unittest.TestCase):
 def test_local_milestones_from_real_files(self):
  with tempfile.TemporaryDirectory()as t:
   local=pathlib.Path(t);control=local/('attempt-'+NATIVE+'.control');control.mkdir();(local/'task.json').write_text('{}')
   (control/'plan.json').write_text('{}');(control/'launch-requested.json').write_text('{}')
   read=lambda q:json.loads(q.read_text())
   f=scope['facts'](local,NATIVE,read);self.assertTrue(f['plan']);self.assertIsNotNone(f['launch_requested_at']);self.assertIsNone(f['controller'])
   (control/'controller-result.json').write_text(json.dumps({'controller_returned':False,'error':'TimeoutExpired'}))
   self.assertEqual(scope['facts'](local,NATIVE,read)['controller'],'error:TimeoutExpired')
   self.assertFalse(scope['facts'](local,None,read)['plan'])
 def test_launch_file_is_not_reported_as_running(self):
  s,msg,nxt=run('prepared',fs(**PLAN,launch_requested_at=1900))
  self.assertEqual(s,'launch_requested');self.assertIn('does not show whether the VM is still running',msg);self.assertIn('Do not start run again',nxt['action'])
  # A killed run leaves launch-requested.json without a controller result; relaunch is refused.
  s,_,nxt=run('prepared',fs(**PLAN,launch_requested_at=0),now=5000);self.assertEqual(s,'run_outcome_unknown');self.assertTrue(nxt['stop'])
 def test_controller_error_is_not_ready_to_submit(self):
  self.assertEqual(stage('prepared',fs(**PLAN,launch_requested_at=1900,controller='error:X')),'run_failed')
  self.assertEqual(stage('prepared',fs(**PLAN,launch_requested_at=1900,controller='returned')),'ready_to_submit')
 def test_partial_states_give_retry_commands(self):
  self.assertIn('--resume-download',run('prepared',fs(local_dir=True))[2]['command'])
  s,_,nxt=run('prepared',fs(local_dir=True,task=True));self.assertEqual(s,'local_prepare_incomplete');self.assertFalse(nxt['stop']);self.assertIn(' prepare ',nxt['command'])
  self.assertTrue(run('prepared',fs(local_dir=True,task=True,control=True))[2]['stop'])
  s,_,nxt=run('prepared',fs(**PLAN,controller='returned'),submission_id='d'*32);self.assertEqual(s,'submitting');self.assertIn(' submit ',nxt['command'])
 def test_commands_use_caller_paths_safely_quoted(self):
  cmd=run('registered')[2]['command'];argv=shlex.split(cmd)
  self.assertEqual(argv[4],"/Users/o'neil/My Config.json");self.assertEqual(argv[argv.index('--attempt')+1],'/Users/x/ATTEMPT.json');self.assertEqual(argv[argv.index('--registration')+1],'/Users/x/REG.json')
 def test_best_effort_reports_only_what_service_exposes(self):
  self.assertEqual(stage('queued',mode='best_effort'),'queued_for_preparation')
  self.assertEqual(stage('prepared',mode='best_effort'),'waiting_for_node')
  self.assertEqual(stage('prepared',mode='best_effort',node_lease={'created_at':1400}),'leased_by_node')
 def test_verified_is_not_paid_until_withdrawal_observed(self):
  self.assertEqual(stage('verifying'),'verifying')
  self.assertEqual(stage('verified',claim={'status':'not_requested'}),'verified')
  self.assertEqual(stage('verified',claim={'stage':'withdraw','transactions':{}}),'reward_withdraw')
  self.assertEqual(stage('verified',claim={'stage':'received','payment_received':False}),'reward_received')
  s,msg,nxt=run('verified',claim={'stage':'withdrawal_unobserved','received':False});self.assertEqual(s,'withdrawal_unobserved');self.assertIn('Not paid',msg);self.assertIn('Do not send another withdrawal',nxt['action'])
  s,_,nxt=run('verified',claim={'stage':'gas_grant_pending','transactions':{},'gas_grant':{'status':'pending'}});self.assertEqual(s,'gas_grant_pending');self.assertIn('Check testnet gas grant',nxt['action'])
  # The claim packet can lag the browser's pending wallet request; never tell the user to sign blindly.
  nxt=run('verified',claim={'stage':'submit','transactions':{}})[2]['action'];self.assertIn('do not send it again',nxt);self.assertNotIn('sign',nxt.lower())
  self.assertEqual(stage('verified',claim={'stage':'received','payment_received':True}),'paid')
  self.assertEqual(stage('claim_uncertain',claim={'status':'uncertain'}),'reward_check_incomplete')
 def test_service_closed_attempts_point_to_status_not_maintainer(self):
  for s in ('preparation_failed','prepareExecution_uncertain','verification_error','verifyEvidence_failed'):
   nxt=run(s)[2];self.assertFalse(nxt['stop'],s);self.assertIn(' status ',nxt['command'])
  self.assertTrue(run('mystery')[2]['stop']);self.assertEqual(stage('failed'),'rejected')
 def test_json_report_carries_human_fields_without_capability(self):
  r=scope['report']({**A,'state':'registered','cap_hash':'secret'},None,fs(),'self',1600,C)
  self.assertEqual({k:r[k] for k in ('stage','task','candidate_commit','payee','elapsed_seconds')},{'stage':'registered','task':'board-search','candidate_commit':A['candidate_commit'],'payee':A['payee'],'elapsed_seconds':600})
  self.assertTrue(r['message'] and r['next']['command']);text=scope['render'](r)
  self.assertNotIn('secret',json.dumps(r)+text);self.assertIn(r['next']['command'],text)

class Recovery(unittest.TestCase):
 PACKET={'native_execution_id':NATIVE,'attempt_id':'a'*32}
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='.progress-',dir=pathlib.Path.home());self.addCleanup(t.cleanup)
  self.local=pathlib.Path(t.name);self.local.chmod(0o700);self.control=self.local/('attempt-'+NATIVE+'.control')
  for name,body in (('task.json','{}'),('execution-packet.json',json.dumps(self.PACKET))):client['exclusive'](self.local/name,body.encode())
 def prepare(self,packet=None):
  with patch.dict(client['_scope'],{'coordinator':lambda *a:self.calls.append(a) or 0}):
   self.calls=[];return client['existing_preparation']({},packet or self.PACKET,self.local)
 def test_missing_control_reruns_only_coordinator_prepare(self):
  self.assertEqual(self.prepare(),0);self.assertEqual([c[1] for c in self.calls],['prepare'])
  self.assertEqual(self.calls[0][2:],(self.local/'task.json',self.local,NATIVE))
 def test_existing_plan_is_not_prepared_again(self):
  self.control.mkdir();(self.control/'plan.json').write_text('{}')
  self.assertIs(self.prepare(),True);self.assertEqual(self.calls,[])
 def test_uncertain_control_or_other_packet_is_refused(self):
  self.control.mkdir()
  with self.assertRaises(ValueError):self.prepare()
  self.control.rmdir()
  with self.assertRaises(ValueError):self.prepare({**self.PACKET,'attempt_id':'e'*32})
  self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()
