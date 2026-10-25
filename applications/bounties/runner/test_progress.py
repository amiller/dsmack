import json,pathlib,tempfile,unittest
P=pathlib.Path(__file__).parent
scope={'__name__':'progress_test','__file__':str(P/'progress.py')};exec(compile((P/'progress.py').read_bytes(),str(P/'progress.py'),'exec'),scope)
describe=scope['describe'];NATIVE='b'*32
A={'id':'a'*32,'candidate_commit':'c'*40,'payee':'0x'+'1'*40,'created_at':1000}
def fs(**k):return {'task':False,'plan':False,'launched_at':None,'controller':None,'submitted':False,'cleaned':False,**k}
stage=lambda state,f=None,claim=None,mode='self',now=2000,**a:describe({**A,'state':state,**a},claim,f or fs(),mode,now)[0]
class Progress(unittest.TestCase):
 def test_local_milestones_from_real_files(self):
  with tempfile.TemporaryDirectory()as t:
   local=pathlib.Path(t);control=local/('attempt-'+NATIVE+'.control');control.mkdir()
   for name in ('task.json',):(local/name).write_text('{}')
   (control/'plan.json').write_text('{}');(control/'launch-requested.json').write_text('{}')
   read=lambda q:json.loads(q.read_text())
   f=scope['facts'](local,NATIVE,read);self.assertTrue(f['plan']);self.assertIsNotNone(f['launched_at']);self.assertIsNone(f['controller'])
   (control/'controller-result.json').write_text(json.dumps({'controller_returned':False,'error':'TimeoutExpired'}))
   self.assertEqual(scope['facts'](local,NATIVE,read)['controller'],'error:TimeoutExpired')
   self.assertFalse(scope['facts'](local,None,read)['plan'])
 def test_run_phases_are_distinct(self):
  self.assertEqual(stage('prepared'),'downloading')
  self.assertEqual(stage('prepared',fs(task=True,plan=True)),'ready_to_run')
  self.assertEqual(stage('prepared',fs(task=True,plan=True,launched_at=1900)),'executing')
 def test_stale_launch_is_not_reported_as_executing(self):
  # A killed run leaves launch-requested.json without a controller result; relaunch is refused.
  stage_,_,nxt=describe({**A,'state':'prepared'},None,fs(task=True,plan=True,launched_at=0),'self',5000)
  self.assertEqual(stage_,'run_interrupted');self.assertEqual(nxt,scope['STOP'])
 def test_controller_error_is_not_ready_to_submit(self):
  self.assertEqual(stage('prepared',fs(task=True,plan=True,launched_at=1900,controller='error:X')),'run_failed')
  self.assertEqual(stage('prepared',fs(task=True,plan=True,launched_at=1900,controller='returned')),'ready_to_submit')
 def test_partial_upload_points_back_to_submit(self):
  self.assertEqual(stage('prepared',fs(task=True,plan=True,controller='returned'),submission_id='d'*32),'submitting')
 def test_best_effort_participant_has_nothing_to_run(self):
  self.assertEqual(stage('prepared',mode='best_effort'),'node_running')
  self.assertEqual(stage('prepared',mode='best_effort',submission_id='d'*32),'node_running')
 def test_verified_is_not_paid_until_withdrawal_observed(self):
  self.assertEqual(stage('verifying'),'verifying')
  self.assertEqual(stage('verified',claim={'status':'not_requested'}),'verified')
  self.assertEqual(stage('verified',claim={'stage':'withdraw','transactions':{}}),'reward_withdraw')
  self.assertEqual(stage('verified',claim={'stage':'received','payment_received':False}),'verified')
  self.assertEqual(stage('verified',claim={'stage':'received','payment_received':True}),'paid')
  self.assertEqual(stage('claim_uncertain',claim={'status':'uncertain'}),'reward_check_incomplete')
 def test_failures_stop(self):
  for s in ('preparation_failed','prepareExecution_uncertain','verification_error','verifyEvidence_failed','mystery'):
   self.assertEqual(describe({**A,'state':s},None,fs(),'self',2000)[2],scope['STOP'],s)
  self.assertEqual(stage('failed'),'rejected')
 def test_render_omits_capability(self):
  _,text=scope['render']({**A,'state':'registered','cap_hash':'secret'},None,fs(),'self',1600)
  self.assertNotIn('secret',text);self.assertIn('Elapsed   10 min',text);self.assertIn(A['payee'],text)
if __name__=='__main__':unittest.main()
