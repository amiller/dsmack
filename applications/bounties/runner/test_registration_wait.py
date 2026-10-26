import contextlib,io,unittest
from pathlib import Path
s=Path(__file__).with_name('client.py');C={'__name__':'arcade_client','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),C)
RID='a'*32;KEY='+hToe57RLIP+JNhsdbJZsTr4FqOwdzTtqQCv7YiGUVI=';RECORD={'registration_id':RID,'key_id':KEY,'node_capability':'x'*43}

class API:
    def __init__(self,replies):self.replies=list(replies);self.calls=[]
    def request(self,method,path,body=None,capability=None):
        self.calls.append((method,path,body));r=self.replies.pop(0) if len(self.replies)>1 else self.replies[0];return {'registration_id':RID,**r}

class Clock:
    def __init__(self):self.t=0.0
    def __call__(self):return self.t
    def sleep(self,d):self.t+=d

def wait(api,seconds,record=RECORD):
    c=Clock()
    with contextlib.redirect_stderr(io.StringIO()):return C['register_wait'](api,record,seconds,clock=c,sleep=c.sleep),c.t

class RegistrationWait(unittest.TestCase):
    def test_queued_then_enrolled_with_this_key_is_ready(self):
        api=API([{'state':'challenged','pending_job_id':'j'},{'state':'enrolled','enrollment':{'registered_key_id':KEY}}])
        r,_=wait(api,60);self.assertEqual(r,{'registration_id':RID,'state':'enrolled','ready':True,'can_prepare':True})
        self.assertTrue(all(m=='GET' and p==f'/api/registrations/{RID}' and b is None for m,p,b in api.calls))

    def test_enrolled_with_another_key_is_refused(self):
        with self.assertRaisesRegex(ValueError,'key other than'):wait(API([{'state':'enrolled','enrollment':{'registered_key_id':'other'}}]),0)

    def test_timeout_is_pending_not_failure_and_only_gets(self):
        api=API([{'state':'challenged','pending_job_id':'j'}]);r,t=wait(api,10)
        self.assertEqual((r['ready'],r['can_prepare'],r['pending'],r['state']),(False,False,True,'challenged'));self.assertEqual(t,10)
        self.assertEqual({(m,b)for m,_,b in api.calls},{('GET',None)});self.assertEqual(len(api.calls),6)

    def test_terminal_states_refuse(self):
        for s in ('failed','uncertain'):
            with self.assertRaisesRegex(ValueError,'do not enroll or sign again'):wait(API([{'state':s}]),30)

    def test_wait_bounds_and_identity(self):
        for bad in (-1,301):
            with self.assertRaises(ValueError):wait(API([{'state':'challenged'}]),bad)
        with self.assertRaisesRegex(ValueError,'registration identity'):wait(API([{'state':'challenged'}]),0,{**RECORD,'registration_id':'../x'})

class CLI(unittest.TestCase):
    def test_status_is_get_only_and_register_refuses_saved_record(self):
        import json,sys,tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory(prefix='.rw-',dir=Path.home())as t:
            t=Path(t);t.chmod(0o700);(t/'s').mkdir(mode=0o700)
            for name,v in (('client.json',{'api_url':'https://pilot.example','state_dir':str(t/'s')}),('REGISTRATION.json',{'response':{},**RECORD})):
                (t/name).write_text(json.dumps(v));(t/name).chmod(0o600)
            api=API([{'state':'challenged','pending_job_id':'j'}]);base=['client.py','--config',str(t/'client.json')]
            for _ in range(2):
                out=io.StringIO()
                with mock.patch.dict(C,{'API':lambda *a:api}),mock.patch.object(sys,'argv',base+['registration-status','--registration',str(t/'REGISTRATION.json')]),contextlib.redirect_stdout(out),contextlib.redirect_stderr(io.StringIO()):C['main']()
                r=json.loads(out.getvalue());self.assertEqual((r['ready'],r['state']),(False,'challenged'));self.assertIn('registration-status --registration '+str(t/'REGISTRATION.json'),r['next'])
            self.assertEqual({(m,b)for m,_,b in api.calls},{('GET',None)})
            argv=base+['register','--authorization','/x','--wallet-signature','/y','--out',str(t/'REGISTRATION.json'),'--wait-seconds','30']
            with mock.patch.dict(C,{'API':lambda *a:api}),mock.patch.object(sys,'argv',argv),contextlib.redirect_stderr(io.StringIO()),self.assertRaisesRegex(ValueError,'already saved'):C['main']()
            self.assertEqual(len(api.calls),2)
