import copy,io,json,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'applications/bounty-runtime'),str(Path(__file__).parent)]
import core
from test_source_bundle import fixture
p=core.p
sha=core.sha

class DevelopControls(unittest.TestCase):
    def inputs(self,root):
        bundle,manifest,tree=fixture({n:b'base'for n in core.source.BOARD})
        spec={'text':'Implement search','sha256':sha(b'Implement search')}
        profile={'schema':'dsmack-bounty-develop-profile/1','model':core.MODEL,'seconds':480,'turns':30,'tools':core.TOOLS,'specification':spec}
        raw={'task_terms':b'{}','acceptance_profile':b'{}','plan':b'{}','driver':b'measured source','stage_profile':p.canonical_json(profile),'source_manifest':manifest,'source_bundle':bundle}
        request={'schema':p.REQUEST_SCHEMA,'task_id':'task','task_terms_sha256':sha(raw['task_terms']),'attempt_id':'attempt','attempt_nonce':'0'*64,'run_id':'develop','run_role':'develop','acceptance_profile_sha256':sha(raw['acceptance_profile']),'base':{'repo':'https://github.com/amiller/bounty-arcade','commit':'1'*40,'tree_manifest_sha256':tree},'candidate':None,'toolchain':{'platform':'linux/arm64','image_digest':'sha256:'+'2'*64},'required_artifacts':['public-input-audit','result-files','stage-checks']}
        raw['request']=p.canonical_json(request);paths={n:None for n in core.SLOTS}
        for n,b in raw.items():paths[n]=root/n;paths[n].write_bytes(b)
        return paths,[sha(request['schema'].encode()+b'\0'+raw['request']),sha(raw['stage_profile']),sha(raw['driver']),sha(raw['plan'])]
    def test_typed_develop_fullbase_and_capture(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,expected=self.inputs(root);result=core.audit(paths,*expected);projection=core.materialize(result,root/'repo')
            self.assertEqual(set(projection),set(core.source.BOARD))
            with self.assertRaises(ValueError):core.capture(root/'repo',result)
            (root/'repo'/core.source.BOARD[0]).write_bytes(b'fresh authored change')
            bundle,manifest,relation=core.capture(root/'repo',result)
            self.assertEqual(relation['changed_files'],[core.source.BOARD[0]])
            self.assertEqual(core.source.decode_source(bundle,manifest,relation['candidate_tree_manifest_sha256'])[0],p.parse_json(manifest))
    def test_pins_tampered_source_suite_refuse(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,expected=self.inputs(root)
            for i in range(4):
                altered=list(expected);altered[i]='f'*64
                with self.assertRaises(ValueError):core.audit(paths,*altered)
            paths['suite']=paths['plan']
            with self.assertRaises(ValueError):core.audit(paths,*expected)
            paths['suite']=None;paths['source_bundle'].write_bytes(bytes(1024))
            with self.assertRaises(ValueError):core.audit(paths,*expected)
    def test_wrong_policy_refuses_even_with_matching_profile_pin(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,expected=self.inputs(root);original=p.parse_json(paths['stage_profile'].read_bytes())
            for key,value in [('model','opus'),('turns',31),('seconds',481),('tools','Bash')]:
                profile={**original,key:value};raw=p.canonical_json(profile);paths['stage_profile'].write_bytes(raw);expected[1]=sha(raw)
                with self.assertRaises(ValueError):core.audit(paths,*expected)
    def test_nonallowlisted_or_added_candidate_refuses(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,e=self.inputs(root);result=core.audit(paths,*e);core.materialize(result,root/'repo');(root/'repo/extra').write_bytes(b'extra')
            with self.assertRaises(ValueError):core.capture(root/'repo',result)
    def events(self):
        return [{'type':'system','subtype':'init','model':core.MODEL},{'type':'assistant','message':{'model':core.MODEL,'content':[{'type':'tool_use','name':'Edit','input':{'unused':'not authority'}}]}},{'type':'result','subtype':'success','is_error':False,'num_turns':3,'modelUsage':{core.MODEL:{'costUSD':.1}}}]
    def test_model_observation_and_exact_tools_budget(self):
        events=self.events();raw=b'\n'.join(json.dumps(e).encode()for e in events);self.assertEqual(core.observe(raw)['tools'],['Edit'])
        for i,key,value in [(0,'model','opus'),(2,'num_turns',31),(2,'modelUsage',{'other':{}}),(2,'is_error',True)]:
            bad=copy.deepcopy(events);bad[i][key]=value
            with self.assertRaises(ValueError):core.observe(b'\n'.join(json.dumps(e).encode()for e in bad))
        bad=self.events();bad[1]['message']['content'][0]['name']='WebFetch'
        with self.assertRaises(ValueError):core.observe(b'\n'.join(json.dumps(e).encode()for e in bad))
        argv=core.command(Path('/usr/local/bin/claude'),'task');self.assertNotIn('--dangerously-skip-permissions',argv);self.assertIn(core.MODEL,argv);self.assertIn('30',argv)
    def test_namespace_members_live_zombie_and_foreign_uid(self):
        with tempfile.TemporaryDirectory()as directory:
            proc=Path(directory)
            for pid,state in [(1,'S'),(2,'S'),(3,'Z')]:
                d=proc/str(pid);d.mkdir();(d/'status').write_text('Uid:\t1000 1000 1000 1000\nState:\t'+state+' (state)\n')
            self.assertEqual(core.namespace_members(proc,self_pid=1,uid=1000),[2])
            (proc/'2/status').write_text('Uid:\t0 0 0 0\nState:\tS (state)\n')
            with self.assertRaises(ValueError):core.namespace_members(proc,self_pid=1,uid=1000)
    def test_nondumpable_parent_guard_set_and_get(self):
        with self.assertRaises(ValueError):core.protect_parent()
        for observation,ok in [(0,True),(1,False)]:
            lib=MagicMock();lib.prctl.side_effect=[0,observation]
            with patch.object(core.os,'getpid',return_value=1),patch.object(core.os,'getuid',return_value=1000),patch.object(core.ctypes,'CDLL',return_value=lib):
                if ok:core.protect_parent()
                else:
                    with self.assertRaises(ValueError):core.protect_parent()
            self.assertEqual(lib.prctl.call_args_list[0].args,(4,0,0,0,0));self.assertEqual(lib.prctl.call_args_list[1].args,(3,0,0,0,0))
    def test_host_quiesce_refuses(self):
        with self.assertRaises(ValueError):core.quiesce()

if __name__=='__main__':unittest.main()
