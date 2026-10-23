import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'applications/bounty-judges'),str(ROOT/'applications/bounty-runtime'),str(Path(__file__).parent)]
import main
import test_core
from output_bundle import decode

class MainControls(unittest.TestCase):
    def run_case(self,failed=False,dirty=False):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);inputs=root/'inputs';inputs.mkdir();state=root/'state';state.mkdir();out=root/'artifacts';out.mkdir();helper=test_core.DevelopControls();paths,expected=helper.inputs(inputs)
            def mapped(value):
                text=str(value)
                if text.startswith('/workspace/'):return root/text[len('/workspace/'):]
                return Path(value)
            calls=[]
            def process(argv,data,cwd,env,*limits):
                if '--version'in argv:return b'2.1.187 (Claude Code)\n',b'',0,None
                calls.append('cli');(Path(cwd)/'apps/board/index.html').write_bytes(b'new authored source')
                if dirty:(out/'checks.json').symlink_to(root/'state/forged')
                raw=b'\n'.join(json.dumps(e).encode()for e in helper.events())
                return raw,b'',1 if failed else 0,None
            argv=['driver']
            for n,v in zip(('request','stage-profile','driver','plan'),expected):argv+=['--expected-'+n+'-sha256',v]
            with patch.object(sys,'argv',argv),patch.object(main,'Path',mapped),patch.object(main.os,'getuid',return_value=1000),patch.object(main.os,'getgid',return_value=1000),patch.object(main.os,'getpid',return_value=1),patch.object(main.qualified,'file_sha',return_value=main.qualified.CLI_SHA256),patch.object(main.qualified,'runtime_environment',return_value=(state,{})),patch.object(main.qualified,'bounded_process',side_effect=process),patch.object(main.core,'quiesce',side_effect=lambda:calls.append('quiesce')),patch.object(main.core,'protect_parent',side_effect=lambda:calls.append('protected')):
                if dirty:
                    with self.assertRaises(ValueError):main.main()
                    self.assertFalse((out/'result-files.tar').exists());self.assertFalse((state/'forged').exists());return
                rc=main.main()
            checks=json.loads((out/'checks.json').read_bytes());manifest,files=decode((out/'result-files.tar').read_bytes());self.assertEqual(files['checks.json'],(out/'checks.json').read_bytes());self.assertIn('public-input-audit.json',files)
            self.assertEqual(calls[:3],['protected','cli','quiesce']);self.assertEqual(checks['completed'],not failed);self.assertEqual(rc,2 if failed else 0)
            self.assertEqual('source-delivery.tar'in files,not failed)
    def test_complete_model_work_and_capture(self):self.run_case()
    def test_cli_nonzero_is_infrastructure_not_success(self):self.run_case(True)
    def test_child_precreated_artifact_link_refuses_before_publication(self):self.run_case(dirty=True)
if __name__=='__main__':unittest.main()
