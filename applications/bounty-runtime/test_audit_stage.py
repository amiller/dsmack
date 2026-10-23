import tempfile
from pathlib import Path
import unittest
from source_bundle import protocol as p, sha, BOARD
from test_source_bundle import fixture
from audit_stage import audit, SLOTS
from project import project


class AuditControls(unittest.TestCase):
    def fixture(self, root):
        bundle,manifest,tree=fixture({name:b'plain nonexecutable text' for name in BOARD})
        profile={'specification':{'text':'check search','sha256':sha(b'check search')},'admission_transform':None}
        raw={'task_terms':b'{}','acceptance_profile':b'{}','plan':b'{}','stage_profile':p.canonical_json(profile),
             'driver':b'# trusted app bootstrap','source_manifest':manifest,'source_bundle':bundle}
        request={'schema':'dsmack-bounty-child-request/1','task_id':'task','task_terms_sha256':sha(raw['task_terms']),
                 'acceptance_profile_sha256':sha(raw['acceptance_profile']),'plan_sha256':sha(raw['plan']),
                 'attempt_id':'attempt','attempt_nonce':'0'*64,'payee':'0x0000000000000000000000000000000000000001',
                 'run_id':'run','stage_id':'gen-1','role':'generate','judge_index':1,
                 'stage_profile_sha256':sha(raw['stage_profile']),'oci_manifest_sha256':'1'*64,
                 'source_tree_sha256':tree,'input_suite_sha256':None,'requested_model':'opus-4.8'}
        raw['request']=p.canonical_json(request)
        paths={key:None for key in SLOTS}
        for key,data in raw.items():paths[key]=root/key;paths[key].write_bytes(data)
        expected=(sha(request['schema'].encode()+b'\0'+raw['request']),sha(raw['stage_profile']),sha(raw['driver']),sha(raw['plan']))
        return paths,expected
    def test_generation_projects_closed_public_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);paths,expected=self.fixture(root)
            result=audit(paths,*expected)
            projection=project(result,root/'projected')
            self.assertEqual(sorted(projection),['base.json','spec.txt'])
            self.assertEqual(result['source_tree_sha256'],result['request']['source_tree_sha256'])
    def test_independent_pins_and_source_tampering_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);paths,expected=self.fixture(root)
            for index in range(4):
                changed=list(expected);changed[index]='f'*64
                with self.assertRaises(ValueError):audit(paths,*changed)
            paths['source_bundle'].write_bytes(bytes(1024))
            with self.assertRaises(ValueError):audit(paths,*expected)
    def test_suite_and_path_substitution_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);paths,expected=self.fixture(root)
            paths['suite']=root/'suite';paths['suite'].write_bytes(b'{}')
            with self.assertRaises(ValueError):audit(paths,*expected)
            paths['suite']=None;paths['driver']=paths['plan']
            with self.assertRaises(ValueError):audit(paths,*expected)

if __name__=='__main__':unittest.main()

class ProjectionControls(unittest.TestCase):
    def test_primary_keeps_full_source_and_original_delivery(self):
        from project import retain_delivery
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            files={'apps/board/index.html':b'html','apps/other/fixture.gpx':b'<gpx/>','README.md':b'docs'}
            bundle,raw,tree=fixture(files)
            result={'role':'primary-review','source_files':files,'source_manifest':p.parse_json(raw),
                    'input_bytes':{'source_bundle':bundle,'source_manifest':raw}}
            projection=project(result,root/'projection')
            self.assertEqual(set(projection),set(files))
            self.assertEqual((root/'projection/apps/other/fixture.gpx').read_bytes(),b'<gpx/>')
            retain_delivery(result,root/'delivery')
            self.assertEqual((root/'delivery/source-delivery.tar').read_bytes(),bundle)
