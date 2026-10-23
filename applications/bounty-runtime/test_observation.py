import tempfile
from pathlib import Path
import unittest
from observation import observation,compare_observation,append_observation
from source_bundle import protocol as p
import test_audit_stage as fixtures
from audit_stage import audit
from project import project

class ObservationControls(unittest.TestCase):
    def test_independent_compare_and_bounded_closed_manifest(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,pins=fixtures.AuditControls().fixture(root);result=audit(paths,*pins)
            projection=project(result,root/'projection');expected=observation(result,projection)
            raw=p.canonical_json(expected);self.assertEqual(compare_observation(raw,result,projection),expected)
            for key in ('request_sha256','source_tree_sha256','stage_profile_sha256','plan_sha256','driver_sha256','projection_sha256'):
                changed={**expected,key:'f'*64}
                with self.assertRaises(ValueError):compare_observation(p.canonical_json(changed),result,projection)
            with self.assertRaises(ValueError):observation({**result,'input_bytes':{}},projection)
            output=root/'output';output.mkdir();(output/'checks.json').write_bytes(b'{}')
            files=append_observation(output,result,projection)
            self.assertEqual([f['name']for f in files],['checks.json','public-input-audit.json'])
            self.assertNotIn('output-manifest.json',[f['name']for f in files])
            self.assertNotIn('verified',expected);self.assertNotIn('authorized',expected)
    def test_missing_child_output_and_existing_observation_refuse(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,pins=fixtures.AuditControls().fixture(root);result=audit(paths,*pins);projection={}
            with self.assertRaises(ValueError):append_observation(root/'absent',result,projection)
            output=root/'output';output.mkdir();(output/'public-input-audit.json').write_bytes(b'old')
            with self.assertRaises(FileExistsError):append_observation(output,result,projection)


    def test_dangling_manifest_link_never_creates_target(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);paths,pins=fixtures.AuditControls().fixture(root);result=audit(paths,*pins)
            output=root/'output';output.mkdir();target=root/'outside'
            (output/'output-manifest.json').symlink_to(target)
            with self.assertRaises(OSError):append_observation(output,result,{})
            self.assertFalse(target.exists())

if __name__=='__main__':unittest.main()
