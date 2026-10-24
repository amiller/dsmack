import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import protocol


def request():
    # Synthetic interface fixture only; not funded or authenticated evidence.
    return {'schema':protocol.REQUEST_SCHEMA,'task_id':'synthetic-board-search',
        'task_terms_sha256':'1'*64,'attempt_id':'synthetic-assignment','attempt_nonce':'2'*64,
        'run_id':'synthetic-review-1','run_role':'review','acceptance_profile_sha256':'3'*64,
        'base':{'repo':'https://github.com/amiller/bounty-arcade','commit':'4'*40,'tree_manifest_sha256':'5'*64},
        'candidate':{'upstream_commit':'6'*40,'tree_manifest_sha256':'7'*64,'admission_transform_sha256':'8'*64},
        'toolchain':{'platform':'linux/arm64','image_digest':'sha256:'+'9'*64},
        'required_artifacts':['acceptance-report','browser-trace','browser-video','public-input-audit']}


class ProtocolTests(unittest.TestCase):
    def test_independent_node_crosschecked_golden_fixture(self):
        fixture=json.loads((Path(__file__).with_name('protocol.synthetic.json')).read_text())
        self.assertEqual('03cbd0538544d76b2cf1ef165c0af84527fbcca5aa0c263682cf66d8d2c0140c',protocol.request_digest(fixture['request']))
        self.assertEqual('e5b9c7f5a1c11e2ebda9d412ccb6ff5aeb56ae8a621816a60fd2c7395b962967',protocol.tree_digest(fixture['tree_manifest']))

    def test_review_and_develop_have_distinct_identities(self):
        review=request();develop=copy.deepcopy(review);develop.update(run_role='develop',run_id='synthetic-develop-1',candidate=None)
        self.assertNotEqual(protocol.request_digest(review),protocol.request_digest(develop))
        self.assertEqual(review,protocol.validate_request(review))
        self.assertEqual(develop,protocol.validate_request(develop))

    def test_unknown_authority_flags_and_ambiguous_numbers_rejected(self):
        for value in (True,1.5,float('nan'),(1<<53)):
            with self.assertRaises(ValueError):protocol.canonical_json({'value':value})
        bad=request();bad['verified']=True
        with self.assertRaises(ValueError):protocol.validate_request(bad)
        with self.assertRaises(ValueError):protocol.parse_json(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):protocol.parse_json(b'{"x":NaN}')

    def test_all_public_bindings_change_request_digest(self):
        original=request();expected=protocol.request_digest(original)
        for field in ('task_terms_sha256','attempt_nonce','acceptance_profile_sha256'):
            altered=copy.deepcopy(original);altered[field]='a'*64
            self.assertNotEqual(expected,protocol.request_digest(altered))
        for parent,field,length in [('base','commit',40),('base','tree_manifest_sha256',64),
                                   ('candidate','tree_manifest_sha256',64),('candidate','admission_transform_sha256',64)]:
            altered=copy.deepcopy(original);altered[parent][field]='b'*length
            self.assertNotEqual(expected,protocol.request_digest(altered))

    def test_malformed_profile_and_artifact_ambiguity_rejected(self):
        for patch in ({'run_role':'unknown'},{'candidate':None},{'required_artifacts':['browser-video','browser-trace']},
                      {'required_artifacts':['browser-video','browser-video']}):
            bad=request();bad.update(patch)
            with self.assertRaises(ValueError):protocol.validate_request(bad)
        bad=request();bad['toolchain']['platform']='linux/amd64'
        with self.assertRaises(ValueError):protocol.validate_request(bad)

    def test_source_bytes_mode_and_names_are_bound(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'app.js';p.write_text('original');p.chmod(0o644)
            first=protocol.tree_digest(protocol.scan_tree(d));p.chmod(0o755)
            second=protocol.tree_digest(protocol.scan_tree(d));self.assertNotEqual(first,second)
            p.write_text('changed');third=protocol.tree_digest(protocol.scan_tree(d));self.assertNotEqual(second,third)
            p.rename(Path(d)/'other.js');self.assertNotEqual(third,protocol.tree_digest(protocol.scan_tree(d)))

    def test_history_symlinks_traversal_and_duplicate_entries_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file.js';p.write_text('data');p.chmod(0o644)
            m=protocol.scan_tree(d)
            with self.assertRaises(ValueError):protocol.tree_digest(m+m)
            bad=copy.deepcopy(m);bad[0]['path']='../escape'
            with self.assertRaises(ValueError):protocol.tree_digest(bad)
            bad=copy.deepcopy(m);bad[0]['path']='.'
            with self.assertRaises(ValueError):protocol.tree_digest(bad)
            bad=copy.deepcopy(m);bad[0]['path']='a'
            conflict=copy.deepcopy(bad[0]);conflict['path']='a/b'
            with self.assertRaises(ValueError):protocol.tree_digest(bad+[conflict])
            (Path(d)/'alias.js').symlink_to(p)
            with self.assertRaises(ValueError):protocol.scan_tree(d)
            (Path(d)/'alias.js').unlink();(Path(d)/'.git').mkdir()
            with self.assertRaises(ValueError):protocol.scan_tree(d)


if __name__=='__main__':unittest.main()
