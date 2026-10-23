"""Synthetic contract controls; never claimed as genuine execution evidence."""
import copy
import unittest
import closure as c


def fixture():
    h = lambda text: c.sha(text.encode())
    expected = {'plan_sha256': h('plan'), 'primary_request_sha256': h('primary-review-request'),
                'task_terms_sha256': h('terms'), 'attempt_id': 'attempt-1', 'attempt_nonce': 'nonce-1',
                'base_tree_sha256': h('base'), 'candidate_tree_sha256': h('candidate'),
                'requested_model': 'explicit-model', 'stages': []}
    result = {k: v for k, v in expected.items() if k != 'requested_model'}
    result['schema'] = c.RESULT_SCHEMA
    result['stages'] = []
    verified = {}
    for stage in c.STAGES:
        role = 'primary-review' if stage == 'primary-review' else stage.rsplit('-', 1)[0]
        i = None if role == 'primary-review' else int(stage[-1])
        suite = c.canonical({'schema': 'dsmack-bounty-browser-suite/1', 'tests': [{'id': 'judge-'+str(i)+'-assertion'}]})
        pin = {'stage_id': stage, 'role': role, 'judge_index': i, 'run_id': stage+'-run',
               'request_sha256': h(stage+'-request'), 'stage_profile_sha256': h(role+'-profile'),
               'oci_manifest_sha256': h('generator-image' if role == 'generate' else 'browser-image'),
               'source_tree_sha256': h('base' if role in ('generate', 'base') else 'candidate')}
        expected['stages'].append(pin)
        files = {}
        if role == 'generate':
            checks = {'schema': 'dsmack-bounty-generation-checks/1', 'completed': True,
                      'requested_model': 'explicit-model', 'observed_model': 'explicit-model',
                      'suite_sha256': c.sha(suite), 'base_tree_sha256': h('base')}
            files['suite.json'] = suite
        elif role == 'primary-review':
            checks = {'schema': 'dsmack-bounty-primary-checks/1',
                      'fixed_browser_baselines': [True]*4, 'fixed_logic_baselines': [True]*4,
                      'feature_checks': [True]*6}
        else:
            checks = {'schema': 'dsmack-bounty-ci-checks/1', 'browser_started': True,
                      'completed': True, 'infrastructure_failed': False,
                      'tests': [{'id': 'judge-'+str(i)+'-assertion', 'status': 'assertion_failed' if role == 'base' else 'passed'}], 'suite_sha256': c.sha(suite)}
        files['checks.json'] = c.canonical(checks)
        manifest = c.canonical({'schema': 'dsmack-bounty-output-manifest/1', 'files': [
            {'name': name, 'size': len(raw), 'sha256': c.sha(raw)} for name, raw in sorted(files.items())]})
        row = dict(pin, input_suite_sha256=c.sha(suite) if role in ('base', 'candidate') else None,
                   output_manifest_sha256=c.sha(manifest), checks_sha256=c.sha(files['checks.json']),
                   execution_evidence_sha256=h(stage+'-evidence'),
                   status='assertion_failed' if role == 'base' else 'completed')
        result['stages'].append(row)
        verified[row['execution_evidence_sha256']] = c.VerifiedOutputs(manifest, files, row['status'])
    def verifier(pin, digest):
        # Simulated trusted boundary for these synthetic tests only.
        if not any(pin == row for row in expected['stages']):
            raise ValueError('wrong expected request')
        return verified[digest]
    return expected, result, verified, verifier


def rewrite_output(result, verified, stage, change):
    row = next(row for row in result['stages'] if row['stage_id'] == stage)
    old = verified[row['execution_evidence_sha256']]
    files = dict(old.files)
    checks = c.parse(files['checks.json'])
    change(checks)
    files['checks.json'] = c.canonical(checks)
    manifest = c.canonical({'schema': 'dsmack-bounty-output-manifest/1', 'files': [
        {'name': n, 'size': len(raw), 'sha256': c.sha(raw)} for n, raw in sorted(files.items())]})
    row['checks_sha256'] = c.sha(files['checks.json'])
    row['output_manifest_sha256'] = c.sha(manifest)
    verified[row['execution_evidence_sha256']] = c.VerifiedOutputs(manifest, files, row['status'])


class ClosureTests(unittest.TestCase):
    def test_complete_synthetic_graph_and_hashes(self):
        expected, result, _, verifier = fixture()
        verdict = c.join(c.canonical(result), expected, verifier)
        self.assertIs(verdict['accepted'], True)
        self.assertEqual(verdict['acceptance_results_sha256'], c.sha(c.RESULT_SCHEMA.encode()+b'\0'+c.canonical(result)))
        changed = copy.deepcopy(result); changed['attempt_nonce'] = 'another'
        with self.assertRaises(ValueError): c.join(c.canonical(changed), expected, verifier)

    def test_missing_duplicate_unsorted_and_cross_attempt(self):
        for mode in ('missing', 'duplicate', 'unsorted', 'wrong-run', 'image', 'source', 'profile'):
            with self.subTest(mode=mode):
                expected, result, _, verifier = fixture()
                if mode == 'missing': result['stages'].pop()
                elif mode == 'duplicate': result['stages'][1] = result['stages'][0]
                elif mode == 'unsorted': result['stages'].reverse()
                else:
                    field = {'wrong-run': 'run_id', 'image': 'oci_manifest_sha256', 'source': 'source_tree_sha256', 'profile': 'stage_profile_sha256'}[mode]
                    result['stages'][0][field] = '0'*64
                with self.assertRaises(ValueError): c.join(c.canonical(result), expected, verifier)

    def test_full_verifier_required_for_every_run(self):
        for bad in (None, True, {'verified': True}):
            expected, result, _, _ = fixture()
            with self.assertRaises(ValueError): c.join(c.canonical(result), expected, lambda *_: bad)
        expected, result, _, verifier = fixture()
        calls = []
        def last_refuses(pin, digest):
            calls.append(pin['stage_id'])
            if pin['stage_id'] == 'primary-review': raise ValueError('invalid original evidence')
            return verifier(pin, digest)
        with self.assertRaises(ValueError): c.join(c.canonical(result), expected, last_refuses)
        self.assertEqual(len(calls), 10)

    def test_authenticated_workload_outcome_and_full_test_membership(self):
        expected, result, verified, verifier = fixture()
        row = next(r for r in result['stages'] if r['stage_id'] == 'base-1')
        out = verified[row['execution_evidence_sha256']]
        verified[row['execution_evidence_sha256']] = c.VerifiedOutputs(out.manifest_bytes, out.files, 'infrastructure_failed')
        with self.assertRaisesRegex(ValueError, 'authenticated workload outcome'):
            c.join(c.canonical(result), expected, verifier)
        expected, result, verified, verifier = fixture()
        rewrite_output(result, verified, 'candidate-1', lambda c: c.update(tests=[{'id': 'another-test', 'status': 'passed'}]))
        with self.assertRaisesRegex(ValueError, 'test identity'):
            c.join(c.canonical(result), expected, verifier)

    def test_original_output_bytes_required(self):
        for mode in ('checks', 'suite', 'extra'):
            expected, result, verified, verifier = fixture()
            row = next(r for r in result['stages'] if r['stage_id'] == 'generate-1')
            out = verified[row['execution_evidence_sha256']]
            files = dict(out.files)
            files[{'checks': 'checks.json', 'suite': 'suite.json', 'extra': 'extra.json'}[mode]] = b'{}'
            verified[row['execution_evidence_sha256']] = c.VerifiedOutputs(out.manifest_bytes, files, row['status'])
            with self.assertRaises(ValueError): c.join(c.canonical(result), expected, verifier)

    def test_crash_timeout_empty_skipped_and_wrong_ids_are_not_base_failure(self):
        mutations = [lambda c: c.update(browser_started=False), lambda c: c.update(completed=False),
                     lambda c: c.update(infrastructure_failed=True), lambda c: c.update(tests=[]),
                     lambda c: c.update(tests=[{'id':'wrong-id','status':'passed'}]),
                     lambda c: c.update(tests=[{'id':'judge-1-assertion','status':'skipped'}])]
        for mutation in mutations:
            expected, result, verified, verifier = fixture()
            rewrite_output(result, verified, 'base-1', mutation)
            with self.assertRaises(ValueError): c.join(c.canonical(result), expected, verifier)

    def test_suite_splice_model_mismatch_candidate_fail_and_missing_regression(self):
        for stage, mutation in [('generate-2', lambda c: c.update(observed_model='other')),
                                ('base-3', lambda c: c.update(suite_sha256='0'*64)),
                                ('candidate-1', lambda c: c.update(tests=[{'id':'judge-1-assertion','status':'assertion_failed'}])),
                                ('primary-review', lambda c: c.update(fixed_logic_baselines=[True]*3)),
                                ('primary-review', lambda c: c.update(feature_checks=[True]*5+[1]))]:
            expected, result, verified, verifier = fixture()
            rewrite_output(result, verified, stage, mutation)
            with self.assertRaises(ValueError): c.join(c.canonical(result), expected, verifier)

    def test_parser_rejects_duplicate_noncanonical_and_unknown(self):
        expected, result, _, verifier = fixture()
        for raw in (b'{"x":1,"x":2}', c.canonical(result)+b'\n', c.canonical(dict(result, verified=True))):
            with self.assertRaises(ValueError): c.join(raw, expected, verifier)


if __name__ == '__main__':
    unittest.main()
