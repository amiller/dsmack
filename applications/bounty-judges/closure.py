"""Closed ten-run bounty acceptance join, called behind the genuine verifier.

This module has no HTTP/JSON 'verified' intake. Its trusted caller supplies a
verifier callback that verifies ORIGINAL evidence against each expected request
and returns only authenticated output files. Unit fixtures are not execution proof.
"""
from dataclasses import dataclass
import hashlib
import json
import re

RESULT_SCHEMA = 'dsmack-bounty-stage-results/1'
CLOSURE_SCHEMA = 'dsmack-bounty-execution-closure/1'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
STAGES = tuple(sorted([f'{role}-{i}' for role in ('generate', 'base', 'candidate')
                       for i in range(1, 4)] + ['primary-review']))
PINS = {'stage_id', 'role', 'judge_index', 'run_id', 'request_sha256',
        'stage_profile_sha256', 'oci_manifest_sha256', 'source_tree_sha256'}
ROW_KEYS = PINS | {'input_suite_sha256', 'output_manifest_sha256',
                   'execution_evidence_sha256', 'checks_sha256', 'status'}
TOP_KEYS = {'schema', 'plan_sha256', 'primary_request_sha256', 'task_terms_sha256',
            'attempt_id', 'attempt_nonce', 'base_tree_sha256',
            'candidate_tree_sha256', 'stages'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    """Bounded, exact JSON encoding; no float, duplicate-key or truthy coercions."""
    def walk(item, depth=0):
        require(depth <= 24, 'JSON nesting')
        if item is None or type(item) in (str, bool):
            return
        if type(item) is int:
            require(abs(item) <= 2**53-1, 'unsafe integer')
            return
        if type(item) is list:
            for child in item:
                walk(child, depth+1)
            return
        require(type(item) is dict and all(type(k) is str for k in item), 'JSON type')
        for child in item.values():
            walk(child, depth+1)
    walk(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha(raw):
    require(type(raw) is bytes, 'expected bytes')
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and DIGEST.fullmatch(value), 'invalid SHA256')
    return value


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 262144, 'JSON size')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs)
    require(raw == canonical(result), 'noncanonical JSON')
    return result


def keys(obj, expected):
    require(type(obj) is dict and set(obj) == expected, 'unexpected object fields')


@dataclass(frozen=True)
class VerifiedOutputs:
    """Return type for the trusted full verifier adapter, never client input.

    manifest_bytes is the ORIGINAL authenticated output manifest. Files are the
    authenticated exported regular-file bytes, not paths supplied by a worker.
    The callback must refuse invalid signature/native/guest evidence and pin the
    request, image, source, challenge, enrollment and replay state independently.
    """
    manifest_bytes: bytes
    files: dict
    workload_status: str


def authenticate_outputs(output, row):
    require(type(output) is VerifiedOutputs, 'full verifier must return authenticated outputs')
    require(output.workload_status == row['status'], 'authenticated workload outcome')
    require(sha(output.manifest_bytes) == row['output_manifest_sha256'], 'manifest digest')
    manifest = parse(output.manifest_bytes)
    keys(manifest, {'schema', 'files'})
    require(manifest['schema'] == 'dsmack-bounty-output-manifest/1', 'manifest schema')
    entries = manifest['files']
    require(type(entries) is list and 0 < len(entries) <= 64, 'manifest count')
    names = []
    for entry in entries:
        keys(entry, {'name', 'size', 'sha256'})
        name = entry['name']
        require(type(name) is str and re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name), 'output name')
        require(type(entry['size']) is int and 0 <= entry['size'] <= 16*1024*1024, 'output size')
        digest(entry['sha256'])
        raw = output.files.get(name)
        require(type(raw) is bytes and len(raw) == entry['size'] and sha(raw) == entry['sha256'], 'output bytes')
        names.append(name)
    require(names == sorted(set(names)) and set(output.files) == set(names), 'closed output files')
    require('checks.json' in output.files and sha(output.files['checks.json']) == row['checks_sha256'], 'checks digest')
    return output.files, parse(output.files['checks.json'])


def join(results_bytes, expected, verify_original):
    """Validate closure against trusted independently derived expectations.

    expected has TOP_KEYS (except schema/stages), requested_model and a closed
    stages list of PINS. The immutable application profile must authorize those
    expectations. This function does not derive/admit a funding profile itself.
    verify_original(expected_stage, evidence_digest) must run the full verifier;
    returning a worker's self-reported verified flag is NOT an implementation.
    """
    results = parse(results_bytes)
    keys(results, TOP_KEYS)
    keys(expected, (TOP_KEYS - {'schema'}) | {'requested_model'})
    require(results['schema'] == RESULT_SCHEMA, 'results schema')
    for name in TOP_KEYS - {'schema', 'stages'}:
        require(results[name] == expected[name] and type(results[name]) is str, 'attempt/context mismatch: '+name)
        if name.endswith('_sha256'):
            digest(results[name])
        else:
            require(0 < len(results[name]) <= 128, 'attempt bound')
    require(type(expected['requested_model']) is str and expected['requested_model'], 'requested model')
    rows, planned = results['stages'], expected['stages']
    require(type(rows) is list and type(planned) is list and len(rows) == len(planned) == 10, 'ten stages required')
    require([s.get('stage_id') for s in rows if type(s) is dict] == list(STAGES), 'closed sorted stages')
    require([s.get('stage_id') for s in planned if type(s) is dict] == list(STAGES), 'closed expected stages')
    require(planned[-1]['request_sha256'] == results['primary_request_sha256'], 'primary request link')
    run_ids, request_ids, evidence_ids, suites, evidence_rows = set(), set(), set(), {}, []
    # All original evidence is verified before acceptance; no selected subset.
    authenticated = {}
    for row, pin in zip(rows, planned):
        keys(row, ROW_KEYS)
        keys(pin, PINS)
        require({k: row[k] for k in PINS} == pin, 'stage pins')
        stage_id = row['stage_id']
        role = 'primary-review' if stage_id == 'primary-review' else stage_id.rsplit('-', 1)[0]
        judge = None if role == 'primary-review' else int(stage_id[-1])
        require(row['role'] == role and type(row['judge_index']) is type(judge) and row['judge_index'] == judge, 'stage role/index')
        require(type(row['run_id']) is str and 0 < len(row['run_id']) <= 128 and row['run_id'] not in run_ids, 'unique run')
        require(row['request_sha256'] not in request_ids, 'unique request')
        require(row['execution_evidence_sha256'] not in evidence_ids, 'unique original evidence')
        run_ids.add(row['run_id']); request_ids.add(row['request_sha256'])
        evidence_ids.add(row['execution_evidence_sha256'])
        for k in ROW_KEYS:
            if k.endswith('_sha256') and k != 'input_suite_sha256':
                digest(row[k])
        source = results['base_tree_sha256'] if role in ('generate', 'base') else results['candidate_tree_sha256']
        require(row['source_tree_sha256'] == source, 'stage source')
        require(row['status'] == ('assertion_failed' if role == 'base' else 'completed'), 'workload outcome')
        files, checks = authenticate_outputs(verify_original(dict(pin), row['execution_evidence_sha256']), row)
        authenticated[stage_id] = (row, files, checks)
        evidence_rows.append({k: row[k] for k in ('stage_id', 'run_id', 'request_sha256', 'execution_evidence_sha256')})
    for i in range(1, 4):
        row, files, checks = authenticated[f'generate-{i}']
        keys(checks, {'schema', 'completed', 'requested_model', 'observed_model', 'suite_sha256', 'base_tree_sha256'})
        require(checks['schema'] == 'dsmack-bounty-generation-checks/1' and checks['completed'] is True, 'generation completion')
        require(checks['requested_model'] == checks['observed_model'] == expected['requested_model'], 'model mismatch')
        require(checks['base_tree_sha256'] == results['base_tree_sha256'], 'generation base')
        require(row['input_suite_sha256'] is None and 'suite.json' in files, 'generation input/output')
        suite = parse(files['suite.json'])
        keys(suite, {'schema', 'tests'})
        require(suite['schema'] == 'dsmack-bounty-browser-suite/1' and type(suite['tests']) is list and 0 < len(suite['tests']) <= 64, 'suite schema/count')
        test_ids = []
        for test in suite['tests']:
            require(type(test) is dict and type(test.get('id')) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', test['id']), 'suite test ID')
            test_ids.append(test['id'])
        require(test_ids == sorted(set(test_ids)), 'suite closed test IDs')
        suites[i] = sha(files['suite.json'])
        require(checks['suite_sha256'] == suites[i], 'generated suite')
        for role in ('base', 'candidate'):
            ci, _, check = authenticated[f'{role}-{i}']
            keys(check, {'schema', 'browser_started', 'completed', 'infrastructure_failed', 'tests', 'suite_sha256'})
            require(check['schema'] == 'dsmack-bounty-ci-checks/1' and check['browser_started'] is True and check['completed'] is True and check['infrastructure_failed'] is False, 'CI infrastructure')
            require(ci['input_suite_sha256'] == check['suite_sha256'] == suites[i], 'suite substitution')
            tests = check['tests']
            require(type(tests) is list and len(tests) == len(test_ids), 'all suite tests required')
            for test, expected_id in zip(tests, test_ids):
                keys(test, {'id', 'status'})
                require(test['id'] == expected_id and test['status'] in ('passed', 'assertion_failed'), 'test identity/terminal classification')
            failed = sum(test['status'] == 'assertion_failed' for test in tests)
            require(failed > 0 if role == 'base' else failed == 0, 'base calibration/candidate result')
    row, _, checks = authenticated['primary-review']
    keys(checks, {'schema', 'fixed_browser_baselines', 'fixed_logic_baselines', 'feature_checks'})
    require(checks['schema'] == 'dsmack-bounty-primary-checks/1' and row['input_suite_sha256'] is None, 'primary checks')
    for name, count in (('fixed_browser_baselines', 4), ('fixed_logic_baselines', 4), ('feature_checks', 6)):
        require(type(checks[name]) is list and len(checks[name]) == count and all(v is True for v in checks[name]), 'fixed checks: '+name)
    closure = {'schema': CLOSURE_SCHEMA, 'plan_sha256': results['plan_sha256'],
               'primary_request_sha256': results['primary_request_sha256'], 'stages': evidence_rows}
    return {'accepted': True,
            'acceptance_results_sha256': sha(RESULT_SCHEMA.encode()+b'\0'+results_bytes),
            'execution_evidence_sha256': sha(CLOSURE_SCHEMA.encode()+b'\0'+canonical(closure))}
