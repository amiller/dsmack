#!/usr/bin/env python3
"""One operator-selected, credential-free invitation; no installer or authority service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

INSTALLER_SHA256 = '7f222196640c7eefd7429ef56bd0c6983b798986b3f0bdce09cc85055d2ee6eb'
COORDINATOR_SHA256 = 'aa24282d8f806028ccaf8188a5fdf36b87ab472d4c4340dc2ad0fd01093cd009'
PROFILES = {'bounty-board-search-primary-review-v1',
            'bounty-board-search-primary-review-v1-primary'}


def need(value, message):
    if not value:
        raise ValueError(message)


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def protected(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'canonical absolute local path required')
    for parent in reversed(path.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid())
             and not s.st_mode & 0o022, 'unprotected path ancestor')
    s = path.lstat()
    need(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, os.getuid())
         and not s.st_mode & 0o022, 'unprotected local path')
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
         'wrong local path type')
    return path


def read(path, cap=1048576):
    path = protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= cap
             and s.st_uid in (0, os.getuid()) and not s.st_mode & 0o022,
             'bounded single-link regular file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        need(len(raw) == s.st_size and len(raw) <= cap, 'file changed or too large')
        return raw
    finally:
        os.close(fd)


def pinned(desc, cap=1048576):
    need(type(desc) is dict and set(desc) == {'path', 'bytes', 'sha256'},
         'exact public descriptor required')
    need(type(desc['bytes']) is int and 0 <= desc['bytes'] <= cap
         and re.fullmatch('[a-f0-9]{64}', desc['sha256'] or ''), 'descriptor bounds')
    raw = read(desc['path'], cap)
    need(len(raw) == desc['bytes'] and hashlib.sha256(raw).hexdigest() == desc['sha256'],
         'selected file changed')
    return raw


def invitation(path, expected):
    need(re.fullmatch('[a-f0-9]{64}', expected or ''), 'independently selected invitation SHA256 required')
    raw = read(path)
    need(hashlib.sha256(raw).hexdigest() == expected, 'invitation digest mismatch')
    v = document(raw)
    need(set(v) == {'schema', 'native_execution_id', 'profile_id', 'install_root',
                    'run_parent', 'bootstrap', 'inventory', 'signature', 'task'},
         'closed invitation fields')
    need(v['schema'] == 'dsmack-friend-invitation/1'
         and v['profile_id'] in PROFILES
         and re.fullmatch('[a-f0-9]{32}', v['native_execution_id'] or ''),
         'supported credential-free starter invitation required')
    protected(v['install_root'], True)
    protected(v['run_parent'], True)
    for role in ('bootstrap', 'inventory', 'signature'):
        pinned(v[role])
    task = document(pinned(v['task'], 65536))
    fields = {'schema', 'profile_id', 'closure_context', 'checker_context', 'challenge',
              'key_id', 'workload_disk', 'workload_admission', 'workload_signature'}
    need(set(task) == fields and task['schema'] == 'dsmack-alpha-local-task/2'
         and task['profile_id'] == v['profile_id'], 'credential-free task/2 only')
    closure = document(pinned(task['closure_context'], 65536))
    need(closure.get('attempt_id') == v['native_execution_id'], 'task/native identity mismatch')
    return v, task


def authenticate(v, task):
    source = Path(__file__).resolve().with_name('alpha_stage.py')
    raw = read(source)
    need(hashlib.sha256(raw).hexdigest() == INSTALLER_SHA256, 'selected installer source changed')
    scope = {'__name__': 'friend_selected_installer', '__file__': str(source)}
    exec(compile(raw, str(source), 'exec'), scope)
    bootstrap = document(pinned(v['bootstrap']))
    result = scope['authenticate'](
        bootstrap, v['inventory']['path'], v['signature']['path'],
        root=v['install_root'], profile=v['profile_id'],
        workload_admission=task['workload_admission']['path'],
        workload_signature=task['workload_signature']['path'])
    need(result['profile']['schema'] == 'dsmack-alpha-profile/2', 'public profile/2 only')
    manifest_path = Path(v['install_root']) / result['profile']['roles']['compose_manifest']
    manifest = document(read(manifest_path))
    need(manifest['network']['mode'] == 'none'
         and manifest.get('credentials', {}).get('required', False) is False
         and not manifest.get('allowed_envs') and not manifest.get('required_envs'),
         'offline credential-free starter only')
    entry = Path(v['install_root']) / 'alpha_coordinator.py'
    row = next(x for x in result['inventory']['files'] if x['path'] == 'alpha_coordinator.py')
    code = read(entry)
    need(hashlib.sha256(code).hexdigest() == row['sha256'] == COORDINATOR_SHA256,
         'selected signed coordinator source changed')
    coordinator = {'__name__': 'friend_selected_coordinator', '__file__': str(entry)}
    exec(compile(code, str(entry), 'exec'), coordinator)
    core, _, _ = coordinator['selected_modules'](v['install_root'], result)
    auth = {k: v[k] for k in ('bootstrap', 'inventory', 'signature')}
    # Reuse the original complete disk/admission/closure/checker validation.
    coordinator['validate_workload'](auth, v['install_root'], result, task, core)
    return entry


def argv(command, v, entry):
    need(command in {'prepare', 'check', 'run', 'resume'}, 'unsupported command')
    prefix = [sys.executable, '-I', '-B', str(entry)]
    if command == 'prepare':
        return prefix + ['--prepare', '--bootstrap', v['bootstrap']['path'],
                         '--inventory', v['inventory']['path'], '--signature', v['signature']['path'],
                         '--root', v['install_root'], '--profile', v['profile_id'],
                         '--task', v['task']['path'], '--out-parent', v['run_parent']]
    plan = Path(v['run_parent']) / ('attempt-' + v['native_execution_id'] + '.control') / 'plan.json'
    return prefix + [{'check': '--check-only', 'run': '--execute', 'resume': '--resume'}[command],
                     '--plan', str(plan)]


def validate_plan(v):
    path = Path(v['run_parent']) / ('attempt-' + v['native_execution_id'] + '.control') / 'plan.json'
    plan = document(read(path, 65536))
    expected = {'schema': 'dsmack-alpha-launch-plan/1',
                'admission': {k: v[k] for k in ('bootstrap', 'inventory', 'signature')},
                'root': v['install_root'], 'profile_id': v['profile_id'], 'task': v['task'],
                'out_parent': v['run_parent'], 'inventory_sha256': v['inventory']['sha256'],
                'attempt_id': v['native_execution_id']}
    need(plan == expected, 'existing plan does not match selected invitation')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['inspect', 'prepare', 'check', 'run', 'resume'])
    parser.add_argument('invitation')
    parser.add_argument('--sha256', required=True, help='invitation digest supplied independently by operator')
    a = parser.parse_args()
    need(sys.flags.isolated == 1, 'invoke trusted Python with -I')
    v, task = invitation(a.invitation, a.sha256)
    if a.command in ('check', 'run', 'resume'):
        validate_plan(v)
    entry = authenticate(v, task)
    if a.command == 'inspect':
        print(json.dumps({'native_execution_id': v['native_execution_id'],
                          'credential_free': True, 'network': 'none', 'vm_launched': False,
                          'enrollment_and_challenge': 'operator supplied; not created here',
                          'proof_verification': 'separate selected Linux verifier'}))
        return 0
    summary = Path(v['run_parent']) / ('friend-summary-' + v['native_execution_id'] + '.json')
    if a.command == 'run':
        need(not summary.exists(), 'existing run summary; use resume, never implicit retry')
    result = subprocess.run(argv(a.command, v, entry), env={'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin'})
    if a.command == 'run':
        record = {'schema': 'dsmack-friend-controller-summary/1', 'invitation_sha256': a.sha256,
                  'native_execution_id': v['native_execution_id'], 'controller_returncode': result.returncode,
                  'originals_path': str(Path(v['run_parent']) / ('attempt-' + v['native_execution_id'])),
                  'verification_status': 'operator-verification-required', 'task_acceptance': 'not evaluated',
                  'payment': 'not requested', 'summary_is_cryptographic_proof': False}
        fd = os.open(summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(record, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        print(json.dumps({'summary': str(summary), 'verification_status': record['verification_status']}))
    return result.returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, StopIteration) as exc:
        print('Invitation refused: ' + str(exc), file=sys.stderr)
        sys.exit(2)
