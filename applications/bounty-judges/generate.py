#!/usr/bin/env python3
"""One independent bounded judge generation, run in its own admitted container.

No tools, repository mounts, candidate, prior sessions or other judge outputs.
The parent supplies only a pinned public snapshot and just-in-time CLI auth.
This program neither provisions nor fetches credentials and proves no execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
NODE_BINARY = '/usr/local/bin/node'
STATE_ROOT = Path('/workspace/state')
CLI_VERSION = '2.1.187'
CLI_SHA256 = 'b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2'
OCI_SHA256 = 'dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418'
WALL_SECONDS = 480
MAX_TURNS = 2
MAX_STDOUT = 1024*1024
MAX_STDERR = 65536
MAX_INPUT = 512*1024
MAX_SUITE = 262144
SERIALIZATION_SCHEMA = 'dsmack-bounty-suite-serialization/1'
SERIALIZATION_VERSION = 'strict-json-canonical-suite/1'
MAX_PROMPT = 98304  # below Linux's per-argument bound; fixed wrapper uses -p ARG
PUBLIC_NAMES = ('base.json', 'spec.txt')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw, *, suite_only=False):
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate JSON key')
            obj[key] = value
        return obj
    options = {}
    if suite_only:
        def integer(token):
            value = int(token)
            require(str(value) == token and abs(value) <= 2**53-1,
                    'suite canonical safe integer required')
            return value
        def decimal(_):
            raise ValueError('suite integer scalar required')
        options = {'parse_int': integer, 'parse_float': decimal}
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON constant')),
                      **options)


def canonicalize_suite(raw):
    """Representation only; unchanged Node grammar must still admit the result.

    Parse once with duplicate rejection before object collapse. Do not reorder
    arrays, fix IDs/actions/values, coerce numbers or normalize Unicode text.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_SUITE, 'raw suite byte bound')
    value = parse(raw.decode('utf-8', errors='strict'), suite_only=True)
    result = canonical(value)
    require(0 < len(result) <= MAX_SUITE, 'canonical suite byte bound')
    return result


def suite_serialization_record(raw, suite):
    return {'schema': SERIALIZATION_SCHEMA, 'version': SERIALIZATION_VERSION,
            'raw_bytes': len(raw), 'raw_sha256': sha(raw),
            'canonical_bytes': len(suite), 'canonical_sha256': sha(suite),
            'raw_equals_canonical': raw == suite}



def read_regular(file, limit):
    # Public mounts and the executable must be immutable throughout the run.
    before = file.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'public file type/size')
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= limit
                and (meta.st_dev, meta.st_ino) == (before.st_dev, before.st_ino),
                'public file type/size')
        raw = stream.read(limit+1)
    require(len(raw) <= limit and len(raw) == meta.st_size, 'public byte bound/size')
    return raw


def file_sha(file, limit=256*1024*1024):
    """Hash an immutable image binary without retaining a second full copy."""
    require(not file.is_symlink(), 'binary link refused')
    digest = hashlib.sha256()
    with file.open('rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= limit, 'binary type/size')
        size = 0
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            size += len(chunk)
            require(size <= limit, 'binary byte bound')
            digest.update(chunk)
    require(size == meta.st_size, 'binary changed')
    return digest.hexdigest()


def runtime_environment(context, endpoint):
    """Qualified subscription ABI: only run-local capability, never provider auth.

    Endpoint is injected by the generic credential route, NOT by model/snapshot.
    The parent independently admits its route. Never include its value in errors.
    """
    require(type(endpoint) is str and len(endpoint) <= 512, 'sentinel endpoint required')
    route = urlsplit(endpoint)
    require(route.scheme == 'http' and route.username is None and route.password is None
            and route.hostname and re.fullmatch('[a-zA-Z0-9.-]+', route.hostname)
            and route.port is not None and 0 < route.port <= 65535
            and not route.query and not route.fragment
            and re.fullmatch('/[a-zA-Z0-9_-]{1,128}', route.path)
            and endpoint == 'http://'+route.netloc+route.path, 'sentinel endpoint shape')
    home, cwd, config = context/'home', context/'empty', context/'claude-config'
    for directory in (home, cwd, config):
        directory.mkdir(mode=0o700)
    env = {'HOME': str(home), 'CLAUDE_CONFIG_DIR': str(config),
           'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': str(context),
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1',
           'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
           'ANTHROPIC_BASE_URL': endpoint, 'ANTHROPIC_AUTH_TOKEN': route.path[1:]}
    return cwd, env


def load_snapshot(public, expected_snapshot, expected_base):
    require(sorted(p.name for p in public.iterdir()) == list(PUBLIC_NAMES), 'closed public input slots')
    base_raw = read_regular(public/'base.json', MAX_INPUT)
    spec_raw = read_regular(public/'spec.txt', 65536)
    require(len(base_raw)+len(spec_raw) <= MAX_INPUT, 'total public input bound')
    base = parse(base_raw)
    require(type(base) is dict and set(base) == {'schema', 'files'}, 'base snapshot fields')
    require(base['schema'] == 'dsmack-bounty-base-snapshot/1', 'base snapshot schema')
    require(base_raw == canonical(base), 'canonical base snapshot')
    require(type(base['files']) is list and 0 < len(base['files']) <= 64, 'base file count')
    paths = []
    for row in base['files']:
        require(type(row) is dict and set(row) == {'path', 'content'}, 'base file fields')
        name = row['path']
        require(type(name) is str and re.fullmatch(r'[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*', name)
                and all(part not in ('.', '..') for part in name.split('/')), 'base path')
        require(type(row['content']) is str, 'base text content')
        paths.append(name)
    require(paths == sorted(set(paths)), 'sorted closed base files')
    # The admitted base digest may be a whole repository tree manifest rather
    # than this intentionally bounded source projection. Pin BOTH independently.
    require(re.fullmatch('[0-9a-f]{64}', expected_base), 'base tree digest')
    snapshot = {'schema': 'dsmack-bounty-generator-input/1',
                'base_tree_sha256': expected_base,
                'files': [{'name': name, 'size': len(raw), 'sha256': sha(raw)}
                          for name, raw in zip(PUBLIC_NAMES, (base_raw, spec_raw))]}
    require(sha(canonical(snapshot)) == expected_snapshot, 'immutable snapshot digest')
    spec_raw.decode('utf-8', errors='strict')
    return base_raw, spec_raw, snapshot


def prompt(base, spec):
    # Only the trusted grammar and the pinned base/spec enter the model context.
    grammar = (HERE/'suite-language.txt').read_text()
    return ('You are an independent behavioral browser-test judge for a NEW pilot policy. '
            'This is not a legacy three-Claude-5.5 claim. Design meaningful tests for the '
            'specified behavior, given only the pinned base and task specification. '
            'Do not grade your tests. Never output code, explanations, or markdown. '
            'Output ONLY one canonical JSON suite, with sorted object keys and no whitespace '
            'outside strings, using the following trusted language. Use sorted unique IDs. '
            'There is no candidate and you must not request one. Each test starts fresh. '
            'Assert required control presence before using fill/click: an absent action '
            'target is infrastructure failure, whereas an explicit count mismatch is '
            'a behavioral failure. Include meaningful assertions beyond control presence.\n'
            + grammar+'\nPINNED_BASE_JSON\n'+base.decode('utf-8')
            +'\nPINNED_TASK_SPEC\n'+spec.decode('utf-8')).encode('utf-8')


def bounded_process(argv, input_bytes, cwd, env, seconds, stdout_limit, stderr_limit):
    """Bound wall time and both streams, kill/reap owned group, preserve bytes."""
    stdout, stderr, failure = bytearray(), bytearray(), None
    with tempfile.TemporaryFile(dir=Path(cwd).parent) as input_file:
        input_file.write(input_bytes)
        input_file.seek(0)
        proc = subprocess.Popen(argv, stdin=input_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=env, start_new_session=True)
        deadline = time.monotonic()+seconds
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, (stdout, stdout_limit))
        selector.register(proc.stderr, selectors.EVENT_READ, (stderr, stderr_limit))
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    failure = 'deadline'; break
                for key, _ in selector.select(min(0.1, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target, limit = key.data
                    remaining = limit-len(target)
                    target.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        failure = 'output bound'; break
                if failure:
                    break
            if not failure:
                try:
                    proc.wait(timeout=max(0.001, deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    failure = 'deadline'
        finally:
            # Also terminate descendants which closed their inherited streams.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
            selector.close()
            proc.stdout.close(); proc.stderr.close()
    return bytes(stdout), bytes(stderr), proc.returncode, failure


def cli_command(cli, model, input_prompt):
    require(len(input_prompt) <= MAX_PROMPT, 'prompt argument bound')
    return [str(cli), '--print', input_prompt.decode('utf-8'), '--verbose', '--output-format', 'stream-json',
            '--model', model, '--max-turns', str(MAX_TURNS), '--tools', '',
            '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
            '--setting-sources', 'user', '--settings', '{"disableAllHooks":true}',
            '--disable-slash-commands', '--no-session-persistence']


def observe(transcript):
    events = []
    for line in transcript.splitlines():
        require(len(line) <= 262144, 'event byte bound')
        event = parse(line)
        require(type(event) is dict, 'stream event object')
        events.append(event)
    require(0 < len(events) <= 1024, 'stream event count')
    models = []
    for event in events:
        if event.get('type') == 'assistant':
            model = event.get('message', {}).get('model')
            require(type(model) is str and 0 < len(model) <= 128, 'assistant observed model')
            models.append(model)
            content = event.get('message', {}).get('content')
            require(type(content) is list and all(type(block) is dict and block.get('type') != 'tool_use'
                                                for block in content), 'unexpected tool use')
    require(models, 'no assistant model observation')
    results = [event for event in events if event.get('type') == 'result']
    require(len(results) == 1 and events[-1] is results[0], 'one final result')
    result = results[0]
    require(result.get('subtype') == 'success' and result.get('is_error') is False, 'CLI result not success')
    require(type(result.get('num_turns')) is int and 1 <= result['num_turns'] <= MAX_TURNS, 'turn bound')
    require(type(result.get('result')) is str, 'suite result text')
    init = [event.get('model') for event in events if event.get('type') == 'system' and event.get('subtype') == 'init']
    require(len(init) == 1 and type(init[0]) is str, 'one observed CLI init model')
    return result['result'].encode('utf-8'), sorted(set(models)), init[0]


def output_manifest(output):
    files = []
    for file in sorted(output.iterdir()):
        if file.name == 'output-manifest.json':
            continue  # authenticated envelope is not a member of its own files
        require(re.fullmatch('[a-z][a-z0-9.-]{0,79}', file.name), 'output name')
        raw = read_regular(file, 16*1024*1024)
        files.append({'name': file.name, 'size': len(raw), 'sha256': sha(raw)})
    require(0 < len(files) <= 64, 'output count')
    return {'schema': 'dsmack-bounty-output-manifest/1', 'files': files}


def generate(public, output, cli, model, judge, snapshot_sha256, base_sha256):
    require(type(judge) is int and judge in (1, 2, 3), 'judge index')
    require(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', model), 'explicit exact model ID')
    output.mkdir(parents=True, exist_ok=True)
    require(not output.is_symlink() and not any(output.iterdir()), 'output directory must be empty')
    checks = {'schema': 'dsmack-bounty-generation-checks/1', 'completed': False,
              'requested_model': model, 'observed_model': None, 'suite_sha256': None,
              'base_tree_sha256': base_sha256}
    identity = {'schema': 'dsmack-bounty-generator-identity/1', 'judge_index': judge,
                'requested_model': model, 'observed_models': [], 'cli_version': None,
                'cli_sha256': None, 'qualified_source_oci_manifest_sha256': OCI_SHA256,
                'node_path': NODE_BINARY, 'node_binary_sha256': None,
                'runtime_uid': os.getuid(), 'runtime_gid': os.getgid(),
                'observed_cli_init_model': None,
                'image_verification': 'requires-independent-original-run-verifier'}
    outcome = {'schema': 'dsmack-bounty-generator-outcome/1', 'status': 'infrastructure_failed',
               'error': None, 'exit_code': None, 'max_turns': MAX_TURNS,
               'wall_seconds': WALL_SECONDS, 'stdout_limit': MAX_STDOUT, 'stderr_limit': MAX_STDERR}
    try:
        require(os.getuid() == 1000 and os.getgid() == 1000, 'runtime UID/GID1000 required')
        base, spec, snapshot = load_snapshot(public, snapshot_sha256, base_sha256)
        (output/'input-snapshot.json').write_bytes(canonical(snapshot))
        input_prompt = prompt(base, spec)
        require(len(input_prompt) <= MAX_PROMPT, 'prompt argument bound')
        (output/'prompt.txt').write_bytes(input_prompt)
        require(cli.is_absolute(), 'absolute CLI path')
        identity['cli_sha256'] = file_sha(cli)
        require(identity['cli_sha256'] == CLI_SHA256, 'fixed ARM64 Claude binary digest')
        identity['node_binary_sha256'] = file_sha(Path(NODE_BINARY))
        # Fresh empty HOME and cwd; no caller PATH, settings, routing, plugins,
        # prior sessions or ambient provider configuration. The parent may
        # inject ONLY the just-in-time run-local sentinel endpoint. No provider
        # token/API key or credential file is accepted by this implementation.
        require(STATE_ROOT.is_dir() and not STATE_ROOT.is_symlink(), 'writable state mount required')
        with tempfile.TemporaryDirectory(prefix='judge-context-', dir=STATE_ROOT) as context:
            cwd, env = runtime_environment(Path(context), os.environ.get('DSMACK_SENTINEL_ENDPOINT'))
            version, err, code, failure = bounded_process([str(cli), '--version'], b'', cwd, env, 10, 4096, 4096)
            (output/'version.txt').write_bytes(version+err)
            require(not failure and code == 0 and re.fullmatch(rb'2\.1\.187 \(Claude Code\)\s*', version), 'fixed Claude Code version')
            identity['cli_version'] = CLI_VERSION
            transcript, stderr, code, failure = bounded_process(cli_command(cli, model, input_prompt), b'',
                                                               cwd, env, WALL_SECONDS, MAX_STDOUT, MAX_STDERR)
            (output/'transcript.jsonl').write_bytes(transcript)
            (output/'stderr.txt').write_bytes(stderr)
            outcome['exit_code'] = code
            require(not failure, 'CLI '+str(failure))
            require(code == 0, 'CLI nonzero exit')
            raw_suite, models, init_model = observe(transcript)
            (output/'suite-model-raw.txt').write_bytes(raw_suite)
            identity['observed_models'] = models
            identity['observed_cli_init_model'] = init_model
            checks['observed_model'] = models[0] if len(models) == 1 else None
            require(init_model == model and models == [model], 'requested/observed model mismatch')
            # Preserve exactly what the model emitted; canonical bytes are a
            # measured deterministic transform, never model-authored byte claims.
            suite = canonicalize_suite(raw_suite)
            # Validate in the very same trusted language implementation as CI.
            admitted = subprocess.run([NODE_BINARY, str(HERE/'suite-contract.mjs')], input=suite,
                                      capture_output=True, timeout=5, cwd=cwd, env=env, check=False)
            require(admitted.returncode == 0 and admitted.stdout == suite, 'strict declarative suite: '+admitted.stderr.decode('utf-8', errors='replace')[:500])
            (output/'suite-serialization.json').write_bytes(canonical(suite_serialization_record(raw_suite, suite)))
            (output/'suite.json').write_bytes(suite)
            checks['suite_sha256'] = sha(suite)
            checks['completed'] = True
            outcome['status'] = 'completed'
    except Exception as error:
        outcome['error'] = str(error)[:1000]
    (output/'observed-identity.json').write_bytes(canonical(identity))
    (output/'checks.json').write_bytes(canonical(checks))
    (output/'generation-outcome.json').write_bytes(canonical(outcome))
    with (output/'output-manifest.json').open('xb') as envelope:
        envelope.write(canonical(output_manifest(output)))
    return checks, outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cli', type=Path, default=Path('/usr/local/bin/claude'))
    parser.add_argument('--model', required=True)
    parser.add_argument('--judge', type=int, choices=(1, 2, 3), required=True)
    parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--base-tree-sha256', required=True)
    args = parser.parse_args()
    checks, _ = generate(args.public.resolve(), args.output.resolve(), args.cli, args.model,
                         args.judge, args.snapshot_sha256, args.base_tree_sha256)
    return 0 if checks['completed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
