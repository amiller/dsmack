#!/usr/bin/python3
"""Separate NONBOUNTY 480-second observation; never bounty acceptance or retry.

The image generator is loaded into a fresh module after its exact source pin is
checked. Only its wall allowance and process function change in that private
module. Its CLI argv, environment, prompt, input checks and strict observer stay
unchanged. Raw streams and generated suites remain in temporary guest state.
"""
import hashlib
from contextlib import ExitStack
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time
import types

MODEL = 'claude-opus-4-8'
WALL_SECONDS = 480
MAX_TURNS = 2
GENERATOR = Path('/opt/bounty-judges/generate.py')
GENERATOR_SHA256 = '5285751bb2ca25fb4dd72dfb6e3f0467eba101166b3066a4646a412448f61973'
CLI = Path('/usr/local/bin/claude')
BASE_TREE_SHA256 = 'ca3ff7c4e70d33a481e672079ac381037f3940b8102f09d7c9e1d3b8ce9ab553'


def need(value):
    if not value:
        raise ValueError('Nonbounty diagnostic refused')


class EventTimings:
    """Bounded structural arrival observations; never retain event values."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.start = clock()
        self.pending = bytearray()
        self.discard_line = False
        self.counts = dict(init=0, assistant=0, result=0, api_retry=0, other=0,
                           parse_refused=0)
        self.first_ms = dict(init=None, assistant=None, result=None)
        self.init_model_matches = False
        self.assistant_models_match = True
        self.event_bound_hit = False

    def line(self, raw):
        if sum(self.counts.values()) >= 1024:
            self.event_bound_hit = True
            return
        try:
            need(len(raw) <= 262144)
            def pairs(items):
                value = {}
                for key, item in items:
                    need(key not in value)
                    value[key] = item
                return value
            event = json.loads(raw, object_pairs_hook=pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            need(type(event) is dict)
            kind = event.get('type')
            if kind == 'system' and event.get('subtype') == 'init':
                category = 'init'
                self.init_model_matches = event.get('model') == MODEL
            elif kind == 'assistant':
                category = 'assistant'
                message = event.get('message')
                self.assistant_models_match &= (type(message) is dict
                                                 and message.get('model') == MODEL)
            elif kind == 'result':
                category = 'result'
            elif kind == 'system' and event.get('subtype') == 'api_retry':
                category = 'api_retry'
            else:
                category = 'other'
            self.counts[category] += 1
            if category in self.first_ms and self.first_ms[category] is None:
                self.first_ms[category] = min(490000, max(0, int((self.clock()-self.start)*1000)))
        except Exception:
            self.counts['parse_refused'] += 1

    def feed(self, chunk):
        for part in chunk.splitlines(keepends=True):
            end = part.endswith(b'\n')
            if not self.discard_line:
                if len(self.pending)+len(part) > 262144:
                    self.counts['parse_refused'] += 1
                    self.pending.clear()
                    self.discard_line = True
                else:
                    self.pending.extend(part)
            if end:
                if not self.discard_line:
                    self.line(bytes(self.pending))
                self.pending.clear()
                self.discard_line = False

    def finish(self):
        if self.pending and not self.discard_line:
            self.line(bytes(self.pending))
        self.pending.clear()

    def summary(self):
        return dict(counts=dict(self.counts), first_event_elapsed_ms=dict(self.first_ms),
                    init_model_matches=self.init_model_matches,
                    assistant_models_match=self.assistant_models_match,
                    event_bound_hit=self.event_bound_hit)


def timed_process(argv, input_bytes, cwd, env, seconds, stdout_limit, stderr_limit, observer):
    """Original selector/kill/reap bounds, plus a structural stdout observer."""
    stdout, stderr, failure = bytearray(), bytearray(), None
    with tempfile.TemporaryFile(dir=Path(cwd).parent) as input_file:
        input_file.write(input_bytes)
        input_file.seek(0)
        proc = subprocess.Popen(argv, stdin=input_file, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, env=env,
                                start_new_session=True)
        deadline = time.monotonic()+seconds
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, (stdout, stdout_limit))
        selector.register(proc.stderr, selectors.EVENT_READ, (stderr, stderr_limit))
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    failure = 'deadline'
                    break
                for key, _ in selector.select(min(0.1, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target, limit = key.data
                    remaining = limit-len(target)
                    accepted = chunk[:remaining]
                    target.extend(accepted)
                    if target is stdout:
                        observer.feed(accepted)
                    if len(chunk) > remaining:
                        failure = 'output bound'
                        break
                if failure:
                    break
            if not failure:
                try:
                    proc.wait(timeout=max(0.001, deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    failure = 'deadline'
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
            selector.close()
            proc.stdout.close()
            proc.stderr.close()
            observer.finish()
    return bytes(stdout), bytes(stderr), proc.returncode, failure


def image_generator():
    # Execute the bytes we hashed, not a second path lookup. No paid file changes.
    raw = GENERATOR.read_bytes()
    need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == GENERATOR_SHA256)
    module = types.ModuleType('nonbounty_image_generator')
    module.__file__ = str(GENERATOR)
    exec(compile(raw, str(GENERATOR), 'exec'), module.__dict__)
    need(module.WALL_SECONDS == 180 and module.MAX_TURNS == MAX_TURNS)
    return module


def outcome_category(outcome, timings):
    if outcome.get('status') == 'completed':
        return 'strict_suite_completed'
    error = outcome.get('error')
    if error == 'CLI deadline':
        if timings['counts']['assistant']:
            return 'deadline_after_assistant'
        return 'deadline_after_init' if timings['counts']['init'] else 'deadline_before_init'
    if error == 'CLI output bound':
        return 'stream_bound'
    if error == 'CLI nonzero exit':
        return 'cli_nonzero_exit'
    if type(error) is str and error.startswith('strict declarative suite:'):
        return 'strict_suite_refused'
    return 'harness_or_transcript_refused'


def diagnose(public, expected_snapshot, output, flat_public=False):
    need(os.getuid() == 1000 and os.getgid() == 1000)
    state = Path('/workspace/state')
    need(state.is_dir() and not state.is_symlink() and not any(state.iterdir()))
    need(output.is_dir() and not output.is_symlink() and not any(output.iterdir()))
    q = image_generator()
    with ExitStack() as copies:
        if flat_public:
            # Manifest targets are flat. Copy ONLY the two bounded public files;
            # never expose the extra measured driver to the closed snapshot.
            projected = Path(copies.enter_context(tempfile.TemporaryDirectory(
                prefix='nonbounty-public-', dir=state)))
            for name, bound in [('base.json', q.MAX_INPUT), ('spec.txt', 65536)]:
                raw = q.read_regular(public/name, bound)
                (projected/name).write_bytes(raw)
                (projected/name).chmod(0o400)
            public = projected
        need(q.file_sha(CLI) == q.CLI_SHA256)
        base, spec, _ = q.load_snapshot(public, expected_snapshot, BASE_TREE_SHA256)
        expected_argv = q.cli_command(CLI, MODEL, q.prompt(base, spec))
        original_process = q.bounded_process
        observed = {}

        def measured_process(argv, input_bytes, cwd, env, seconds, stdout_limit, stderr_limit):
            if argv == [str(CLI), '--version']:
                # Preserve the original separate version probe and its bounds.
                return original_process(argv, input_bytes, cwd, env, seconds,
                                        stdout_limit, stderr_limit)
            need(argv == expected_argv and input_bytes == b'' and seconds == WALL_SECONDS
                 and stdout_limit == q.MAX_STDOUT and stderr_limit == q.MAX_STDERR
                 and not observed)
            collector = EventTimings()
            raw, err, code, failure = timed_process(
                argv, input_bytes, cwd, env, seconds, stdout_limit, stderr_limit, collector)
            observed.update(collector.summary(), stdout_bytes=len(raw), stderr_bytes=len(err),
                            elapsed_ms=min(490000, max(0, int((time.monotonic()-collector.start)*1000))),
                            process_failure=failure if failure in (None, 'deadline', 'output bound') else 'other')
            return raw, err, code, failure

        # Explicit separate measured derivative, in a private fresh module namespace.
        # MAX_TURNS, argv, runtime_environment, prompt and observe are not replaced.
        q.WALL_SECONDS = WALL_SECONDS
        q.bounded_process = measured_process
        with tempfile.TemporaryDirectory(prefix='nonbounty-reliability-', dir=state) as temporary:
            private_output = Path(temporary)/'raw'
            checks, outcome = q.generate(public, private_output, CLI, MODEL, 1,
                                         expected_snapshot, BASE_TREE_SHA256)
            # The original strict suite/model validation ran inside generate(). Its
            # transcript, stderr, prompt and any suite are removed with this directory.
            timings = observed or EventTimings().summary()
            code = outcome.get('exit_code')
            report = dict(schema='dsmack-generation-reliability-diagnostic/1',
                          scope='nonbounty-observation-only', requested_model=MODEL,
                          wall_seconds=WALL_SECONDS, max_turns=MAX_TURNS,
                          result_category=outcome_category(outcome, timings),
                          cli_exit_class=('not_started' if code is None else
                                          'terminated' if code < 0 else 'zero' if code == 0 else 'nonzero'),
                          strict_suite_completed=checks.get('completed') is True,
                          cli_observed=timings, raw_streams_or_suite_exported=False,
                          bounty_acceptance=False, retry_performed=False)
    # Only the allowlisted report survives; no model content or routing values.
    raw = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(len(raw) <= 4096)
    fd = os.open(output/'generation-reliability.json',
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--flat-public', action='store_true',
                        help='copy only flat base.json/spec.txt to a temporary closed snapshot')
    args = parser.parse_args()
    diagnose(args.public, args.snapshot_sha256, Path('/workspace/artifacts'), args.flat_public)
    # A completed observation is not a successful bounty generation.
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('Nonbounty reliability diagnostic refused') from None
