"""dsmack_gc.py keeps what launchd, the pool commands, processes and pins name, and reclaims the rest."""
import gzip
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import dsmack_gc


class GcTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.dsmack = self.home/'.dsmack'
        patches = [patch.object(dsmack_gc, name, self.dsmack/leaf) for name, leaf in
                   (('STORE', 'store'), ('BARE', 'dsmack.git'), ('PINS', 'gc-pins'), ('KEEP', 'gc-keep'))]
        patches.append(patch.object(dsmack_gc, 'clone', lambda src, dst: shutil.copyfile(src, dst)))
        patches.append(patch.object(dsmack_gc, 'DSMACK', self.dsmack))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.dsmack.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def release(self, name, mtime, files=()):
        path = self.home/name
        (path/'source').mkdir(parents=True)
        for rel, data in files:
            (path/rel).parent.mkdir(parents=True, exist_ok=True)
            (path/rel).write_bytes(data)
        os.utime(path, (mtime, mtime))
        return path

    def pool(self, label, root, argv):
        agents = self.home/'Library/LaunchAgents'
        agents.mkdir(parents=True, exist_ok=True)
        command = self.home/(label+'.json')
        command.write_text(json.dumps(argv))
        (agents/(label+'.plist')).write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': [
            '/venv/bin/python', '/x/pool-service.py', 'run', '--label', label, '--root', str(root), '--command', str(command)]}))
        root.mkdir(exist_ok=True)

    def test_gc_keeps_live_linked_restart_pinned_and_one_rollback_and_preserves_keys(self):
        live = self.release('dsmack-live', 50, [('pool-command.json', b'[]')])
        linked = self.release('dsmack-runner', 10, [('DsmackRunner.app/x', b'app')])
        stage = self.home/'dsmack-stage3'
        (stage/'runner').mkdir(parents=True)
        base = self.release('dsmack-base', 5, [('runner/base/Image', b'kernel')])
        os.symlink(base/'runner/base', stage/'runner/base')
        notes = self.home/'dsmack-research'
        notes.mkdir()
        (live/'runner').mkdir()
        os.symlink(linked/'DsmackRunner.app', live/'runner/DsmackRunner.app')
        staged = self.release('dsmack-next', 20)
        pinned = self.release('dsmack-pinned', 30)
        old = self.release('dsmack-old', 40, [('relay.key', b'secret'), ('enrollment/keyId.txt', b'kid'),
                                               ('workload/workload.img', b'\0'*4096), ('source/x.py', b'code'),
                                               ('logs/pool.log', b'log')])
        rollback = self.release('dsmack-rollback', 45)
        root = self.home/'dl'
        self.pool('org.dsmack.pool.live', root, ['/py', str(live/'source/mac-pool.py'), '--runner', str(live/'runner'),
                                                 '--other-runner', str(stage/'runner')])
        (root/'restart.json').write_text(json.dumps({'source': str(staged/'source')}))
        (self.dsmack/'gc-pins').write_text(str(pinned)+'\n')
        with patch.object(dsmack_gc, 'processes', return_value='/usr/bin/true'):
            dsmack_gc.gc(home=self.home)
        self.assertEqual(sorted(p.name for p in self.home.glob('dsmack-*')),
                         ['dsmack-base', 'dsmack-live', 'dsmack-next', 'dsmack-pinned', 'dsmack-research', 'dsmack-rollback',
                          'dsmack-runner', 'dsmack-stage3'])
        kept = self.dsmack/'gc-keep'/old.name
        self.assertEqual((kept/'relay.key').read_bytes(), b'secret')
        self.assertEqual((kept/'enrollment/keyId.txt').read_bytes(), b'kid')
        self.assertTrue((kept/'logs/pool.log').exists())
        self.assertFalse((kept/'workload').exists() or (kept/'source').exists())
        self.assertTrue(rollback.exists())

    def test_gc_keeps_a_release_only_a_running_process_names_and_refuses_without_a_pool(self):
        busy = self.release('dsmack-resip', 1)
        provider = self.release('dsmack-signing', 0)
        self.release('dsmack-a', 2)
        self.release('dsmack-b', 3)
        with self.assertRaisesRegex(RuntimeError, 'no launchd pool'):
            dsmack_gc.gc(home=self.home)
        self.pool('org.dsmack.pool.live', self.home/'dl', ['/py'])
        with patch.object(dsmack_gc, 'processes', return_value=''), self.assertRaisesRegex(RuntimeError, 'gc-pins missing'):
            dsmack_gc.gc(home=self.home)
        self.assertEqual(len(list(self.home.glob('dsmack-*'))), 4)
        (self.dsmack/'gc-pins').write_text('')
        # Hand-written plists put tags back to back: <array><string>/Users/...
        (self.home/'Library/LaunchAgents/dev.dsmack.provider.plist').write_bytes(re.sub(rb'>\s+<', b'><', plistlib.dumps(
            {'Label': 'dev.dsmack.provider', 'ProgramArguments': [str(provider/'ProviderDemo.app/Contents/MacOS/provider-host')]})))
        with patch.object(dsmack_gc, 'processes', return_value=str(busy/'runner/DsmackRunner.app')+' -args x'):
            dsmack_gc.gc(home=self.home)
        self.assertEqual(sorted(p.name for p in self.home.glob('dsmack-*')), ['dsmack-b', 'dsmack-resip', 'dsmack-signing'])

    def test_dry_run_deletes_nothing_and_a_held_lock_skips_gc(self):
        self.pool('org.dsmack.pool.live', self.home/'dl', ['/py'])
        (self.dsmack/'gc-pins').write_text('')
        for i in range(3):
            self.release(f'dsmack-{i}', i)
        with patch.object(dsmack_gc, 'processes', return_value=''):
            dsmack_gc.gc(dry_run=True, home=self.home)
            self.assertEqual(len(list(self.home.glob('dsmack-*'))), 3)
            with dsmack_gc.locked() as ok:
                self.assertTrue(ok)
                dsmack_gc.gc(home=self.home)
            self.assertEqual(len(list(self.home.glob('dsmack-*'))), 3)
            self.assertIn('gc_busy', (self.dsmack/'gc-keep/gc.jsonl').read_text())

    def run_dir(self, root, generation, run, launcher_pid=None):
        path = root/generation/'guests-1'/run
        (path/'out').mkdir(parents=True)
        for name in ('workload.img', 'out/scratch.img', 'out/system.img.staged', 'out/.scratch.img.dsmack-attempt.999999.1.2.partial'):
            (path/name).write_bytes(b'\0'*1024)
        (path/'out/result.img').write_bytes(b'result'*1000)
        (path/'session.json').write_text('{}')
        if launcher_pid:
            (root/generation/'launcher.pid').write_text(str(launcher_pid))
        os.utime(path, (1, 1))
        return path

    def test_reap_retires_stopped_runs_and_spares_live_launchers_and_processes(self):
        root = self.home/'dl'
        stopped = self.run_dir(root, 'pool-1', 'run-1', launcher_pid=999999)
        running = self.run_dir(root, 'pool-2', 'run-2', launcher_pid=os.getpid())
        draining = self.run_dir(root, 'pool-3', 'run-3')
        young = self.run_dir(root, 'pool-4', 'run-4')
        os.utime(young)
        # The draining run starts after the first ps read; reap must see it in a later one.
        snapshots = iter(['']+['dsmack-runner hvf-v3 '+str(draining/'out')]*10)
        with patch.object(dsmack_gc, 'alive', side_effect=lambda pid: pid == os.getpid()), \
                patch.object(dsmack_gc, 'processes', side_effect=lambda: next(snapshots)):
            dsmack_gc.reap(root)
        self.assertEqual(sorted(p.name for p in stopped.rglob('*') if p.is_file()),
                         ['result.img.gz', 'session.json'])
        with gzip.open(stopped/'evidence/result.img.gz') as stream:
            self.assertEqual(stream.read(), b'result'*1000)
        for path in (running, draining, young):
            self.assertTrue((path/'out/scratch.img').exists() and (path/'out/result.img').exists())

    def test_reap_keeps_a_partial_copy_whose_writer_lives(self):
        root = self.home/'ds'
        run = self.run_dir(root, 'pool-1', 'run-1')
        partial = run/'out/.scratch.img.dsmack-attempt.4242.1.2.partial'
        partial.write_bytes(b'x')
        with patch.object(dsmack_gc, 'alive', side_effect=lambda pid: pid == 4242), \
                patch.object(dsmack_gc, 'processes', return_value=''):
            dsmack_gc.reap(root)
        self.assertTrue(partial.exists())
        self.assertFalse((run/'out/scratch.img').exists())

    def test_store_dedupes_identical_images_and_gc_drops_unreferenced_objects(self):
        big = os.urandom(1024) * (dsmack_gc.BIG // 1024)
        a = self.release('dsmack-a', 1, [('workload/workload.img', big), ('small.json', b'{}')])
        b = self.release('dsmack-b', 2, [('workload/workload.img', big)])
        dsmack_gc.store([a, b])
        objects = list((self.dsmack/'store/sha256').iterdir())
        self.assertEqual(len(objects), 1)
        self.assertEqual((b/'workload/workload.img').read_bytes(), big)
        dsmack_gc.store_gc([a], dry_run=False)
        self.assertEqual(len(list((self.dsmack/'store/sha256').iterdir())), 1)
        shutil.rmtree(a)
        shutil.rmtree(b)
        dsmack_gc.store_gc([], dry_run=False)
        self.assertEqual(list((self.dsmack/'store/sha256').iterdir()), [])

    def test_source_is_a_worktree_of_one_bare_repository(self):
        origin = self.home/'origin'
        git = lambda *a, cwd=origin: subprocess.run(['git', *a], cwd=cwd, check=True, capture_output=True, text=True).stdout
        origin.mkdir()
        git('init', '-q', '-b', 'main')
        (origin/'pool.py').write_text('v1')
        git('add', '.')
        git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'v1')
        commit = git('rev-parse', 'HEAD').strip()
        bare = self.dsmack/'dsmack.git'
        for name in ('dsmack-r1', 'dsmack-r2'):
            dsmack_gc.source(commit, self.home/name/'source', bare=bare, url=str(origin))
            self.assertEqual((self.home/name/'source/pool.py').read_text(), 'v1')
        self.assertEqual(len(git('--git-dir', str(bare), 'worktree', 'list', cwd=self.home).splitlines()), 3)
        shutil.rmtree(self.home/'dsmack-r1')
        git('--git-dir', str(bare), 'worktree', 'prune', cwd=self.home)
        self.assertEqual(len(git('--git-dir', str(bare), 'worktree', 'list', cwd=self.home).splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
