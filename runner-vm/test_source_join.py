import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
DERIVATION_SHA=hashlib.sha256((HERE/'SOURCE-DERIVATION.json').read_bytes()).hexdigest() if (HERE/'SOURCE-DERIVATION.json').exists() else None
sys.path.insert(0,str(HERE))
from source_check import check, selected_lock
from build_unsigned import stage_archive, cleanup_adapter, portable_group_members, select_native


class SourceJoinTests(unittest.TestCase):
    def test_actual_original_membership_and_hashes(self):
        result=check(derivation_sha256=DERIVATION_SHA)
        self.assertEqual(557 if DERIVATION_SHA else 556,result['source_files_checked'])
        self.assertFalse(result['compiled'])
        self.assertFalse(result['signed'])

    def test_native_inventory_matches_original_qualified_archive(self):
        spec=importlib.util.spec_from_file_location('original_native_supervisor',HERE/'native/xbuild-supervise.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        inventory=module.source_inventory()
        lock=selected_lock(check(derivation_sha256=DERIVATION_SHA),json.loads((HERE/'QUALIFIED-INPUTS.json').read_text()))
        self.assertEqual(460,len(inventory.splitlines()))
        self.assertEqual(lock['native_source_inventory_sha256'],hashlib.sha256(inventory.encode()).hexdigest())

    def fixture(self, directory):
        root=Path(directory)
        for name in ('app-src','control-src','io-contract-consumer','packaging','native/source-tree'):
            (root/name).mkdir(parents=True)
        source=root/'app-src/main.swift';source.write_text('original')
        manifest={'files':[{'repository_relative':'runner-vm/app-src/main.swift',
                            'original_sha256':hashlib.sha256(b'original').hexdigest()}]}
        (root/'SOURCE-IMPORT.json').write_text(json.dumps(manifest))
        return root,source

    def test_modified_source_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root,source=self.fixture(d);source.write_text('modified')
            with self.assertRaisesRegex(ValueError,'source changed'):check(root)

    def test_unreviewed_compile_input_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root,source=self.fixture(d);(root/'app-src/addition.swift').write_text('extra')
            with self.assertRaisesRegex(ValueError,'unreviewed source addition'):check(root)

    def test_source_symlink_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root,source=self.fixture(d);(root/'control-src/alias.swift').symlink_to(source)
            with self.assertRaisesRegex(ValueError,'symlink'):check(root)

    def test_migration_preserves_all_original_bytes(self):
        manifest=json.loads((HERE/'SOURCE-IMPORT.json').read_text())
        changes={x['repository_relative']:x for x in json.loads((HERE/'SOURCE-DERIVATION.json').read_text())['changes']} if DERIVATION_SHA else {}
        for entry in manifest['files']:
            selected=entry['original_sha256']
            if entry['repository_relative'] in changes:
                change=changes[entry['repository_relative']]
                self.assertEqual(selected,change['before_sha256']);selected=change['after_sha256']
            self.assertEqual(selected,hashlib.sha256((HERE/entry['repository_relative'].removeprefix('runner-vm/')).read_bytes()).hexdigest())

    def test_new_native_selection_requires_independent_pins_and_exact_source(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'native.a';archive.write_bytes(b'new-native')
            lock={'native_archive_sha256':'0'*64,'native_source_inventory_sha256':'a'*64,
                  'native_rustc':'rustc EXACT'}
            record={'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                    'archive_bytes':archive.stat().st_size,'source_inventory_sha256':'a'*64,
                    'rustc':'rustc EXACT','group_quiescence':'confirmed-empty',
                    'command':['cargo','build','--release','--offline','--locked','--target','aarch64-apple-darwin']}
            path=root/'record.json';path.write_text(json.dumps(record))
            pin=hashlib.sha256(path.read_bytes()).hexdigest()
            chosen=select_native(archive,lock,path,pin,record['archive_sha256'])
            self.assertTrue(chosen['new_app_qualification_required'])
            self.assertEqual('0'*64,select_native(archive,lock)['expected_sha256'])
            with self.assertRaises(ValueError):select_native(archive,lock,path,None,None)
            with self.assertRaises(ValueError):select_native(archive,lock,path,'b'*64,record['archive_sha256'])
            for field,value in [('source_inventory_sha256','b'*64),('rustc','other'),
                                ('group_quiescence','unknown'),('archive_sha256','c'*64),
                                ('command',['cargo','build'])]:
                bad=dict(record);bad[field]=value;path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):select_native(archive,lock,path,
                    hashlib.sha256(path.read_bytes()).hexdigest(),record['archive_sha256'])

    def test_derivation_requires_exact_external_selection_and_refuses_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root,source=self.fixture(d)
            baseline=hashlib.sha256((root/'SOURCE-IMPORT.json').read_bytes()).hexdigest()
            before=hashlib.sha256(source.read_bytes()).hexdigest();source.write_text('reviewed update')
            addition=root/'app-src/Capacity.swift';addition.write_text('new exact source')
            doc={'schema':'dsmack-derived-runner-source/1','source_profile_id':'test-derived','baseline_import_manifest_sha256':baseline,'native_source_inventory_sha256':'a'*64,
                 'changes':[{'repository_relative':'runner-vm/app-src/main.swift','before_sha256':before,'after_sha256':hashlib.sha256(source.read_bytes()).hexdigest()},
                            {'repository_relative':'runner-vm/app-src/Capacity.swift','before_sha256':None,'after_sha256':hashlib.sha256(addition.read_bytes()).hexdigest()}]}
            path=root/'SOURCE-DERIVATION.json';path.write_text(json.dumps(doc));pin=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'independently selected'):check(root)
            with self.assertRaisesRegex(ValueError,'independently selected'):check(root,'0'*64)
            result=check(root,pin);self.assertFalse(result['original_import_matched']);self.assertEqual(2,result['source_files_checked'])
            with self.assertRaisesRegex(ValueError,'new independently selected'):select_native(root/'old.a',selected_lock(result,{'native_archive_sha256':'0'*64}))
            doc['changes'][0]['before_sha256']='f'*64;path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError,'before identity'):check(root,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_renamed_archive_cannot_select_wrong_neighbor(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'renamed.a';source.write_bytes(b'correct')
            (root/'libdsmack_hvf_returning.a').write_bytes(b'wrong neighbor')
            expected=hashlib.sha256(b'correct').hexdigest()
            staged=stage_archive(source,root/'inputs',expected)
            self.assertEqual('libdsmack_hvf_returning.a',staged.name)
            self.assertEqual(b'correct',staged.read_bytes())
            self.assertEqual(b'wrong neighbor',(root/'libdsmack_hvf_returning.a').read_bytes())

    def test_exited_leader_live_term_ignoring_descendant_is_killed(self):
        code='''import os,signal,time,sys
if os.fork(): os._exit(0)
signal.signal(signal.SIGTERM,signal.SIG_IGN)
signal.alarm(30)
print(os.getpid(),flush=True)
while True: time.sleep(1)
'''
        with tempfile.TemporaryDirectory() as d:
            proc=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,
                                  text=True,start_new_session=True)
            try:
                descendant=int(proc.stdout.readline().strip())
                proc.wait(timeout=5)
                self.assertIn(descendant,portable_group_members(proc.pid))
                cleanup=cleanup_adapter(Path(d)/'owner.json')
                cleanup.GRACE_SECONDS=0.1
                result=cleanup.confirm_group_reaped(proc,proc.pid)
                self.assertEqual('clean',result['status'])
                self.assertEqual([],portable_group_members(proc.pid))
            finally:
                try: os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                proc.stdout.close()

    def test_ps_failures_keep_cleanup_unknown_and_transfer_ownership(self):
        import build_unsigned
        for failure in (subprocess.TimeoutExpired(['ps'],5),
                        subprocess.CalledProcessError(1,['ps']), ValueError('malformed ps')):
            with mock.patch.object(build_unsigned,'capture',side_effect=failure):
                with self.assertRaises(OSError):portable_group_members(999999)
                with tempfile.TemporaryDirectory() as d:
                    cleanup=cleanup_adapter(Path(d)/'owner.json')
                    cleanup.GRACE_SECONDS=cleanup.KILL_CONFIRM_SECONDS=0
                    process=mock.Mock();process.wait.return_value=0
                    with mock.patch.object(cleanup.os,'killpg'), mock.patch.object(
                            cleanup,'spawn_persistent_owner',return_value=54321):
                        self.assertTrue(cleanup.group_alive(999999))
                        result=cleanup.confirm_group_reaped(process,999999)
                    self.assertEqual('transferred',result['status'])
                    self.assertEqual(54321,result['owner_pid'])


if __name__=='__main__':unittest.main()
