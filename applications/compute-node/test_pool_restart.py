"""A replacement cannot drain serving guests until the broker sees new capacity."""
import json
from pathlib import Path
from types import SimpleNamespace
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

import pool
import pool_restart


class ConfigTests(unittest.TestCase):
    def release(self, root):
        runner, workload = root/'runner', root/'workload'
        for subdir in ('base', 'runtime/base', 'runtime/helper', 'enrollment', 'DsmackRunner.app/Contents/MacOS'):
            (runner/subdir).mkdir(parents=True)
        workload.mkdir()
        for name in ('scratch', 'result'):
            (runner/'runtime/base'/(name+'-template.ext4')).write_bytes(name.encode())
        cmdline = ' '.join('dstack.'+name+'_template_sha256='+pool.sha(runner/'runtime/base'/(name+'-template.ext4'))
                           for name in ('scratch', 'result'))
        (runner/'base/metadata.json').write_text(json.dumps(dict(cmdline=cmdline)))
        base = dict(memory_mb=4096, vcpus=1)
        for name, field in [('Image', 'kernel_sha256'), ('initramfs.cpio.gz', 'initrd_sha256'),
                            ('rootfs.squashfs.verity', 'rootfs_sha256'), ('metadata.json', 'metadata_sha256'),
                            ('sha256sum.txt', 'os_image_hash')]:
            path = runner/'base'/name
            if not path.exists():
                path.write_bytes(name.encode())
            base[field] = pool.sha(path)
        for name in ('runtime/helper/gvproxy-darwin', 'enrollment/keyId.txt', 'DsmackRunner.app/Contents/MacOS/dsmack-runner'):
            (runner/name).write_bytes(b'fixture')
        (workload/'workload.img').write_bytes(b'workload')
        node = dict(command=['serve', '/p2p/relay', '3600'], environment=dict(ADMIT_SECONDS='3120'))
        (workload/'compose-manifest.json').write_text(json.dumps(dict(base_vm=base,
            docker_compose_file=json.dumps(dict(services=dict(node=node))))))
        operator = root/'operator.json'
        operator.write_text(json.dumps(dict(max_guests=4, guest=dict(mem_mib=4096, vcpus=1), reserve=dict(mem_gb=16, cores=4))))
        source = root/'new-source'
        (source/'applications/compute-node').mkdir(parents=True)
        (source/'applications/compute-node/pool.py').write_text('# staged pool\n')
        config = dict(source=str(source), runner=str(runner), workload=str(workload), operator=str(operator), pool_version='next',
                      workload_sha256=pool.sha(workload/'workload.img'), manifest_sha256=pool.sha(workload/'compose-manifest.json'))
        path = root/'restart.json'; path.write_text(json.dumps(config))
        return runner, workload, path

    def test_files_and_measured_hashes_are_checked_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pool_restart, 'hardware', return_value=dict(mem_bytes=64<<30, cores=14)):
            root = Path(tmp)
            runner, workload, path = self.release(root)
            config = pool_restart.replacement(path, 'relay')
            self.assertEqual(config['drain'], 480)
            self.assertEqual(config['source'], root/'new-source')
            (workload/'workload.img').write_bytes(b'incomplete transfer')
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                pool_restart.replacement(path, 'relay')
            (workload/'workload.img').write_bytes(b'workload')
            (runner/'base/Image').write_bytes(b'wrong kernel')
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                pool_restart.replacement(path, 'relay')
            (runner/'base/Image').write_bytes(b'Image')
            (runner/'runtime/base/result-template.ext4').unlink()
            with self.assertRaises(FileNotFoundError):
                pool_restart.replacement(path, 'relay')

    def test_new_generations_keep_the_slot_cap_and_coexisting_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            start = Mock()
            manager = pool_restart.Generations(Path(tmp), 'broker', Mock(), start, 'relay',
                                               max_slots=1, coexist_pools=[Path('/production')])
            config = dict(source=Path('/source'), runner='/runner', workload='/workload', operator='/operator',
                          seconds=3600, drain=480, replace=1830)
            manager.launch(config)
            command = start.call_args.args[0]
            self.assertEqual(command[command.index('--max-slots')+1], '1')
            self.assertEqual(command[command.index('--coexist-pool')+1], Path('/production'))

    def test_bad_configuration_leaves_serving_process_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            start = Mock()
            manager = pool_restart.Generations(Path(tmp), 'unused', Mock(), start, 'relay')
            old = dict(process=Mock()); manager.current=old; manager.pools=[old]
            with self.assertRaises(FileNotFoundError):
                manager.restart(Path(tmp)/'missing.json')
            start.assert_not_called()
            old['process'].send_signal.assert_not_called()


class HandoverTests(unittest.TestCase):
    def setup_manager(self, root):
        publisher = Mock(account=SimpleNamespace(address='publisher'))
        publisher.tick.return_value = dict(event='heartbeat_posted', updated_at=100)
        manager = pool_restart.Generations(root, 'unused', publisher, Mock(), 'relay')
        config = dict(measurement='compose', image='image', version='new', operator=root/'operator.json')
        for name in ('old', 'new'):
            state = root/name; state.mkdir()
            snapshot = dict(config=dict(max_guests=1), hardware={}, classes=['class'], errors=[], slots=[dict(
                slot_id=0, state='busy' if name == 'old' else 'ready', relay_peer=name)])
            (state/'directory.json').write_text(json.dumps(snapshot))
            generation = dict(state=state, config=config, process=Mock(poll=Mock(return_value=None)))
            manager.pools.append(generation)
        manager.current, manager.candidate = manager.pools
        manager.ready_heartbeat = None
        manager.deadline = float('inf')
        return manager

    def test_only_new_verified_live_guest_and_reported_capacity_release_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.setup_manager(Path(tmp)); old, new = manager.pools
            live = dict(admit_until=pool.time.time()+300, kind='compute', relay_peer='new', manifest_sha256='compose', os_image_hash='image', attestation={})
            network = dict(macs=[dict(publisher='publisher', online=True, ready=1, last_heartbeat=100)])
            manager.read = Mock(side_effect=lambda path: [live] if path == '/nodes' else network)
            combined = manager.tick()
            self.assertEqual([s['state'] for s in combined['slots']], ['busy', 'ready'])
            self.assertEqual([s['slot_id'] for s in combined['slots']], [0, 1])
            old['process'].send_signal.assert_not_called()
            live['attestation']['status']='verified'
            network['macs'][0]['ready']=0
            manager.tick(); old['process'].send_signal.assert_not_called()
            network['macs'][0]['ready']=1
            network['macs'][0]['last_heartbeat']=99
            manager.tick(); old['process'].send_signal.assert_not_called()
            network['macs'][0]['last_heartbeat']=100
            manager.tick()
            old['process'].send_signal.assert_called_once_with(signal.SIGTERM)
            new['process'].send_signal.assert_not_called()
            self.assertIs(manager.current, new)
            self.assertIsNone(manager.candidate)

    def test_failed_and_timed_out_replacements_keep_old_running(self):
        for failed in (True, False):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                manager=self.setup_manager(Path(tmp)); old,new=manager.pools
                if failed:
                    new['process'].poll.return_value=1
                else:
                    manager.deadline=0
                    manager.read=Mock(side_effect=TimeoutError('broker down'))
                manager.tick()
                self.assertIs(manager.current, old)
                old['process'].send_signal.assert_not_called()
                self.assertIsNone(manager.candidate)
                if not failed:
                    new['process'].send_signal.assert_called_once_with(signal.SIGTERM)

    def test_launch_passes_measured_drain_interval_and_shared_ownership_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); start=Mock()
            manager=pool_restart.Generations(root, 'broker', Mock(), start, 'relay')
            config=dict(source=root/'source', runner=root/'runner', workload=root/'workload', operator=root/'operator.json',
                        seconds=840, drain=270, replace=450)
            manager.launch(config)
            command=start.call_args.args[0]
            self.assertEqual(command[command.index('--drain-seconds')+1], '270')
            self.assertEqual(command[command.index('--pool-root')+1], root)

    def test_source_upgrade_keeps_ready_slots_through_boot_and_old_retirement(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pool_restart, 'hardware', return_value=dict(mem_bytes=64<<30, cores=14)):
            root = Path(tmp)
            _, _, restart = ConfigTests().release(root)
            publisher = Mock(account=SimpleNamespace(address='publisher'))
            publisher.tick.return_value = dict(event='heartbeat_posted', updated_at=100)
            start = Mock(return_value=Mock(poll=Mock(return_value=None)))
            manager = pool_restart.Generations(root, 'broker', publisher, start, 'relay')
            old_state = root/'old'; old_state.mkdir()
            def write_slots(state, ready):
                (state/'directory.json').write_text(json.dumps(dict(config=dict(max_guests=4),
                    hardware={}, classes=['class'], errors=[], slots=[dict(slot_id=i,
                    state='ready' if i < ready else 'launching', relay_peer=state.name+str(i)) for i in range(4)])))
            write_slots(old_state, 4)
            old = dict(state=old_state, process=Mock(poll=Mock(return_value=None)))
            manager.current = old; manager.pools = [old]
            manager.restart(restart)
            new = manager.candidate
            self.assertEqual(start.call_args.args[0][1], root/'new-source/applications/compute-node/pool.py')
            counts = []
            def tick():
                snapshot = manager.tick()
                counts.append(sum(s['state'] == 'ready' for s in snapshot['slots']))
                self.assertGreater(counts[-1], 0)
            # There is no candidate directory during startup; old slots stay advertised.
            tick()
            write_slots(new['state'], 0)
            tick(); old['process'].send_signal.assert_not_called()
            live = dict(admit_until=pool.time.time()+300, kind='compute',
                relay_peer=new['state'].name+'0', manifest_sha256=new['config']['measurement'],
                os_image_hash=new['config']['image'], attestation=dict(status='verified'))
            network = dict(macs=[dict(publisher='publisher', online=True, ready=5, last_heartbeat=100)])
            manager.read = Mock(side_effect=lambda path: [live] if path == '/nodes' else network)
            write_slots(new['state'], 1)
            tick()
            old['process'].send_signal.assert_called_once_with(signal.SIGTERM)
            self.assertEqual(publisher.version, 'next')
            self.assertIs(manager.current, new)
            # Even if all old guests expire now, the new generation supplies capacity.
            old['process'].poll.return_value = 0
            for ready in range(1, 5):
                write_slots(new['state'], ready)
                tick()
            self.assertEqual(counts, [4, 4, 5, 1, 2, 3, 4])
            new['process'].send_signal.assert_not_called()


if __name__ == '__main__':
    unittest.main()
