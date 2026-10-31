"""Measured Mac networking admits only the host-loopback CONNECT proxy."""
import json
from pathlib import Path
import unittest
import workload

ROOT = Path(__file__).resolve().parents[2]
RELAY = '/ip4/127.0.0.1/tcp/18082/ws/p2p/12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x'
INDEX = 'https://pod.dstack.soc1024.com/private-agent/tunnels'


class MacWorkloadTests(unittest.TestCase):
    def generate(self, seconds=840, **kwargs):
        return workload.manifest(ROOT/'applications/compute-node/testdata/compose-manifest.json',
            'sha256:'+'01'*32, Path(workload.__file__), RELAY,
            'https://pod.dstack.soc1024.com/relay-broker', '02'*32, '03'*32, seconds,
            'http://192.168.127.254:18484', **kwargs)

    def test_mac_mode_has_no_dns_pin_or_direct_network_route(self):
        measured = json.loads(self.generate(tunnel_index=INDEX))
        node = json.loads(measured['docker_compose_file'])['services']['node']
        env = node['environment']
        self.assertEqual(env['BROKER_GATEWAY'], 'http://127.0.0.1:18080')
        self.assertEqual(env['TUNNEL_INDEX'], INDEX)
        self.assertEqual(env['HTTPS_PROXY'], 'http://192.168.127.254:18484')
        self.assertEqual(measured['network']['egress'], [
            {'destination':'192.168.127.254/32','protocol':'tcp','port':18484}])
        self.assertEqual(node['command'][1], RELAY)
        self.assertEqual(env['ADMIT_SECONDS'], '360')
        self.assertTrue({'egress-checks','gateway-log'}.issubset({a['name'] for a in measured['outputs']['artifacts']}))

    def test_hour_guest_binds_lifetime_and_paid_run_to_its_measured_compose(self):
        payments = {'runSeconds': 3600}
        measured = json.loads(self.generate(seconds=3600, tunnel_index=INDEX, payments=payments))
        node = json.loads(measured['docker_compose_file'])['services']['node']
        self.assertEqual(node['command'][2], '3600')
        self.assertEqual(node['environment']['ADMIT_SECONDS'], '3120')
        self.assertEqual(json.loads(node['environment']['PAYMENTS_CONFIG'])['runSeconds'], 3600)
        self.assertEqual(measured['limits']['timeout_s'], 3600)
        with self.assertRaisesRegex(ValueError, '1..3600'):
            self.generate(seconds=3601, tunnel_index=INDEX)

    def test_requested_guest_size_changes_measured_manifest(self):
        default = self.generate(tunnel_index=INDEX)
        large = self.generate(tunnel_index=INDEX, guest={'mem_mib': 8192, 'vcpus': 2})
        self.assertNotEqual(default, large)
        manifest = json.loads(large)
        self.assertEqual(manifest['base_vm']['memory_mb'], 8192)
        self.assertEqual(manifest['base_vm']['vcpus'], 2)

    def test_mac_mode_requires_its_explicit_https_index(self):
        with self.assertRaisesRegex(ValueError, 'HTTPS broker and tunnel index'):
            self.generate()
        with self.assertRaisesRegex(ValueError, 'HTTPS broker and tunnel index'):
            self.generate(tunnel_index='https://other.invalid/tunnels')


if __name__ == '__main__':
    unittest.main()
