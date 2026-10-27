import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "source/runner-content/lib"))
from dsmack_compose_contract.egress import apply
from dsmack_compose_contract.errors import MultiError
from dsmack_compose_contract.lowering import lower, render_egress_rules
from dsmack_compose_contract.manifest import validate_manifest_bytes
from test_dstack_app_compose import COMPOSE, DSMACK


def raw(egress=(), mode="nat"):
    manifest = copy.deepcopy(DSMACK)
    manifest.update(manifest_version=4, name="worker", docker_compose_file=COMPOSE, allowed_envs=[])
    manifest["network"] = {"mode": mode, "listen_ports": []}
    if egress != ():
        manifest["network"]["egress"] = egress
    return json.dumps(manifest).encode()


class Egress(unittest.TestCase):
    def test_destinations_are_measured_and_lowered_for_output_and_forward(self):
        entries = [{"destination": "203.0.113.7", "protocol": "tcp", "port": 443},
                   {"destination": "2001:db8::/64", "protocol": "udp", "port": 51820}]
        encoded = raw(entries)
        manifest, summary = validate_manifest_bytes(encoded)
        self.assertEqual(summary["manifest_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertNotEqual(summary["manifest_sha256"], validate_manifest_bytes(raw([]))[1]["manifest_sha256"])
        lowered = lower(manifest, summary["manifest_sha256"], daemon_endpoint="unix:///run/docker.sock", run_id="test")
        rules = lowered["egress_nftables"]
        for hook in ("output", "forward"):
            chain = rules.split(" chain " + hook + " {", 1)[1].split(" }", 1)[0]
            self.assertIn("policy drop;", chain)
            self.assertIn("ip daddr 203.0.113.7/32 tcp dport 443 counter accept", chain)
            self.assertIn("ip6 daddr 2001:db8::/64 udp dport 51820 counter accept", chain)
        self.assertNotIn("1.1.1.1", rules)

    def test_absent_and_empty_allowlist_deny_both_ip_families(self):
        for encoded in (raw(), raw([]), raw([], "none")):
            manifest, _ = validate_manifest_bytes(encoded)
            rules = render_egress_rules(manifest)
            self.assertEqual(rules.count("policy drop;"), 2)
            self.assertNotIn("daddr", rules)

    def test_bad_destinations_cannot_widen_or_inject_firewall_rules(self):
        good = {"destination": "203.0.113.7", "protocol": "tcp", "port": 443}
        for field, value in (("destination", "example.com"), ("destination", "10.0.0.1/24"),
                             ("destination", "fe80::1%eth0"), ("destination", "1.1.1.1; accept"),
                             ("destination", 123), ("protocol", "icmp"), ("protocol", None),
                             ("port", True), ("port", 0), ("port", 65536), ("port", "443"),
                             ("ports", [443])):
            with self.subTest(field=field, value=value), self.assertRaises(MultiError):
                validate_manifest_bytes(raw([{**good, field: value}]))
        for entries in (None, {}, [None], [{}]):
            with self.subTest(entries=entries), self.assertRaises(MultiError):
                validate_manifest_bytes(raw(entries))
        with self.assertRaises(MultiError):
            validate_manifest_bytes(raw([good], "none"))

    def test_nft_failure_propagates_to_supervisor(self):
        for error in (FileNotFoundError(), subprocess.CalledProcessError(1, "nft"),
                      subprocess.TimeoutExpired("nft", 30)):
            with self.subTest(error=type(error)), patch("dsmack_compose_contract.egress.subprocess.run", side_effect=error):
                with self.assertRaises(type(error)):
                    apply(raw([]))

    def test_dstack_compose_wrapper_keeps_the_measured_egress_policy(self):
        v4 = json.loads(raw([{"destination": "192.0.2.0/24", "protocol": "udp", "port": 53}]))
        wrapped = {"manifest_version": 2, "name": v4.pop("name"), "runner": "docker-compose",
                   "docker_compose_file": v4.pop("docker_compose_file"),
                   "allowed_envs": v4.pop("allowed_envs"), "kms_enabled": True}
        del v4["manifest_version"]
        encoded = json.dumps(dict(wrapped, dsmack=v4)).encode()
        manifest, summary = validate_manifest_bytes(encoded)
        self.assertEqual(summary["manifest_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertIn("ip daddr 192.0.2.0/24 udp dport 53 counter accept", render_egress_rules(manifest))


if __name__ == "__main__":
    unittest.main()
