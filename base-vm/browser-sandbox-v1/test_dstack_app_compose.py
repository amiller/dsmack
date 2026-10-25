import hashlib, json, pathlib, sys, unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent / "source/runner-content/lib"))
from dsmack_compose_contract.errors import MultiError
from dsmack_compose_contract.manifest import validate_manifest_bytes

H = lambda c: c * 64
ROOTFS = H("6")
COMPOSE = json.dumps({"services": {"worker": {"image": "127.0.0.1:5005/worker@sha256:" + H("2"), "entrypoint": ["/usr/bin/python3", "-I"],
                                              "command": ["/worker.py"], "read_only": True}}})
DSMACK = {
    "base_vm": {"architecture": "aarch64", "memory_mb": 4096, "vcpus": 1, "verity_root_hash": ROOTFS, "os_image_hash": H("a"),
                "rootfs_sha256": H("b"), "kernel_sha256": H("c"), "initrd_sha256": H("d"), "metadata_sha256": H("e"),
                "cmdline": f"console=hvc0 init=/init panic=1 oops=panic net.ifnames=0 biosdevname=0 dstack.rootfs_hash={ROOTFS} "
                           f"dstack.rootfs_size=217137152 dstack.rootfs_device=/dev/vda dstack.scratch_template_sha256={H('7')} "
                           f"dstack.result_template_sha256={H('8')}"},
    "runner": {"kind": "oci-compose", "container_runtime": "runc", "runtime_name": "runc", "runtime_version": "1.1.15+ds1",
               "compose_tool": {"name": "docker-compose", "version": "2.26.1-4"},
               "runtime_closure": {"components": [{"name": "runc", "path": "/usr/bin/runc", "registration_args": [], "sha256": H("9")}]}},
    "harness": {"name": "python-application", "path": "/usr/bin/python3", "sha256": H("1"), "version": "worker-v1"},
    "image_platform": {"architecture": "arm64", "os": "linux"},
    "required_envs": [], "allowed_files": [],
    "runtime_inputs": {"env": {"mode": "inject"}, "stdin": {"max_bytes": 0, "mode": "none"}, "user_config": {"max_bytes": 0, "mode": "none"}},
    "network": {"mode": "none", "listen_ports": []},
    "outputs": {"capture": ["stdout"], "artifacts": []},
    "limits": {"output_max_bytes": 16777216, "timeout_s": 300, "workspace_max_bytes": 67108864},
}


def app_compose(**extra):
    return json.dumps({"manifest_version": 2, "name": "worker", "runner": "docker-compose", "docker_compose_file": COMPOSE,
                       "allowed_envs": [], "kms_enabled": True, "dsmack": DSMACK, **extra}).encode()


class DstackAppCompose(unittest.TestCase):
    def test_one_hash_names_the_workload_on_both_platforms(self):
        raw = app_compose()
        manifest, summary = validate_manifest_bytes(raw)
        v4 = json.dumps(dict(DSMACK, manifest_version=4, name="worker", docker_compose_file=COMPOSE, allowed_envs=[])).encode()
        _, v4_summary = validate_manifest_bytes(v4)
        self.assertEqual(summary["manifest_sha256"], hashlib.sha256(raw).hexdigest())  # dstack's compose_hash
        self.assertEqual({**summary, "manifest_sha256": None}, {**v4_summary, "manifest_sha256": None})

    def test_dstack_fields_dsmack_does_not_implement_are_refused(self):
        for extra in ({"key_provider": "local"}, {"init_script": "true"}, {"manifest_version": 3}):
            with self.assertRaises(MultiError, msg=extra):
                validate_manifest_bytes(app_compose(**extra))


if __name__ == "__main__":
    unittest.main()
