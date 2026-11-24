#!/usr/bin/env python3
"""pack.py REPO BASE TEMPLATE_MANIFEST OCI_DIR DIGEST OUT
Writes OUT/compose-manifest.json and OUT/disk/workload.img for the dev-session-v1 proof of concept.
REPO is a dsmack checkout whose contract library has dev-session-v1; BASE holds the image files."""
import hashlib, json, sys
from pathlib import Path
repo, base, template, oci = map(Path, sys.argv[1:5])
digest, out = sys.argv[5], Path(sys.argv[6])
sys.path.insert(0, str(repo / 'dstack-compat'))
import canary_workload
NAME = 'dev-session-poc-v1'
run_sh = Path(__file__).with_name('image') / 'run.sh'
m = json.loads(template.read_bytes())
meta = json.loads((base / 'metadata.json').read_bytes())
fsha = canary_workload.fsha
service = {'image': '127.0.0.1:5005/dev-session-poc@' + digest, 'entrypoint': ['/opt/dev/run.sh'],
           'read_only': True, 'security_profile': 'dev-session-v1',
           'volumes': ['artifacts:/workspace/artifacts:rw', '/var/run/dstack.sock:/var/run/dstack.sock:ro']}
# ghcr.io and its blob CDN, plus gvproxy's resolver.
egress = [{'destination': d, 'protocol': 'tcp', 'port': 443} for d in ('140.82.112.0/20', '185.199.108.0/22')]
egress += [{'destination': '192.168.127.1/32', 'protocol': p, 'port': 53} for p in ('udp', 'tcp')]
m.update(name=NAME, allowed_envs=[], required_envs=[], allowed_files=[],
         base_vm=dict(m['base_vm'], cmdline=meta['cmdline'], initrd_sha256=fsha(base / 'initramfs.cpio.gz'),
                      kernel_sha256=fsha(base / 'Image'), metadata_sha256=fsha(base / 'metadata.json'),
                      os_image_hash=fsha(base / 'sha256sum.txt'), rootfs_sha256=fsha(base / 'rootfs.squashfs.verity'),
                      verity_root_hash=meta['cmdline'].split('dstack.rootfs_hash=')[1].split()[0]),
         network={'mode': 'nat', 'listen_ports': [], 'egress': egress},
         harness={'name': 'dev-session-poc', 'path': '/opt/dev/run.sh', 'sha256': fsha(run_sh), 'version': 'dev-session-poc-1'},
         docker_compose_file=canary_workload.canon({'services': {'dev': service}}).decode(),
         outputs={'capture': ['stdout', 'stderr'], 'artifacts': [
             {'name': n.replace('.', '-'), 'path': '/workspace/artifacts/' + n} for n in ('result.txt', 'attestation.json')]})
m['limits'] = dict(m['limits'], timeout_s=900)
raw = canary_workload.canon(m)
out.mkdir()
(out / 'compose-manifest.json').write_bytes(raw)
canary_workload.pack(repo, base, oci, out / 'disk', NAME, raw)
