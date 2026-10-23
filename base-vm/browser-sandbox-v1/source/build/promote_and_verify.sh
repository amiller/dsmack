#!/bin/bash
# Post-build: two-leg byte-compare (reproducibility), promote legA, admission
# (+tamper), IMAGE-MANIFEST.json. Owned adaptation of
# dstack-smoke-finish/source/build/promote_and_verify.sh (prior lane,
# read-only), reflecting THIS lane's method: both legs share the PROVEN
# ec83a3fc kernel bytes (no kernel rebuild) and independently run debootstrap
# + runner-content install + assembly; all 8 artifacts must be byte-identical
# across legs.
# Runs INSIDE dsmack-dstack-arm64/builder:trixie-20260721 with this lane at /w.
set -euo pipefail
W=/w
LANE=$W
LEGDIR=$LANE/build/legs
EV=$LANE/evidence
mkdir -p "$EV"

for L in legA legB; do
  [ -f "$LEGDIR/$L.rc" ] && grep -q "rc=0" "$LEGDIR/$L.rc" || { echo "leg $L did not complete rc=0" >&2; exit 1; }
done

python3 - <<'PY'
import hashlib, json, os
LANE = '/w'
LEGDIR = os.path.join(LANE, 'build/legs')
EV = os.path.join(LANE, 'evidence')
FILES = ['Image', 'config-6.18.40-dstack', 'rootfs.squashfs.verity', 'initramfs.cpio.gz',
         'metadata.json', 'sha256sum.txt', 'digest.txt', 'artifact-manifest.json',
         'scratch-template.ext4', 'result-template.ext4', 'disk-templates.json']

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()

arts = {}
ok = True
for name in FILES:
    a = os.path.join(LEGDIR, 'legA', 'files', name)
    b = os.path.join(LEGDIR, 'legB', 'files', name)
    ha, hb = sha(a), sha(b)
    identical = ha == hb
    ok = ok and identical
    arts[name] = {'legA_sha256': ha, 'legB_sha256': hb, 'identical': identical,
                  'bytes': os.path.getsize(a)}

def leg_digest(leg):
    return sha(os.path.join(LEGDIR, leg, 'files', 'sha256sum.txt'))

pkg_same = (open(os.path.join(LEGDIR, 'legA', 'guest-packages.txt')).read()
            == open(os.path.join(LEGDIR, 'legB', 'guest-packages.txt')).read())
tarA = open(os.path.join(LEGDIR, 'legA', 'rootfs-tar.sha256')).read().strip()
tarB = open(os.path.join(LEGDIR, 'legB', 'rootfs-tar.sha256')).read().strip()
runner_sums = os.path.join(LEGDIR, 'legA', 'work', 'rootfs',
                           'usr/local/lib/dsmack/compose-runner/SHA256SUMS')
repro = {
  'schema': 'dsmack-repro-check/1',
  'legs': ['build/legs/legA', 'build/legs/legB'],
  'method': ('two full independent rootfs+assembly builds: each leg its own debootstrap --foreign '
             'from the pinned snapshot (seeded from the prior-lane read-only cache), its own '
             'runner-content install, its own module-store extraction from the PROVEN verity '
             'rootfs, and its own tar -> squashfs -> verity -> initramfs -> checksum-manifest '
             'assembly. Kernel bytes (Image + config) are taken byte-identical from the PROVEN '
             'dstack-smoke-finish bundle ec83a3fc… (kernel hash-pinned inside build_leg_rootfs.sh '
             'before any build step; no kernel rebuild in this lane, provenance preserved).'),
  'kernel_rebuilt_in_this_lane': False,
  'kernel_source': {'bundle_os_image_hash': 'ec83a3fcc72dda79b74747460b886971ffee34185e6061c1844549502cc44d08',
                    'Image_sha256': arts['Image']['legA_sha256'],
                    'proven_lane': 'dstack-smoke-finish (boot-proven, evidence boot-smokefinish-try2-summary.json)'},
  'guest_packages_txt_identical': pkg_same,
  'rootfs_tar_sha256_identical': tarA == tarB,
  'rootfs_tar_sha256': tarA,
  'runner_content_sha256sums': 'installed at usr/local/lib/dsmack/compose-runner/SHA256SUMS (in rootfs)',
  'assembly_pipeline': 'tar -> regular file (rc checked) -> mksquashfs - <tarfile -tar (rc checked)',
  'artifacts': arts,
  'reproducible': ok and pkg_same and tarA == tarB,
  'os_image_hash_legA': leg_digest('legA'),
  'os_image_hash_legB': leg_digest('legB'),
}
json.dump(repro, open(os.path.join(EV, 'repro.json'), 'w'), indent=1)
print(json.dumps({'reproducible': repro['reproducible'],
                  'os_image_hash': repro['os_image_hash_legA'],
                  'per_artifact': {k: v['identical'] for k, v in arts.items()}}, indent=1))
if not repro['reproducible']:
    raise SystemExit('REPRO FAILED: legs differ')
PY

rm -rf "$LANE/build/artifacts"
cp -a "$LEGDIR/legA/files" "$LANE/build/artifacts"
cp -a "$LEGDIR/legA/guest-packages.txt" "$LANE/build/guest-packages.txt"

python3 "$LANE/source/tests/verify_manifest.py" "$LANE/build/artifacts" --tamper-test \
  > "$EV/admission.log" 2>&1 || { cat "$EV/admission.log"; echo 'ADMISSION REJECTED'; exit 1; }
cat "$EV/admission.log"

python3 - <<'PY'
import hashlib, json, os
LANE = '/w'
B = os.path.join(LANE, 'build')
EV = os.path.join(LANE, 'evidence')

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()

names = ['Image', 'config-6.18.40-dstack', 'rootfs.squashfs.verity', 'initramfs.cpio.gz',
         'metadata.json', 'sha256sum.txt', 'digest.txt', 'artifact-manifest.json',
         'scratch-template.ext4', 'result-template.ext4', 'disk-templates.json']
arts = {n: {'sha256': sha(os.path.join(B, 'artifacts', n)),
            'bytes': os.path.getsize(os.path.join(B, 'artifacts', n))} for n in names}
os_image_hash = open(os.path.join(B, 'artifacts', 'digest.txt')).read().strip()
md = json.load(open(os.path.join(B, 'artifacts', 'metadata.json')))
am = json.load(open(os.path.join(B, 'artifacts', 'artifact-manifest.json')))
pkgs = [l.strip() for l in open(os.path.join(B, 'guest-packages.txt')) if l.strip()]

manifest = {
  'schema': 'dsmack-image-manifest/1',
  'image': {'name': 'dstack-trixie-arm64-minimal', 'version': '0.6.3.runner',
            'platform': 'arm64', 'os_image_hash': os_image_hash,
            'os_image_hash_definition': 'sha256(sha256sum.txt)'},
  'boot': {'kernel': 'Image', 'initrd': 'initramfs.cpio.gz',
           'kernel_version': '6.18.40-dstack',
           'kernel_source_sha256': '3712fc1ec839e4daac981176c8518912e8f452650aaedfe4381da4419613a431',
           'kernel_config': 'config-6.18.40-dstack',
           'cmdline': md['cmdline'], 'cmdline_source': 'verified metadata.json (single definition source/profile/dstack-trixie-arm64-minimal/kernel-cmdline.sh)',
           'root_device': '/dev/vda (unpartitioned raw squashfs+verity)'},
  'verity': {'root_hash': am['verity']['root_hash'], 'data_size': am['verity']['data_size'],
             'data_block_size': 4096, 'hash_block_size': 4096,
             'salt': '0'*64, 'uuid': '00000000-0000-0000-0000-000000000000',
             'hash_offset': int(am['verity']['data_size']), 'format': 'squashfs zstd + dm-verity'},
  'artifacts': arts,
  'guest_stack': {'packages': pkgs,
                  'container_stack_note': ('docker.io 26.1.5+dfsg1 / docker-compose 2.26.1-4 (usr/libexec/docker/cli-plugins, distro standalone) / '
                                           'containerd 1.7.24~ds1 / runc 1.1.15+ds1; iptables 1.8.11 nf_tables backend; '
                                           '+ python3 (runner dependency), all from the same pinned snapshot')},
  'runner_join': {'source': 'source/runner-content (verified byte-identical copy of the approved contract10 compose_runner package + frozen contract library; evidence/runner-content-copy-verify.txt)',
                  'installed_at': '/usr/local/lib/dsmack/compose-runner (+ /usr/local/bin/dsmack-compose-runner installed-form wrapper)',
                  'approval': 'contract10-review/astra-gate.json approved_for_implementation=true; contract_sha256 b0e8349910511ca29034f7585b6e9ae7e6cf7599e5a160ae5f2898cf14d80a45'},
  'provenance': {
    'upstream': 'Dstack-TEE/dstack@247c3add65d0e8e6ba90eae5f6b981a9063cf701',
    'pins': {'kernel_tarball_sha256': '3712fc1ec839e4daac981176c8518912e8f452650aaedfe4381da4419613a431',
             'debian_snapshot': '20260721T000000Z'},
    'profile': 'source/profile/dstack-trixie-arm64-minimal',
    'deltas_vs_upstream': 'minimal container-stack profile (see prior lanes); kernel fragment carries the NFT repair block; this lane adds the runner join (python3 + compose_runner + contract library)',
    'excluded_by_policy': 'TEE/GPU/KMS/gateway/dstack-agent/KMS/key-provider',
    'reproducibility': 'evidence/repro.json (two-leg byte-compare; kernel bytes by reference to the proven bundle)',
    'lane4_dstack-runner-join': {
      'supersedes_os_image_hash': 'ec83a3fcc72dda79b74747460b886971ffee34185e6061c1844549502cc44d08',
      'kernel_by_reference': 'Image 415e59cc… + config taken byte-identical from the proven bundle; module store extracted per leg from its verity rootfs; NOT a relabel — the new identity is the sha256(sha256sum.txt) of this bundle',
      'join_deltas': ['guest packages += python3', 'runner content installed under /usr/local/lib/dsmack/compose-runner + CLI wrapper', 'supervisor: export disk (vdd), slirp network, RUNNER PHASE over external manifests, digest-pinned boundary probe'],
      'prior_lane_bundle_unchanged': '/data/amiller/dsmack/attested-runner-20261020/dstack-smoke-finish/build/artifacts (read-only input)'}},
  'consumer_api': {
    'admission': 'docker run --rm -v <lane>:/w <builder> python3 /w/source/tests/verify_manifest.py /w/build/artifacts [--tamper-test]',
    'launch_contract': 'console=ttyAMA0 prepended, console=hvc0 LAST; vda verity rootfs ro, vdb scratch ext4 (fresh mkfs per run, docker data-root), vdc workload tar disk (manifests/envelopes/admission/base-bundle), vdd export ext4 (receipts/artifacts)',
    'image_replacement_semantics': 'same launcher boots any admitted bundle by path+os_image_hash pin; no recompile'}
}
json.dump(manifest, open(os.path.join(B, 'IMAGE-MANIFEST.json'), 'w'), indent=1)
open(os.path.join(B, 'IMAGE-MANIFEST.json'), 'a').write('\n')
print('IMAGE-MANIFEST.json written; os_image_hash =', os_image_hash)
PY
echo PROMOTE-AND-VERIFY-DONE
