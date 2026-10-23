"""Record admitted boot claims and validate actual live cmdline/root verity.

Component digests, metadata identity and loader mode are RECORDED CLAIMS, not
independent guest measurements of preboot consumed bytes. Authenticated
provenance requires the external verifier AND checker to join the original
receipt to authenticated native consumed-input facts and independent expected
facts. No guest fw_cfg transport is required or treated as authentication.
"""
import hashlib
import json
import os
import re
import stat
class BootObservationError(Exception):
    pass

def _validate_live_cmdline(admitted_cmdline: str, live_cmdline: str) -> None:
    # Exact current-profile production: remove one terminal LF from proc only.
    # Preserve the admitted UTF-8 string verbatim for the native/external join.
    if (not isinstance(admitted_cmdline, str) or not admitted_cmdline or
            any(c in admitted_cmdline for c in ('\n', '\r', '\x00'))):
        raise BootObservationError("invalid recorded admitted cmdline")
    if not isinstance(live_cmdline, str):
        raise BootObservationError("live /proc/cmdline is unavailable")
    live = live_cmdline[:-1] if live_cmdline.endswith('\n') else live_cmdline
    if live != admitted_cmdline:
        raise BootObservationError("live cmdline differs byte-for-byte from recorded admitted cmdline")


def _parse_verity_table(text):
    rows = []
    for line in text.splitlines():
        m = re.fullmatch(r"([^ :]+):\s+(.*)", line.strip())
        if not m:
            raise BootObservationError("verity table must name each target")
        t = m[2].split()
        if len(t) != 15 or t[2] != 'verity' or t[13:] != ['1', 'panic_on_corruption']:
            raise BootObservationError("expected complete verity v1 target with exactly required panic_on_corruption policy")
        try:
            nums = [int(t[i]) for i in (0,1,3,6,7,8,9)]
        except ValueError:
            raise BootObservationError("noninteger verity geometry") from None
        rows.append(dict(name=m[1], start=nums[0], sectors=nums[1], version=nums[2],
            data_device=t[4], hash_device=t[5], data_block_size=nums[3],
            hash_block_size=nums[4], num_data_blocks=nums[5], hash_start=nums[6],
            algorithm=t[10], root_digest=t[11], salt=t[12]))
    if len(rows) != 1:
        raise BootObservationError("exactly one active verity target is required")
    return rows[0]


def _device_id(value):
    if re.fullmatch(r"[0-9]+:[0-9]+", value):
        return tuple(map(int, value.split(':')))
    try:
        st = os.stat(value)
    except OSError as exc:
        raise BootObservationError("cannot observe backing device: %s" % exc) from None
    if not stat.S_ISBLK(st.st_mode):
        raise BootObservationError("verity backing path is not a block device")
    return os.major(st.st_rdev), os.minor(st.st_rdev)


def build_observation(bundle_dir, live_cmdline, verity_table_text, *,
                      loader_mode="held-fd", loader_observation=None, mountinfo_text=None, dm_info_text=None,
                      root_device_id=None):
    if not isinstance(loader_mode, str) or loader_mode not in ('held-fd', 'owned-copy'):
        raise BootObservationError("invalid recorded loader mode claim")
    # Optional legacy engineering input is only an additional consistency check;
    # it cannot establish provenance and is not needed by the production guest.
    keys = {'schema','loader_mode','kernel_sha256','initrd_sha256','rootfs_sha256','metadata_sha256','cmdline'}
    if loader_observation is not None:
        if (not isinstance(loader_observation, dict) or set(loader_observation) != keys or
                loader_observation['schema'] != 'dsmack.loader-consumed/1'):
            raise BootObservationError("invalid optional engineering claim shape")
        if loader_observation['loader_mode'] != loader_mode:
            raise BootObservationError("engineering claim differs from recorded loader mode")
    try:
        with open(os.path.join(bundle_dir,'metadata.json'),'rb') as stream:
            metadata_bytes = stream.read()
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise BootObservationError("duplicate admitted metadata key")
                value[key] = item
            return value
        md = json.loads(metadata_bytes, object_pairs_hook=unique)
    except (OSError, ValueError) as exc:
        raise BootObservationError("unreadable admitted metadata: %s" % exc) from None
    # These docs supply admitted RECORDED claims, never consumed-byte proof.
    names = dict(kernel_sha256='Image',initrd_sha256='initramfs.cpio.gz',
                 rootfs_sha256='rootfs.squashfs.verity',metadata_sha256='metadata.json')
    try:
        with open(os.path.join(bundle_dir,'sha256sum.txt')) as stream:
            lines = stream.read().splitlines()
        sums = {}
        for line in lines:
            match = re.fullmatch(r'([0-9a-f]{64})  ([^\s]+)', line)
            if not match or match[2] in sums:
                raise BootObservationError("invalid admitted checksum document")
            sums[match[2]] = match[1]
    except OSError as exc:
        raise BootObservationError("unreadable admitted checksums: %s" % exc) from None
    if any(not isinstance(sums.get(name), str) or not re.fullmatch('[0-9a-f]{64}', sums[name])
           for name in names.values()):
        raise BootObservationError("missing admitted component claim")
    if hashlib.sha256(metadata_bytes).hexdigest() != sums['metadata.json']:
        raise BootObservationError("admitted metadata bytes differ from recorded digest")
    cmdline = md.get('cmdline')
    recorded = {key:sums[name] for key,name in names.items()}
    recorded.update(loader_mode=loader_mode, cmdline=cmdline)
    if loader_observation is not None and any(loader_observation[key] != recorded[key] for key in recorded):
        raise BootObservationError("optional engineering claim differs from admitted recorded claim")
    _validate_live_cmdline(cmdline,live_cmdline)
    tokens = cmdline.split()
    def token(key, pattern):
        values = [t[len(key)+1:] for t in tokens if t.startswith(key+'=')]
        if len(values)!=1 or not re.fullmatch(pattern,values[0]):
            raise BootObservationError("missing/duplicate/malformed "+key)
        return values[0]
    root_hash=token('dstack.rootfs_hash','[0-9a-f]{64}')
    data_bytes=int(token('dstack.rootfs_size','[0-9]+'))
    device=token('dstack.rootfs_device',r'/dev/[A-Za-z0-9/_-]+')
    if not any(t.startswith('console=') for t in tokens):
        raise BootObservationError("missing console directive")
    p=_parse_verity_table(verity_table_text)
    if data_bytes<=0 or data_bytes%4096 or any((
        p['start']!=0,p['sectors']!=data_bytes//512,p['version']!=1,
        p['data_block_size']!=4096,p['hash_block_size']!=4096,
        p['num_data_blocks']!=data_bytes//4096,p['hash_start']!=data_bytes//4096+1,
        p['algorithm']!='sha256',p['root_digest']!=root_hash,p['salt']!='0'*64)):
        raise BootObservationError("active verity geometry/root/algorithm/salt substitution")
    if not isinstance(mountinfo_text,str) or not isinstance(dm_info_text,str):
        raise BootObservationError("live root mount and mapper identity observations required")
    roots=[]
    for row in mountinfo_text.splitlines():
        fields=row.split()
        if len(fields)>6 and fields[4]=='/':
            roots.append(_device_id(fields[2]))
    matches=[]
    for row in dm_info_text.splitlines():
        fields=row.strip().split(':')
        if len(fields)==3 and fields[0]==p['name']:
            matches.append(_device_id(':'.join(fields[1:])))
    if len(roots)!=1 or matches!=roots:
        raise BootObservationError("active target does not back the running root mount")
    # root_device_id is a live major:minor obtained by stat of the cmdline's
    # rootfs block path. Tests may supply that syscall result explicitly.
    actual_device = _device_id(device) if root_device_id is None else _device_id(root_device_id)
    if _device_id(p['data_device'])!=actual_device or _device_id(p['hash_device'])!=actual_device:
        raise BootObservationError("verity data/hash devices differ from running root backing device")
    result=dict(recorded)
    result.update(schema='dsmack.vm-boot-observation/1',
                  verity_root_hash=root_hash,verity_data_bytes=data_bytes)
    return result
