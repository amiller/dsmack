"""Pack the launcher's generated public tree on macOS and validate the result."""
import hashlib,io,os,sys,tarfile
from pathlib import Path


def pack_public(tree,out,selector,manifest_sha256):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pilot-client'))
    from public_task import scan_payload
    files=sorted(p for p in tree.rglob('*') if p.is_file())
    sums=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(tree).as_posix()+'\n' for p in files).encode()
    with out.open('xb') as dest:
        os.chmod(out,0o600)
        with tarfile.open(fileobj=dest,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
            for p in sorted(tree.rglob('*')):
                if p.is_symlink():raise ValueError('generated public tree contains a symlink')
                info=tarfile.TarInfo(p.relative_to(tree).as_posix());info.mtime=1784592000
                if p.is_dir():info.type=tarfile.DIRTYPE;info.mode=0o700;tar.addfile(info)
                else:
                    info.mode=0o600;info.size=p.stat().st_size
                    with p.open('rb') as src:tar.addfile(info,src)
            info=tarfile.TarInfo('SHA256SUMS');info.mode=0o600;info.mtime=1784592000;info.size=len(sums)
            tar.addfile(info,io.BytesIO(sums))
        dest.write(b'\0'*((-dest.tell())%(1<<20)));dest.flush();os.fsync(dest.fileno())
    digest=hashlib.sha256()
    with out.open('rb') as src:
        for b in iter(lambda:src.read(1<<20),b''):digest.update(b)
    scan_payload(dict(path=str(out.resolve()),bytes=out.stat().st_size,sha256=digest.hexdigest()),selector,manifest_sha256)
