#!/usr/bin/env python3
"""Reclaim Mac disk from releases and pool generations that launchd no longer runs.

dsmack_gc.py gc [--dry-run]       among ~/dsmack-* releases (a source checkout or pool-command.json), keep those named by a launchd pool (plist, command JSON, restart.json), a running
                                  process or ~/.dsmack/gc-pins, plus the newest other release as rollback; preserve the
                                  rest's small files under ~/.dsmack/gc-keep and delete them; reap every pool root
dsmack_gc.py reap ROOT            retire the disks of stopped generations' runs under one pool root
dsmack_gc.py store PATH...        put big files into the content-addressed store and leave APFS clones in their place
dsmack_gc.py source COMMIT DEST   check COMMIT out at DEST as a worktree of the one shared bare repository
"""
import argparse,contextlib,fcntl,gzip,hashlib,json,os,plistlib,re,shutil,subprocess,sys,time
from pathlib import Path

HOME=Path.home();DSMACK=HOME/'.dsmack'
STORE,BARE,PINS,KEEP=DSMACK/'store',DSMACK/'dsmack.git',DSMACK/'gc-pins',DSMACK/'gc-keep'
URL='https://github.com/amiller/dsmack.git'
RELEASES='dsmack-*'
DISKS=('scratch.img','workload.img','inputs.img','*.staged','.*.partial')
REGENERABLE={'.git','source','node_modules','venv','.venv','__pycache__','.build','swift-build','DerivedData','oci','blobs','build','checkouts'}
IMAGE_SUFFIXES={'.img','.ext4','.raw','.verity','.staged','.partial','.pack','.a','.o','.dylib','.tar','.tgz','.zst','.squashfs'}
SMALL=50<<20;BIG=16<<20;YOUNG=600


def clone(src,dst):
    subprocess.run(['cp','-c',str(src),str(dst)],check=True)


def sha(path,opener=open):
    digest=hashlib.sha256()
    with opener(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1<<20),b''):digest.update(chunk)
    return digest.hexdigest()


def alive(pid):
    try:os.kill(pid,0)
    except ProcessLookupError:return False
    except PermissionError:pass
    return True


@contextlib.contextmanager
def locked():
    """One gc or reap at a time across the pools and launchers sharing this volume; a busy lock skips."""
    DSMACK.mkdir(parents=True,exist_ok=True)
    with (DSMACK/'gc.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            log(dict(event='gc_busy'));yield False;return
        yield True


def processes():
    return subprocess.run(['ps','-axww','-o','command='],capture_output=True,text=True,check=True).stdout


def log(record):
    KEEP.mkdir(parents=True,exist_ok=True)
    with (KEEP/'gc.jsonl').open('a') as stream:stream.write(json.dumps({'at':int(time.time()),**record})+'\n')
    print(json.dumps(record),flush=True)


def pool_jobs(agents):
    """(root, texts naming its live paths) for each launchd pool definition."""
    for plist in sorted(agents.glob('org.dsmack.pool.*.plist')):
        args=plistlib.loads(plist.read_bytes())['ProgramArguments']
        root,command=Path(args[args.index('--root')+1]),Path(args[args.index('--command')+1])
        argv=json.loads(command.read_text())
        restart=[Path(a.split('=',1)[1]) if '=' in a else Path(argv[i+1]) for i,a in enumerate(argv) if a.split('=',1)[0]=='--restart-config']
        restart=(restart or [root/'restart.json'])[0]
        yield root,[json.dumps(args),json.dumps(argv)]+([restart.read_text()] if restart.is_file() else [])


def live_releases(releases,texts):
    """Releases holding any absolute path in texts, closed over the symlinks inside each live release."""
    paths=[Path(p) for text in texts for p in re.findall(r'/[^\s"\',:<>]+',text)]
    found=set()
    def owner(path):
        return next((r for r in releases if path==r or r in path.parents),None)
    while paths:
        path=paths.pop()
        for candidate in {path,Path(os.path.realpath(path))}:
            release=owner(candidate)
            if release and release not in found:
                found.add(release)
                for dp,dns,fns in os.walk(release):
                    paths+=[Path(os.path.realpath(Path(dp)/n)) for n in dns+fns if os.path.islink(Path(dp)/n)]
                    dns[:]=[d for d in dns if d not in REGENERABLE and not os.path.islink(Path(dp)/d)]
    return found


def keepable(path):
    if path.is_symlink():return True
    if not path.is_file() or path.suffix in IMAGE_SUFFIXES or path.name=='Image' or path.name.endswith('.tar.gz'):return False
    if path.stat().st_size>=SMALL:return False
    with path.open('rb') as stream:
        return stream.read(4) not in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe')


def preserve(release):
    """Copy keys, configs, records and logs under 50 MB to gc-keep; regenerable trees and images stay behind."""
    dest=KEEP/release.name;kept=0
    source=release/'source'
    if (source/'.git').exists():
        diff=subprocess.run(['git','-C',str(source),'diff','HEAD'],capture_output=True,text=True,check=True).stdout
        if diff:(dest).mkdir(parents=True,exist_ok=True);(dest/'source.patch').write_text(diff)
    for dp,dns,fns in os.walk(release):
        links=[d for d in dns if os.path.islink(Path(dp)/d)]
        dns[:]=[d for d in dns if d not in REGENERABLE and not d.endswith('.app') and d not in links]
        for name in fns+links:
            path=Path(dp)/name
            if not keepable(path):continue
            target=dest/path.relative_to(release);target.parent.mkdir(parents=True,exist_ok=True)
            if path.is_symlink():target.unlink(missing_ok=True);os.symlink(os.readlink(path),target)
            else:shutil.copy2(path,target)
            kept+=1
    return kept


def allocated(path):
    return sum(f.lstat().st_blocks*512 for f in [path,*path.rglob('*')])


def remove(release,dry_run):
    size=allocated(release)
    if dry_run:return log(dict(event='would_remove',release=str(release),bytes=size))
    kept=preserve(release)
    subprocess.run(['chmod','-R','u+w',str(release)],check=True)
    shutil.rmtree(release)
    log(dict(event='removed',release=str(release),bytes=size,kept_files=kept,kept_in=str(KEEP/release.name)))


def reap(root,dry_run=False):
    """Gzip result.img (hash-checked) and delete the other disks of runs no live launcher or process owns.
    ps is read again for each run, and runs touched in the last YOUNG seconds wait: an orphaned pool.py can still launch."""
    freed=0
    for generation in sorted(root.glob('pool-*')):
        pid=generation/'launcher.pid'
        if pid.is_file() and pid.read_text().strip().isdigit() and alive(int(pid.read_text())):continue
        for run in sorted(generation.glob('**/run-*')):
            if not run.is_dir() or time.time()-run.stat().st_mtime<YOUNG or run.name in processes():continue
            for disk in [f for pattern in DISKS for f in run.rglob(pattern)]+list(run.rglob('result.img')):
                attempt=re.search(r'dsmack-attempt\.(\d+)\.',disk.name)
                if not disk.is_file() or disk.is_symlink() or (attempt and alive(int(attempt[1]))):continue
                freed+=disk.stat().st_blocks*512
                if dry_run:continue
                if disk.name=='result.img':
                    packed=run/'evidence/result.img.gz'  # where pool.py's preserve_and_retire keeps it
                    packed.parent.mkdir(exist_ok=True)
                    with disk.open('rb') as src,gzip.open(packed,'wb') as dest:shutil.copyfileobj(src,dest,1<<20)
                    if sha(packed,gzip.open)!=sha(disk):raise RuntimeError('gzipped result differs: '+str(disk))
                disk.unlink()
    log(dict(event='reaped',root=str(root),bytes=freed,dry_run=dry_run))
    return freed


def store(paths):
    """Replace each big file with an APFS clone of its content-addressed copy."""
    (STORE/'sha256').mkdir(parents=True,exist_ok=True)
    for top in paths:
        for path in [top] if top.is_file() else [p for p in top.rglob('*') if p.is_file()]:
            if path.is_symlink() or path.stat().st_size<BIG or STORE in path.parents:continue
            obj=STORE/'sha256'/sha(path)
            if not obj.exists():
                clone(path,obj.with_suffix('.tmp'));obj.with_suffix('.tmp').chmod(0o444);obj.with_suffix('.tmp').replace(obj)
            mode=path.stat().st_mode
            clone(obj,path.with_name(path.name+'.store'));path.with_name(path.name+'.store').chmod(mode)
            path.with_name(path.name+'.store').replace(path)


def store_gc(releases,dry_run):
    objects={}
    for obj in (STORE/'sha256').glob('*') if (STORE/'sha256').is_dir() else []:
        objects.setdefault(obj.stat().st_size,{})[obj.name]=obj
    for release in releases:
        for path in release.rglob('*'):
            if path.is_file() and not path.is_symlink() and path.stat().st_size in objects:
                objects[path.stat().st_size].pop(sha(path),None)
    for obj in [o for group in objects.values() for o in group.values()]:
        log(dict(event='would_remove_object' if dry_run else 'removed_object',object=obj.name,bytes=obj.stat().st_size))
        if not dry_run:obj.unlink()


def source(commit,dest,bare=BARE,url=URL):
    if not bare.exists():subprocess.run(['git','clone','--bare','--quiet',url,str(bare)],check=True)
    subprocess.run(['git','--git-dir',str(bare),'fetch','--quiet',url,'+refs/heads/*:refs/heads/*'],check=True)
    subprocess.run(['git','--git-dir',str(bare),'worktree','add','--detach','--quiet',str(dest),commit],check=True)


def gc(dry_run=False,home=HOME):
    with locked() as ok:
        if ok:collect(dry_run,home)


def collect(dry_run,home):
    ps,agents=processes(),home/'Library/LaunchAgents'
    jobs=list(pool_jobs(agents))
    if not jobs:raise RuntimeError('no launchd pool found; refusing to treat every release as unused')
    if not PINS.is_file():raise RuntimeError(f'{PINS} missing; list the releases that must survive (one path per line) before gc')
    pins=PINS.read_text().splitlines()
    dirs=sorted(p for p in home.glob(RELEASES) if p.is_dir() and not p.is_symlink())
    texts=[t for _,job in jobs for t in job]+[p.read_bytes().decode('latin1') for p in agents.glob('*.plist')]
    live=live_releases(dirs,texts+[ps,'\n'.join(pins)])
    # Only a staged release (a source checkout or a pool command) is ever removed; other dsmack-* dirs are left alone.
    rest=sorted((r for r in dirs if r not in live and ((r/'source').is_dir() or (r/'pool-command.json').is_file())),
                key=lambda r:r.stat().st_mtime)
    rollback=rest[-1:]  # most recently modified, not most recently staged; pin what must survive
    log(dict(event='gc_plan',live=sorted(map(str,live)),rollback=list(map(str,rollback)),remove=len(rest)-len(rollback),dry_run=dry_run))
    for release in rest[:-1]:remove(release,dry_run)
    if BARE.exists() and not dry_run:subprocess.run(['git','--git-dir',str(BARE),'worktree','prune'],check=True)
    store_gc(sorted(live)+rollback,dry_run)
    for root,_ in jobs:reap(root,dry_run)


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('gc').add_argument('--dry-run',action='store_true')
    r=sub.add_parser('reap');r.add_argument('root',type=Path);r.add_argument('--dry-run',action='store_true')
    sub.add_parser('store').add_argument('paths',type=Path,nargs='+')
    s=sub.add_parser('source');s.add_argument('commit');s.add_argument('dest',type=Path)
    a=parser.parse_args()
    if a.action=='gc':gc(a.dry_run)
    elif a.action=='reap':
        with locked() as ok:
            if ok:reap(a.root.resolve(),a.dry_run)
    elif a.action=='store':store([p.resolve() for p in a.paths])
    else:source(a.commit,a.dest.resolve())


if __name__=='__main__':
    main()
