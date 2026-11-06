#!/usr/bin/env python3
"""Delete the big images of stopped pool runs older than --hours; logs, statements, receipts and result.img(.gz) stay.

prune-runs.py ROOT [--hours 24] [--dry-run]    (ROOT holds pool-*/guests-*/run-*/)
"""
import argparse,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--hours',type=float,default=24);p.add_argument('--dry-run',action='store_true')
a=p.parse_args();cutoff=time.time()-a.hours*3600;freed=0
for run in sorted(a.root.glob('pool-*/guests-*/run-*')):
    if run.stat().st_mtime>cutoff or subprocess.run(['pgrep','-f',run.name],capture_output=True).returncode==0:continue
    for f in [*run.rglob('scratch.img'),*run.rglob('workload.img'),*run.rglob('*.staged')]:
        if f.is_file():
            freed+=f.stat().st_size;print(('would delete ' if a.dry_run else 'delete ')+str(f))
            if not a.dry_run:f.unlink()
print(f'{freed/2**30:.1f} GiB')
