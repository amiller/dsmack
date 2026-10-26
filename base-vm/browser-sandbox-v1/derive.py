#!/usr/bin/env python3
"""Derive the browser-sandbox-v1 guest image from the image7 base bundle and disk templates."""
import argparse,json,subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
def command(base,templates,out,builder):
    return ['docker','run','--rm','--cpus','4','--memory','4g','--pids-limit','256','--network','none',
      '--mount',f'type=bind,src={out},dst=/w','--mount',f'type=bind,src={HERE}/source,dst=/w/source,readonly',
      '--mount',f'type=bind,src={HERE}/derive-in-container.sh,dst=/derive.sh,readonly',
      '--mount',f'type=bind,src={HERE.parent.parent}/dstack-compat,dst=/w/dstack-compat,readonly',
      '--mount',f'type=bind,src={base},dst=/prior-image,readonly','--mount',f'type=bind,src={templates},dst=/selected-templates,readonly',
      builder,'bash','/derive.sh']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('base-bundle','templates','out'):p.add_argument('--'+n,required=True)
    p.add_argument('--builder',required=True,help='image built from builder/Dockerfile')
    a=p.parse_args()
    base,templates,out=(Path(x).absolute() for x in (a.base_bundle,a.templates,a.out))
    out.mkdir(mode=0o700)
    with (out/'build.log').open('wb') as log:subprocess.run(command(base,templates,out,a.builder),stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900)
    files=out/'build/legs/diagnostic/files'
    print(json.dumps({'artifacts':str(files),'image_sha256':(files/'digest.txt').read_text().strip()}))

if __name__=='__main__':main()
