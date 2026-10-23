#!/usr/bin/python3
"""Fixed unprivileged reference application, not a privileged guest hook.

Expected pins are independently selected in measured compose argv. Model access
is possible only for generation and still requires the separately selected broker.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
from audit_stage import audit, SLOTS
from project import project
from observation import append_observation
from output_bundle import pack as pack_result_files
from source_bundle import protocol as p, sha


def main():
    parser=argparse.ArgumentParser()
    for name in ('request','stage-profile','driver','plan'):
        parser.add_argument('--expected-'+name+'-sha256',required=True)
    args=parser.parse_args()
    p.require(os.getuid()==1000 and os.getgid()==1000,'fixed UID/GID1000')
    public=Path('/workspace/inputs')
    paths={name:public/name for name in SLOTS}
    if not paths['suite'].exists():paths['suite']=None
    result=audit(paths,args.expected_request_sha256,args.expected_stage_profile_sha256,
                 args.expected_driver_sha256,args.expected_plan_sha256)
    state=Path('/workspace/state');p.require(state.is_dir() and not state.is_symlink(),'selected writable state')
    if result['role']=='primary-review':
        p.require(not any(state.iterdir()),'fresh primary state before projection')
        (state/'primary-run').mkdir()
    projection_root=state/'candidate-projection' if result['role']=='primary-review' else state/'projection'
    projection=project(result,projection_root)
    root=Path(__file__).resolve().parents[1]
    if result['role']=='generate':
        snapshot={'schema':'dsmack-bounty-generator-input/1','base_tree_sha256':result['source_tree_sha256'],
                  'files':[{'name':name,'size':projection[name]['bytes'],'sha256':projection[name]['sha256']} for name in ('base.json','spec.txt')]}
        request=result['request']
        command=['/usr/bin/python3','/opt/bounty-judges/generate.py','--public',str(state/'projection'),
                 '--output','/workspace/artifacts','--model',request['requested_model'],'--judge',str(request['judge_index']),
                 '--snapshot-sha256',sha(p.canonical_json(snapshot)),'--base-tree-sha256',result['source_tree_sha256']]
    elif result['role'] in ('base','candidate'):
        command=['/usr/bin/node',str(root/'bounty-runtime/browser-launch.mjs')]
    else:
        command=['/usr/bin/node',str(root/'bounty-runtime/primary-launch.mjs'),result['source_tree_sha256']]
    # Outer VM supplies its own 600s bound; this is a narrower child guard.
    result_code=subprocess.run(command,timeout=550,check=False).returncode
    if result['role']=='primary-review':
        for semantic,name in [('source_bundle','source-delivery.tar'),('source_manifest','candidate-manifest.json')]:
            with (Path('/workspace/artifacts')/name).open('xb') as stream:stream.write(result['input_bytes'][semantic])
    append_observation('/workspace/artifacts',result,projection)
    pack_result_files('/workspace/artifacts')
    return result_code


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);sys.exit(2)
