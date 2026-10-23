"""Deterministic projections from audited immutable source bytes.

Writes only fresh, owned application state. Never imports candidate JavaScript.
"""
import json
from pathlib import Path
from source_bundle import BOARD, protocol, sha


def project(audit, destination):
    destination=Path(destination)
    destination.mkdir(mode=0o700,parents=False,exist_ok=False)
    role=audit['role']; files=audit['source_files']; outputs={}
    if role=='generate':
        # Generator load_snapshot contract: exactly these TWO public files.
        outputs['base.json']=protocol.canonical_json({'schema':'dsmack-bounty-base-snapshot/1',
            'files':[{'path':name,'content':files[name].decode('utf-8')} for name in BOARD]})
        outputs['spec.txt']=audit['stage_profile']['specification']['text'].encode('utf-8')
    elif role=='primary-review':
        # Full faithful candidate projection for all original app suites.
        # Candidate files remain data; the selected primary harness serves them
        # only into Chromium and owns all test/import execution.
        rows={row['path']:row for row in audit['source_manifest']}
        for name,data in sorted(files.items()):
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(data)
            target.chmod(rows[name]['mode'])
        return {name:{'bytes':len(data),'sha256':sha(data)} for name,data in sorted(files.items())}
    else:
        for path,name in zip(BOARD,('board-index.html','board-logic.js','board-ui.js')):
            protocol.require(path in files,'required board source absent')
            outputs[name]=files[path]
        if role in ('base','candidate'): outputs['suite.json']=audit['input_bytes']['suite']
    total=sum(len(data) for data in outputs.values())
    protocol.require(total <= 2*1024*1024,'projection bound')
    for name,data in outputs.items():
        (destination/name).write_bytes(data)
        (destination/name).chmod(0o400)
    return {name:{'bytes':len(data),'sha256':sha(data)} for name,data in sorted(outputs.items())}


def retain_delivery(audit,destination):
    """Deliver ORIGINAL committed candidate, never the mutable projected state."""
    protocol.require(audit['role']=='primary-review','only primary candidate delivery')
    destination=Path(destination);destination.mkdir(mode=0o700,parents=False,exist_ok=False)
    for semantic,name in [('source_bundle','source-delivery.tar'),('source_manifest','candidate-manifest.json')]:
        (destination/name).write_bytes(audit['input_bytes'][semantic])
