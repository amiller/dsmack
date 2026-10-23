#!/usr/bin/env python3
"""Check original import or explicitly selected, independently reviewed derivation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent
COMPILED_TREES = ('app-src', 'control-src', 'io-contract-consumer', 'packaging', 'native/source-tree')


def source_file(root, relative):
    cursor=root
    for part in relative.parts[:-1]:
        cursor=cursor/part
        if not stat.S_ISDIR(cursor.lstat().st_mode):
            raise ValueError('source parent is not ordinary directory: '+str(relative))
    path=root/relative
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('missing/nonregular source (symlink refused): '+str(relative))
    return path


def relative_source(name):
    if not isinstance(name,str) or not name.startswith('runner-vm/'):
        raise ValueError('invalid imported repository path')
    relative=Path(name[len('runner-vm/'):])
    if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.as_posix()!=name[len('runner-vm/'):]:
        raise ValueError('unsafe imported path')
    return relative


def check(root=ROOT, derivation_sha256=None):
    root=Path(root)
    if root.is_symlink():raise ValueError('source root symlink refused')
    raw=source_file(root,Path('SOURCE-IMPORT.json')).read_bytes()
    manifest=json.loads(raw);base_sha=hashlib.sha256(raw).hexdigest()
    derived_path=root/'SOURCE-DERIVATION.json';derived=None;changes={}
    if derived_path.exists() or derived_path.is_symlink():
        selected=source_file(root,Path('SOURCE-DERIVATION.json')).read_bytes()
        if not isinstance(derivation_sha256,str) or hashlib.sha256(selected).hexdigest()!=derivation_sha256:
            raise ValueError('derived source requires independently selected derivation SHA-256')
        derived=json.loads(selected)
        if set(derived)!=set(('schema','source_profile_id','baseline_import_manifest_sha256','native_source_inventory_sha256','changes')) or derived['schema']!='dsmack-derived-runner-source/1':
            raise ValueError('unknown source derivation schema')
        if derived['baseline_import_manifest_sha256']!=base_sha:
            raise ValueError('derivation baseline import differs')
        if not re.fullmatch(r'[a-z0-9-]{1,64}',derived['source_profile_id']) or not re.fullmatch(r'[0-9a-f]{64}',derived['native_source_inventory_sha256']):
            raise ValueError('invalid derived source identity')
        if not isinstance(derived['changes'],list) or not 1<=len(derived['changes'])<=64:
            raise ValueError('source derivation change bound')
        for entry in derived['changes']:
            if set(entry)!=set(('repository_relative','before_sha256','after_sha256')):
                raise ValueError('invalid derived source change members')
            relative=relative_source(entry['repository_relative']);name=str(relative)
            if name in changes or not any(relative.parts[:len(Path(t).parts)]==Path(t).parts for t in COMPILED_TREES):
                raise ValueError('duplicate or noncompiled derived source path')
            if not re.fullmatch(r'[0-9a-f]{64}',entry['after_sha256']) or (entry['before_sha256'] is not None and not re.fullmatch(r'[0-9a-f]{64}',entry['before_sha256'])):
                raise ValueError('invalid derivation source digest')
            changes[name]=entry
    elif derivation_sha256 is not None:
        raise ValueError('selected source derivation missing')
    expected={}
    for entry in manifest['files']:
        relative=relative_source(entry['repository_relative']);name=str(relative)
        if name in expected:raise ValueError('duplicate imported path')
        selected=entry['original_sha256']
        if name in changes:
            if changes[name]['before_sha256']!=selected:raise ValueError('derived source before identity differs')
            selected=changes[name]['after_sha256']
        if hashlib.sha256(source_file(root,relative).read_bytes()).hexdigest()!=selected:
            raise ValueError('imported source changed: '+name)
        expected[name]=selected
    for name,entry in changes.items():
        if name not in expected:
            if entry['before_sha256'] is not None:raise ValueError('derivation before source not in original import')
            if hashlib.sha256(source_file(root,Path(name)).read_bytes()).hexdigest()!=entry['after_sha256']:
                raise ValueError('derived source addition changed')
            expected[name]=entry['after_sha256']
    for tree in COMPILED_TREES:
        for path in (root/tree).rglob('*'):
            rel=path.relative_to(root)
            if '__pycache__' in rel.parts:continue
            if path.is_symlink():raise ValueError('unexpected source symlink: '+str(rel))
            if path.is_file() and str(rel) not in expected:raise ValueError('unreviewed source addition: '+str(rel))
    result={'schema':'dsmack-selected-source-check/1','source_files_checked':len(expected),
            'original_import_matched':derived is None,'compiled':False,'signed':False,
            'friend_install_qualified':False,'import_manifest_sha256':base_sha}
    if derived:
        result.update(source_profile_id=derived['source_profile_id'],source_derivation_sha256=derivation_sha256,
                      selected_native_source_inventory_sha256=derived['native_source_inventory_sha256'],
                      original_import_provenance_preserved=True,new_app_qualification_required=True)
    return result


def selected_lock(result, original):
    lock=dict(original)
    if 'source_derivation_sha256' in result:
        lock['source_derivation_sha256']=result['source_derivation_sha256']
        lock['native_source_inventory_sha256']=result['selected_native_source_inventory_sha256']
    return lock


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-derivation-sha256');args=parser.parse_args()
    try:print(json.dumps(check(derivation_sha256=args.source_derivation_sha256),indent=2))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'checked':False,'error':str(exc)}),file=sys.stderr);sys.exit(1)
