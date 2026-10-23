"""Deterministic flat result USTAR. No extraction, authority flags or base hooks.

The original sidecar is retained byte-for-byte. Its entries are independently
recomputed from every member; sealed JSON alone never establishes correctness.
"""
import hashlib
from pathlib import Path
import re
from source_bundle import protocol as p,sha
from audit_stage import regular

SCHEMA='dsmack-flat-result-ustar/1'
MANIFEST='output-manifest.json'
BUNDLE='result-files.tar'
ARCHIVE_CAP=16*1024*1024
FILE_CAP=16*1024*1024
MEMBER_CAP=256
NAME=re.compile(r'[a-z][a-z0-9.-]{0,79}\Z')
SELECTION={'schema':SCHEMA,'artifact':'result-files','manifest':MANIFEST,
           'duplicates':{'stage-checks':'checks.json','public-input-audit':'public-input-audit.json'}}


def header(name,size):
    p.require(isinstance(name,str) and NAME.fullmatch(name) is not None,'flat result filename')
    p.require(type(size)is int and 0<=size<=FILE_CAP,'result file size')
    value=bytearray(512);encoded=name.encode('ascii');value[:len(encoded)]=encoded
    value[100:108]=b'0000644\0';value[108:116]=b'0000000\0';value[116:124]=b'0000000\0'
    value[124:136]=('%011o\0'%size).encode('ascii');value[136:148]=b'00000000000\0'
    value[148:156]=b' '*8;value[156]=ord('0');value[257:263]=b'ustar\0';value[263:265]=b'00'
    value[329:337]=b'0000000\0';value[337:345]=b'0000000\0'
    value[148:156]=('%06o\0 '%sum(value)).encode('ascii')
    return bytes(value)


def validate_manifest(raw,files):
    manifest=p.parse_json(raw,131072);p.keys(manifest,('schema','files'),'output manifest')
    p.require(manifest['schema']=='dsmack-bounty-output-manifest/1','output manifest version')
    p.require(raw==p.canonical_json(manifest),'canonical original output manifest')
    rows=manifest['files'];p.require(isinstance(rows,list)and 0<len(rows)<MEMBER_CAP,'logical file count')
    for row in rows:
        p.keys(row,('name','size','sha256'),'logical file')
        p.require(isinstance(row['name'],str) and NAME.fullmatch(row['name']) is not None,'logical filename')
        p.require(type(row['size']) is int and 0<=row['size']<=FILE_CAP,'logical integer byte bound')
        p.require(isinstance(row['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None,'logical sha256')
    actual=[{'name':name,'size':len(data),'sha256':sha(data)}for name,data in sorted(files.items())]
    p.require(rows==actual,'complete logical manifest differs from actual bytes')
    p.require(all(NAME.fullmatch(row['name'])and row['name']not in(MANIFEST,BUNDLE,'result-files')and row['size']<=FILE_CAP for row in rows),'logical member name/size')
    p.require('checks.json'in files and 'public-input-audit.json'in files,'required duplicate members missing')
    return manifest


def encode(files,manifest_raw):
    validate_manifest(manifest_raw,files)
    members={**files,MANIFEST:manifest_raw}
    size=1024+sum(512+((len(raw)+511)//512)*512 for raw in members.values())
    p.require(len(members)<=MEMBER_CAP and size<=ARCHIVE_CAP,'result archive cap including headers')
    output=bytearray()
    for name,raw in sorted(members.items()):
        output+=header(name,len(raw));output+=raw;output+=bytes((-len(raw))%512)
    output+=bytes(1024)
    p.require(len(output)==size,'result archive length')
    return bytes(output)


def decode(raw):
    p.require(isinstance(raw,bytes)and 1024<=len(raw)<=ARCHIVE_CAP and len(raw)%512==0,'result archive byte bound')
    offset=0;members={};last=''
    while offset+512<=len(raw)and any(raw[offset:offset+512]):
        p.require(len(members)<MEMBER_CAP,'result archive member cap')
        block=raw[offset:offset+512];name_raw,sep,padding=block[:100].partition(b'\0')
        p.require(bool(sep)and not any(padding),'result name NUL padding')
        name=name_raw.decode('ascii');field=block[124:136]
        p.require(field[-1:]==b'\0'and all(c in b'01234567'for c in field[:-1]),'result size encoding')
        size=int(field[:-1],8);p.require(block==header(name,size),'noncanonical result USTAR header')
        p.require(name>last and name!=BUNDLE,'result order/duplicate/self bundle');last=name;offset+=512
        data=raw[offset:offset+size];p.require(len(data)==size,'truncated result member');offset+=size
        count=(-size)%512;p.require(raw[offset:offset+count]==bytes(count),'result member padding');offset+=count
        members[name]=data
    p.require(raw[offset:]==bytes(1024),'result exact terminator/trailing bytes')
    p.require(MANIFEST in members,'original output manifest missing')
    manifest_raw=members.pop(MANIFEST);validate_manifest(manifest_raw,members)
    return manifest_raw,members


def pack(output):
    output=Path(output);p.require(output.is_dir()and not output.is_symlink(),'result root ordinary directory')
    manifest_raw=regular(output/MANIFEST,131072);manifest=p.parse_json(manifest_raw,131072)
    p.keys(manifest,('schema','files'),'output manifest')
    p.require(isinstance(manifest['files'],list)and 0<len(manifest['files'])<MEMBER_CAP,'output member array')
    names=[]
    for row in manifest['files']:
        p.keys(row,('name','size','sha256'),'logical file')
        p.require(isinstance(row['name'],str)and NAME.fullmatch(row['name'])is not None,'logical filename')
        p.require(type(row['size'])is int and 0<=row['size']<=FILE_CAP,'logical file byte bound')
        p.require(row['name']not in(MANIFEST,BUNDLE,'result-files'),'manifest/bundle recursion')
        names.append(row['name'])
    p.require(names==sorted(set(names)),'logical file ordering')
    projected_size=1024+512+((len(manifest_raw)+511)//512)*512+sum(512+((row['size']+511)//512)*512 for row in manifest['files'])
    p.require(projected_size<=ARCHIVE_CAP,'archive cap before reading payloads')
    actual_names=set()
    for member in output.iterdir():
        p.require(len(actual_names)<MEMBER_CAP,'result directory membership cap')
        actual_names.add(member.name)
    p.require(actual_names==set(names)|{MANIFEST},'closed pre-bundle result membership')
    files={name:regular(output/name,FILE_CAP)for name in names}
    raw=encode(files,manifest_raw)
    with(output/BUNDLE).open('xb')as stream:stream.write(raw)
    # Round trip the exact bytes which native export will authenticate.
    p.require(decode(raw)==(manifest_raw,files),'result bundle self consistency')
    return {'schema':SCHEMA,'bytes':len(raw),'sha256':sha(raw),'members':len(files)+1}
