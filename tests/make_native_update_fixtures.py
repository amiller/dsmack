#!/usr/bin/env python3
"""Bounded synthetic ZIP inputs for the actual Swift archive validator."""
import pathlib,sys,zipfile,struct
root=pathlib.Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
base={'Node.app/Contents/Info.plist':b'plist','Node.app/Contents/MacOS/node':b'binary','Node.app/Contents/Resources/dsmack-release.json':b'{}'}
def write(name,files):
 with zipfile.ZipFile(root/name,'w') as z:
  for path,data in files.items():z.writestr(path,data)
write('valid.zip',base)
write('traversal.zip',{**base,'Node.app/../../escape':b'x'})
write('absolute.zip',{**base,'/tmp/escape':b'x'})
write('backslash.zip',{**base,'Node.app/..\\escape':b'x'})
write('missing-metadata.zip',{k:v for k,v in base.items() if not k.endswith('.json')})
with zipfile.ZipFile(root/'symlink.zip','w') as z:
 for path,data in base.items():z.writestr(path,data)
 entry=zipfile.ZipInfo('Node.app/link');entry.create_system=3;entry.external_attr=0o120777<<16;z.writestr(entry,b'/tmp')
valid=(root/'valid.zip').read_bytes()
(root/'trailing.zip').write_bytes(valid+b'extra')
(root/'truncated.zip').write_bytes(valid[:-10])
local_mismatch=bytearray(valid);local_mismatch[30]=ord('X');(root/'mismatched-name.zip').write_bytes(local_mismatch)
# Corrupt central flags without changing the local record.
c=valid.index(b'PK\x01\x02');flags=bytearray(valid);struct.pack_into('<H',flags,c+8,1);(root/'encrypted.zip').write_bytes(flags)
print('Created',len(list(root.glob('*.zip'))),'small ZIP fixtures')
