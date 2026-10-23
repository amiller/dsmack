#!/usr/bin/env python3
"""Prepare one unsigned checker capsule from existing signed app/base sources.
No app/base/OCI build, signing, installation, VM, key or challenge operation.
"""
import argparse,copy,gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
s=Path(__file__).with_name('task_factory.py');f={'__name__':'arcade_factory','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),f)
p=f['p'];need=p['need'];read=p['read'];pin=p['pin'];canonical=p['canonical'];exclusive=p['exclusive'];doc=p['document']

def prepare(config,out,sequence,issued_at,expires_at):
    need(str(out).startswith('/data/')and not out.exists(),'fresh Zed/data release directory required')
    entries=doc(f['selected'](config['qualified_entries'],1<<20));inventory=doc(f['selected'](config['qualified_inventory'],1<<20));profile=doc(f['selected'](config['qualified_profile']))
    need(type(sequence)is int and sequence>inventory['sequence'],'fresh release rollback sequence')
    f['checker_files'](config);f['selected'](config['guest_driver']);m=f['manifest'](config);mr=canonical(m);validate,_=f['guest_modules'](config);validate(mr)
    out.mkdir(mode=0o700);exclusive(out/'compose-manifest.json',mr)
    profile=copy.deepcopy(profile);profile['execution_profile']['compose_manifest_sha256']=hashlib.sha256(mr).hexdigest();exclusive(out/'profile.json',canonical(profile))
    profile_path=next(x['descriptor_path']for x in inventory['profiles']if x['profile_id']==profile['profile_id']);manifest_path=profile['roles']['compose_manifest']
    provenance={'schema':'dsmack-arcade-runtime-provenance/1','qualified_inventory_sha256':config['qualified_inventory']['sha256'],'unchanged_app':inventory['app'],'unchanged_base':profile['selected_image'],'flat_oci_manifest_sha256':f['IMAGE'],'checker_files':f['CHECKER'],'guest_driver':{k:config['guest_driver'][k]for k in ('bytes','sha256')},'purpose':'new deterministic testnet bonus; not original three-judge bounty','source_claims':'Existing narrow corresponding-source offers retained; no whole-image reproducibility or Sigstore claim.'}
    exclusive(out/'provenance.json',canonical(provenance));provenance_path=next(r['path']for r in inventory['files']if r['sha256']==inventory['provenance_sha256'])
    for target,path in ((manifest_path,out/'compose-manifest.json'),(profile_path,out/'profile.json'),(provenance_path,out/'provenance.json')):
        d=pin(path);entries[target]={'path':target,'source':str(path),'bytes':d['bytes'],'sha256':d['sha256'],'mode':0o600}
    archive=out/'release-arcade-browser-r1.tar.gz'
    with archive.open('xb')as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0)as compressed:
            with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT)as tar:
                for name,row in sorted(entries.items()):
                    need(name==row['path']and not Path(name).is_absolute()and '..'not in Path(name).parts,'closed archive path')
                    src=Path(row['source']);actual=pin(src,1<<34);need(all(actual[k]==row[k]for k in ('bytes','sha256')),'preserved source changed')
                    info=tarfile.TarInfo(name);info.size=row['bytes'];info.mode=row['mode'];info.uid=info.gid=0;info.mtime=0
                    with src.open('rb')as stream:tar.addfile(info,stream)
                    need(pin(src,1<<34)==actual,'archive source changed')
    inv=copy.deepcopy(inventory);inv.update(sequence=sequence,issued_at=issued_at,expires_at=expires_at,release_id='arcade-browser-testnet-r1',archive={'format':'tar+gzip',**{k:v for k,v in pin(archive,1<<34).items()if k!='path'}},files=[{k:r[k]for k in ('path','bytes','sha256','mode')}for _,r in sorted(entries.items())],provenance_sha256=pin(out/'provenance.json')['sha256'])
    inv['profiles']=[{**row,'descriptor_sha256':pin(out/'profile.json')['sha256']}if row['profile_id']==profile['profile_id']else row for row in inv['profiles']]
    exclusive(out/'release-arcade-browser-r1.UNSIGNED.json',canonical(inv));exclusive(out/'release.signing-message',inv['schema'].encode()+b'\0'+canonical(inv));exclusive(out/'STAGED-RELEASE-ENTRIES.json',canonical(entries))
    result={'inventory':pin(out/'release-arcade-browser-r1.UNSIGNED.json'),'archive':pin(archive,1<<34),'manifest':pin(out/'compose-manifest.json'),'profile':pin(out/'profile.json'),'sequence':sequence,'files':len(entries),'app_or_base_rebuilt':False,'signed':False};exclusive(out/'UNSIGNED-FREEZE.json',canonical(result));return result

def main():
    a=argparse.ArgumentParser();a.add_argument('--config',required=True);a.add_argument('--config-sha256',required=True);a.add_argument('--out',required=True);a.add_argument('--sequence',type=int,required=True);a.add_argument('--issued-at',required=True);a.add_argument('--expires-at',required=True);x=a.parse_args();raw=read(x.config);need(hashlib.sha256(raw).hexdigest()==x.config_sha256,'selected preparation config');print(json.dumps(prepare(doc(raw),Path(x.out),x.sequence,x.issued_at,x.expires_at),sort_keys=True))
if __name__=='__main__':main()
