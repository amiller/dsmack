"""Closed Zed issuer. Existing release key remains local; no key bytes are inventoried."""
import base64,datetime,hashlib,json,os,secrets,stat,subprocess
from pathlib import Path
s=Path(__file__).with_name('portable.py');p={'__name__':'arcade_portable','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),p)
need=p['need'];read=p['read'];pin=p['pin'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive'];protected=p['protected']

def admission_expiry(now,release_end):
    expiry=min(now+datetime.timedelta(seconds=7200),release_end)
    need((expiry-now).total_seconds()>=3600,'release too close to expiry')
    return expiry

def issue(config,attempt,key,native,context,disk,directory):
    need(config.get('signing_authorized')is True,'exact reviewed signing configuration required')
    inv=config['inventory'];need(pin(inv['path'])==inv,'selected release changed');inventory=doc(read(inv['path']))
    need(inv['sha256']==config['inventory_sha256'] and inventory['key_id']==config['release_key_id'],'release authority binding')
    need(config['profile_id']in{x['profile_id']for x in inventory['profiles']},'profile not in selected release')
    now=datetime.datetime.now(datetime.timezone.utc);release_end=datetime.datetime.fromisoformat(inventory['expires_at'].replace('Z','+00:00'));expiry=admission_expiry(now,release_end)
    challenge=secrets.token_bytes(32);template=config['checker_template'];need(pin(template['path'])==template,'selected checker context template changed');checker=doc(read(template['path']))
    checker['report_key_id']=config['report_key_id'];checker['report_verify_key_b64']=config['report_verify_key_b64']
    expected=checker['expected'];expected.update(challenge=challenge.hex(),manifest_sha256=config['manifest_sha256'],receipt_selector=config['selector'],key_id_b64=key,workload_status='completed',exit_code=0,receipt_environment='vm',closure_context=context,selector_manifests={config['selector']:{'manifest_sha256':config['manifest_sha256'],'workload_status':'completed','exit_code':0,'receipt_environment':'vm'}})
    exclusive(directory/'checker-context.json',canonical(checker))
    stamp=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z')
    admission={'schema':'dsmack-alpha-workload-admission/1','key_id':config['release_key_id'],'release_inventory_sha256':config['inventory_sha256'],'profile_id':config['profile_id'],'compose_manifest_sha256':config['manifest_sha256'],'attempt_id':native,'closure_context_sha256':hashlib.sha256(canonical(context)).hexdigest(),'workload_disk':{k:disk[k]for k in ('bytes','sha256')},'issued_at':stamp(now),'expires_at':stamp(expiry)}
    raw=canonical(admission);exclusive(directory/'workload-admission.json',raw);message=admission['schema'].encode()+b'\0'+raw;exclusive(directory/'workload.signing-message',message)
    keypath=protected(config['release_signing_key']);ks=keypath.stat();need(ks.st_uid==os.getuid()and not ks.st_mode&0o077,'private configured signing key metadata')
    # Public extraction verifies the exact existing authority; private material
    # never enters Python, the packet, diagnostics, hash inventories or logs.
    pub=subprocess.run(['/usr/bin/openssl','pkey','-in',str(keypath),'-pubout'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=True,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'}).stdout
    need(hashlib.sha256(pub).hexdigest()==config['release_public_key_sha256'],'configured signing authority changed')
    sig=subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-rawin','-inkey',str(keypath),'-in',str(directory/'workload.signing-message')],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=True,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'}).stdout
    need(len(sig)==64,'Ed25519 signature length');exclusive(directory/'workload.sig',sig)
    # The current original verifier stores the exact result-context challenge,
    # not an arbitrary worker-supplied nonce. Run only its selected frozen CLI.
    v=config['verifier'];root=Path(v['root'])
    for n in ('verify.py','SOURCE-PINS.json','QUALIFIED-LINUX-ENVIRONMENT.json'):need(pin(root/n)==v['pins'][n],'selected verifier changed')
    cmd=[config['python'],'-I','-B',str(root/'verify.py'),'--source-manifest-sha256',v['source_manifest_sha256'],'--environment-sha256',v['environment_sha256'],'operator','issue-challenge','--replay',config['replay'],'--key-id',key,'--manifest-sha256',config['manifest_sha256'],'--ttl','7200','--challenge',challenge.hex()]
    result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    exclusive(directory/'ISSUE.stdout',result.stdout);exclusive(directory/'ISSUE.stderr',result.stderr);need(result.returncode==0 and doc(result.stdout).get('issued')is True,'original challenge issuer refused')
    return {'challenge_b64':base64.b64encode(challenge).decode()}
