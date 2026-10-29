#!/usr/bin/env python3
"""Pin an Apple-verified enrollment public key and guest measurements into the static client."""
import argparse, base64, hashlib, json, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from verifier.core import verify_key, unb64, decode
from cryptography import x509
from verifier.macos_policy import root, policy, APP_ID
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--enrollment',type=Path,required=True)
p.add_argument('--manifest',type=Path,required=True)
p.add_argument('--cdhash',required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args(); e=a.enrollment
kid=(e/'keyId.txt').read_text().strip()
verified=verify_key((e/'attestation.cbor').read_bytes(),kid,(e/'clientData.bin').read_bytes(),policy(bytes.fromhex(a.cdhash)),root(),time.time())
point=unb64(verified['public_key'])
b64=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
manifest=a.manifest.read_bytes()
template=json.loads(manifest)
compose=json.loads(template['docker_compose_file'])
compose['services']['peer']['command'][:2]=['{tunnelHostname}','{relayPeer}']
template['docker_compose_file']=json.dumps(compose,sort_keys=True,separators=(',',':'))
a.output.write_text(json.dumps({'expires':int(x509.load_der_x509_certificate(decode((e/'attestation.cbor').read_bytes())['attStmt']['x5c'][1]).not_valid_after_utc.timestamp()),'appId':APP_ID,'cdhash':a.cdhash,'keyId':unb64(kid).hex(),'publicKey':{'kty':'EC','crv':'P-256','x':b64(point[1:33]),'y':b64(point[33:65])},'osImage':json.loads(manifest)['base_vm']['os_image_hash'],'manifestTemplate':template},indent=2)+'\n')
print(json.dumps({'appleEnrollmentVerified':True,'cdhash':a.cdhash,'signals':verified['signals']}))
