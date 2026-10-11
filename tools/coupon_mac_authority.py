#!/usr/bin/env python3
"""Sign only explicitly debug Mac issuer controls with the protected authority."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from coupon_staging_authority import load_authority,sign,_read_private,_write_private
from experiments.coupon_redemption.staging_approval import signed_payload,validate_approval_payload,validate_configuration_payload
APPROVAL='dsmack-coupon-mac-approval-v1';CONFIG='dsmack-coupon-mac-config-v1'

def validated(envelope,public,mode,approved=None):
    domain=APPROVAL if mode=='approval' else CONFIG
    payload=signed_payload(envelope,domain,bytes.fromhex(public))
    if mode=='approval':return validate_approval_payload(payload,mac=True)
    compose=payload.get('app_compose')
    if type(compose) is not str or not 0<len(compose.encode())<=131072 or hashlib.sha256(compose.encode()).hexdigest()!=approved['compose_hash']:
        raise ValueError('Mac compose refused')
    validate_configuration_payload({k:v for k,v in payload.items() if k!='app_compose'},approved,approval_domain=APPROVAL)
    return payload

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['approval','config']);p.add_argument('--dir',required=True);p.add_argument('--payload',required=True);p.add_argument('--out',required=True);p.add_argument('--approval')
    args=p.parse_args();key,public=load_authority(Path(args.dir))
    approved=validate_approval_payload(json.loads(_read_private(Path(args.approval),200000)),mac=True) if args.mode=='config' else None
    payload=json.loads(_read_private(Path(args.payload),200000));envelope=sign(payload,APPROVAL if args.mode=='approval' else CONFIG,key)
    validated(envelope,public,args.mode,approved);_write_private(Path(args.out),envelope)
    print(json.dumps({'signed_mac_control':args.mode,'public_key_hex':public,'private_issuance_qualified':False}))

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Mac control signing refused') from None
