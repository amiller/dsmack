#!/usr/bin/env python3
"""Independent public-envelope/native-workload binding using selected original contract."""
import argparse,hashlib,json,sys
from pathlib import Path
s=Path(__file__).with_name('portable.py');p={'__name__':'arcade_portable','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),p)
need=p['need'];read=p['read'];doc=p['document'];pin=p['pin']
def main():
    a=argparse.ArgumentParser()
    for n in ('verifier','manifest','projection','receipt','statement','workload-sha256','workload-bytes'):a.add_argument('--'+n,required=True)
    x=a.parse_args();root=p['protected'](x.verifier,True)
    sys.path.insert(0,str(root))
    from runresult_ref.frozen import validate_receipt_bytes
    statement=doc(read(x.statement));need(statement['consumed']['observed_workload_sha256']==x.workload_sha256 and statement['workload']['sha256']==x.workload_sha256 and statement['workload']['bytes']==int(x.workload_bytes),'authenticated native workload differs from issued task')
    result=validate_receipt_bytes(read(x.manifest),read(x.receipt),read(x.projection,33554432))
    need(result['runtime_inputs_commitment_status']=='bound-to-validated-envelope','independent public input commitment failed')
    print(json.dumps({'public_envelope_commitment_recomputed':True,'native_workload_rebound':True,'commitment_status':'bound-to-validated-envelope'}))
if __name__=='__main__':main()
