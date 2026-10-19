"""Write fixtures/iphone-apple.json from the 2026-09-23 iPhone session: key E enrollment (row 10), honest assertion (row 11), modified-code assertion (row 12)."""
import json,sqlite3,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]))
from verifier.core import decode,unb64
con=sqlite3.connect(HERE.parents[1]/'iphone-20260923/captures/papi-20260923-snapshot.sqlite')
nonces=dict(con.execute('SELECT id,nonce FROM challenges'))
rows={i:json.loads(r) for i,r in con.execute('SELECT id,request_json FROM evidence WHERE id IN (10,11,12)')}
h=lambda b:'0x'+b.hex()
att=decode(unb64(rows[10]['attestation']))
auth=att['authData']
out=dict(cert=h(att['attStmt']['x5c'][0]),auth=h(auth),clientData=h(unb64(nonces[rows[10]['challenge_id']])),kid=h(unb64(rows[10]['key_id'])),
         appHash=h(auth[:32]),cdhash=h(bytes.fromhex(json.load(open(HERE.parents[1]/'iphone-20260923/replay-expected.json'))['reference_cdhashes']['honest'])),aaguid=h(auth[37:53]))
for name,row in (('assert',11),('modified',12)):
    a=decode(unb64(rows[row]['assertion']));r,s=decode_dss_signature(a['signature'])
    out[name]=dict(context=h(unb64(rows[row]['client_data'])),auth=h(a['authenticatorData']),r=h(r.to_bytes(32,'big')),s=h(s.to_bytes(32,'big')))
json.dump(out,open(HERE.parent/'fixtures/iphone-apple.json','w'),indent=2)
