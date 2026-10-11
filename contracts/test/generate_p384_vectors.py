import json,random
from pathlib import Path
p=2**384-2**128-2**96+2**32-1
n=int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',16)
g=(int('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',16),int('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',16))
q=(int('ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706',16),int('9e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99',16))
def add(a,b):
 if a is None:return b
 if b is None:return a
 x,y=a;z,w=b
 if x==z and (y+w)%p==0:return None
 k=((3*x*x-3)*pow(2*y,-1,p) if a==b else (w-y)*pow(z-x,-1,p))%p
 t=(k*k-x-z)%p;return t,(k*(x-t)-y)%p
def mul(a,k):
 r=None
 while k:
  if k&1:r=add(r,a)
  a=add(a,a);k>>=1
 return r
rng=random.Random(20260916);pairs=[(0,0),(1,0),(0,1),(1,1),(n-1,0),(n,0),(0,n),(2**383,2**255)]+[(rng.randrange(n),rng.randrange(n)) for _ in range(16)]
def limbs(x):return [str(x>>256),str(x%(2**256))]
v=[]
for u,w in pairs:
 r=add(mul(g,u),mul(q,w));v.append(limbs(u)+limbs(w)+limbs(r[0] if r else 0)+limbs(r[1] if r else 0))
Path('ios-app-attest/solidity/fixtures/p384-joint.json').write_text(json.dumps(v))
