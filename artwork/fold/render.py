#!/usr/bin/env python3
"""Fold v0.1 — deterministic sculpture from public research-NFT identity.
Offline art prototype. Does not modify token metadata or imply live admission.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np

DOMAIN = 'attest-fold-v1'


def identity(record):
    chain = int(record['chainId'])
    contract = record['contract'].lower()
    token = int(record['participantToken'])
    if chain <= 0 or token <= 0 or len(contract) != 42 or not contract.startswith('0x'):
        raise ValueError('Expected a positive chain/token and 20-byte contract address')
    bytes.fromhex(contract[2:])
    canonical = f'{DOMAIN}:{chain}:{contract}:{token}'
    digest = hashlib.sha256(canonical.encode()).digest()
    return canonical, digest


def parameters(digest):
    return {'folds': 6 + digest[0] % 3,
            'twist': 1.25 + digest[1] / 255 * .55,
            'aperture': .24 + digest[2] / 255 * .10,
            'fullness': .94 + digest[3] / 255 * .04,
            'phase': digest[4] / 255 * math.tau,
            'vermilion': [.46 + digest[5] / 255 * .07, .027, .008]}


def geometry(p):
    """Spiralling porcelain strips with separate outer, inner and edge surfaces."""
    nu, nv = 145, 41
    u, v = np.meshgrid(np.linspace(0, 1, nu), np.linspace(-1, 1, nv), indexing='ij')
    theta = p['aperture'] + u * (math.pi - 2 * p['aperture']) + .12 * v**2 * np.cos(math.pi*u)**5
    width = math.pi / p['folds'] * p['fullness'] * (.62 + .38 * np.sin(math.pi * u) ** .7)
    faces = []
    for i in range(nu - 1):
        for j in range(nv - 1):
            a = i * nv + j
            faces += [(a, a + nv, a + 1), (a + 1, a + nv, a + nv + 1)]
    faces = np.array(faces, dtype=np.uint32)
    pieces = []
    for k in range(p['folds']):
        phi = p['phase'] + k * math.tau / p['folds'] + p['twist'] * (u - .5) + width * v
        # A broad curled lip opens one edge to reveal the interior glaze.
        curl = .24 * ((v + 1) / 2) ** 3 * np.sin(math.pi * u)
        radius = 1 + curl + .025 * np.cos(math.pi * v) * np.sin(math.pi * u)
        points = np.stack([radius * np.sin(theta) * np.cos(phi),
                           radius * np.sin(theta) * np.sin(phi),
                           radius * np.cos(theta)], axis=-1)
        du = np.gradient(points, axis=0)
        dv = np.gradient(points, axis=1)
        normals = np.cross(du, dv)
        normals /= np.linalg.norm(normals, axis=-1, keepdims=True)
        if np.sum(normals * points) < 0:
            normals *= -1
        outer = points + .016 * normals
        inner = points - .016 * normals
        # Turn the polar openings toward the viewer rather than straight up.
        a = .62
        rotate = np.array([[1,0,0],[0,math.cos(a),-math.sin(a)],[0,math.sin(a),math.cos(a)]])
        outer = outer.reshape(-1, 3) @ rotate.T
        inner = inner.reshape(-1, 3) @ rotate.T
        pieces.extend([(f'outer-{k}', outer, faces, 'porcelain'),
                       (f'inner-{k}', inner, faces[:, ::-1], 'glaze')])
        perimeter = list(range(nv)) + [i * nv + nv - 1 for i in range(1, nu)] + list(range(nu * nv - 2, (nu - 1) * nv - 1, -1)) + [i * nv for i in range(nu - 2, 0, -1)]
        n = len(perimeter)
        middle = (outer[perimeter] + inner[perimeter]) / 2
        normal = outer[perimeter] - inner[perimeter]
        normal /= np.linalg.norm(normal,axis=1,keepdims=True)
        tangent = np.roll(middle,-1,axis=0) - np.roll(middle,1,axis=0)
        outward = np.cross(normal,tangent)
        outward /= np.linalg.norm(outward,axis=1,keepdims=True)
        rings = 9
        rim = np.vstack([middle + .016*(math.cos(t)*normal + math.sin(t)*outward)
                         for t in np.linspace(0,math.pi,rings)])
        rf = []
        for ring in range(rings-1):
            for i in range(n):
                j = (i+1)%n
                a,b,c,d = ring*n+i,ring*n+j,(ring+1)*n+i,(ring+1)*n+j
                rf.extend([(a,b,c),(b,d,c)])
        pieces.append((f'edge-{k}',rim,np.array(rf,dtype=np.uint32),'porcelain'))
    low = min(float(x[1][:, 2].min()) for x in pieces)
    for _, vertices, _, _ in pieces:
        vertices[:, 2] -= low - .006
    return pieces


def write_ply(path, vertices, faces):
    with path.open('w') as f:
        f.write(f'ply\nformat ascii 1.0\nelement vertex {len(vertices)}\nproperty float x\nproperty float y\nproperty float z\nelement face {len(faces)}\nproperty list uchar int vertex_indices\nend_header\n')
        np.savetxt(f,vertices,fmt='%.8f')
        for a,b,c in faces:
            f.write(f'3 {a} {b} {c}\n')


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('--receipt',type=Path,required=True)
    a.add_argument('--out',type=Path,required=True)
    a.add_argument('--size',type=int,default=1024)
    a.add_argument('--spp',type=int,default=256)
    args = a.parse_args()
    if not 64 <= args.size <= 4096 or not 1 <= args.spp <= 4096:
        a.error('size must be 64..4096; spp 1..4096')
    record=json.loads(args.receipt.read_text());canonical,digest=identity(record);p=parameters(digest)
    args.out.mkdir(parents=True,exist_ok=False)
    import mitsuba as mi
    mi.set_log_level(mi.LogLevel.Error)
    mi.set_variant('llvm_ad_rgb')
    T=mi.ScalarTransform4f
    scene={'type':'scene','integrator':{'type':'path','max_depth':8,'hide_emitters':True},
           'sensor':{'type':'perspective','fov':29,'to_world':T.look_at(origin=[3.7,-5.4,3.0],target=[0,0,1.04],up=[0,0,1]),
                     'sampler':{'type':'independent','sample_count':args.spp},
                     'film':{'type':'hdrfilm','width':args.size,'height':args.size,'rfilter':{'type':'gaussian'}}},
           'porcelain':{'type':'roughplastic','distribution':'ggx','alpha':.16,'int_ior':1.49,'diffuse_reflectance':{'type':'rgb','value':[.76,.72,.65]}},
           'glaze':{'type':'roughplastic','distribution':'ggx','alpha':.075,'int_ior':1.53,'diffuse_reflectance':{'type':'rgb','value':p['vermilion']}},
           'floor':{'type':'rectangle','to_world':T.scale([200,200,1]),'bsdf':{'type':'diffuse','reflectance':{'type':'rgb','value':[.49,.46,.42]}}},
           'ambient':{'type':'constant','radiance':{'type':'rgb','value':[.32,.32,.32]}}}
    def light(name,origin,scale,power):
        scene[name]={'type':'rectangle','to_world':T.look_at(origin=origin,target=[0,0,1],up=[0,0,1]) @ T.scale([scale[0],scale[1],1]),'emitter':{'type':'area','radiance':{'type':'rgb','value':power}}}
    light('key',[-3,-4,6],[2.6,2.6],[5,4.75,4.3])
    light('rim',[3,2,4],[1.3,2],[3,3,3.1])
    hashes={}
    for name,vertices,faces,material in geometry(p):
        path=args.out/(name+'.ply');write_ply(path,vertices,faces)
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        scene[name]={'type':'ply','filename':str(path.resolve()),'bsdf':{'type':'ref','id':material}}
    loaded=mi.load_dict(scene)
    image=mi.render(loaded,seed=int.from_bytes(digest[8:12],'big'),spp=args.spp)
    mi.util.write_bitmap(str(args.out/'fold.png'),image,write_async=False)
    manifest={'schema':1,'renderer':DOMAIN,'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'identity':canonical,'seed':digest.hex(),'parameters':p,'size':args.size,'spp':args.spp,'mitsuba':mi.__version__,'numpy':np.__version__,'meshes':hashes,'imageSha256':hashlib.sha256((args.out/'fold.png').read_bytes()).hexdigest(),'scope':'Offline procedural art study, not tokenURI metadata. Receipt supplied by caller; renderer does not verify chain ownership. Geometry deterministic; cross-platform pixel identity unverified.'}
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'image':str(args.out/'fold.png'),'parameters':p}))


if __name__=='__main__':main()
