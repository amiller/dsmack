#!/usr/bin/env python3
import copy
import datetime
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'app-attest/contracts/fixtures/local-data/mutations'


def tlv(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + value


@dataclass
class Node:
    tag: int
    value: bytes = b''
    children: list = None
    raw: bytes = None

    def encode(self):
        if self.raw is not None:
            return self.raw
        return tlv(self.tag, b''.join(n.encode() for n in self.children) if self.children is not None else self.value)


def parse(data):
    def one(p):
        tag, length = data[p:p+2]
        q = p + 2
        if length & 128:
            count = length & 127
            length = int.from_bytes(data[q:q+count], 'big')
            q += count
        end = q + length
        assert end <= len(data)
        children = None
        if tag & 32:
            children = []
            at = q
            while at < end:
                child, at = one(at)
                children.append(child)
            assert at == end
        return Node(tag, data[q:end], children), end
    node, end = one(0)
    assert end == len(data)
    return node


def raw(f, key):
    return bytes.fromhex(f[key].removeprefix('0x'))


def hexbytes(b):
    return '0x' + b.hex()


def ext(tbs, oid):
    return next(e for e in tbs.children[7].children[0].children if e.children[0].value.hex() == oid)


def sign(tbs, key, algorithm):
    return Node(48, children=[tbs, Node(48, children=[Node(6, bytes.fromhex(algorithm))]), Node(3, b'\0' + key.sign(tbs.encode(), ec.ECDSA(hashes.SHA256() if algorithm.endswith('02') else hashes.SHA384())))])


def point(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    root = ec.generate_private_key(ec.SECP384R1())
    issuer = ec.generate_private_key(ec.SECP384R1())
    # Keys are deliberately local and ephemeral; only public coordinates leave this process.
    rp = point(root)
    (OUT / 'root.json').write_text(json.dumps({'x': hexbytes(rp[1:49]), 'y': hexbytes(rp[49:])}) + '\n')
    apple_root = x509.load_pem_x509_certificate((ROOT/'trust/apple-app-attestation-root.pem').read_bytes()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    (OUT/'apple-root.json').write_text(json.dumps({'x':hexbytes(apple_root[1:49]),'y':hexbytes(apple_root[49:])})+'\n')
    original_ca = (ROOT / 'app-attest/contracts/fixtures/apple-intermediate.der').read_bytes()
    ca = parse(original_ca).children[0]
    ca.children[6].children[1].value = b'\0' + point(issuer)
    signed_ca = sign(ca, root, '2a8648ce3d040303')
    limbs = [int.from_bytes(rp[i:i+16], 'big') for i in range(1,97,16)]
    (OUT/'RootKey.sol').write_text('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.21;\nimport {P384} from "../../../src/P384.sol";\nlibrary RootKey {function key() internal pure returns(P384.C384Elm memory){return P384.C384Elm('+','.join(str(v) for v in [limbs[0],(limbs[1]<<128)|limbs[2],limbs[3],(limbs[4]<<128)|limbs[5]])+');}}\n')
    rows = []

    def emit(name, description, f, leaf, inter, test=True, covers=()):
        f = copy.deepcopy(f)
        f['cert'] = hexbytes(leaf.encode() if isinstance(leaf, Node) else leaf)
        f['intermediate'] = hexbytes(inter.encode() if isinstance(inter, Node) else inter)
        f['testRoot'] = 'root.json' if test else 'apple-root.json'
        root_point = rp if test else apple_root
        f['rootX'], f['rootY'] = hexbytes(root_point[1:49]), hexbytes(root_point[49:])
        f['category'] = 5 if name.startswith('iphone') else 3
        cert = x509.load_der_x509_certificate(raw(originals['iphone' if name.startswith('iphone') else 'mac'], 'cert'))
        f['timestamp'] = int(cert.not_valid_before.replace(tzinfo=__import__('datetime').timezone.utc).timestamp()) + 1
        original = originals['iphone' if name.startswith('iphone') else 'mac']
        acl = ext(parse(raw(original, 'cert')).children[0], '2a864886f763640806').children[-1].value
        f['acl'] = hexbytes(acl)
        def timestamp(d):
            return int(d.replace(tzinfo=datetime.timezone.utc).timestamp())
        ca_cert = x509.load_der_x509_certificate(original_ca)
        before, after = timestamp(cert.not_valid_before), timestamp(cert.not_valid_after)
        if name == 'future': before = timestamp(datetime.datetime(2049,1,1))
        if name == 'expired': after = timestamp(datetime.datetime(2020,1,1))
        auth_bytes = raw(original, 'auth')
        key_point = cert.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        marker = b'apple_cd_hash_hash_01'
        at = auth_bytes.index(marker) + len(marker) + 2
        halves = lambda b: [int.from_bytes(b[:16], 'big'), int.from_bytes(b[16:], 'big')]
        f['public_inputs'] = (halves(auth_bytes[:32]) + halves(auth_bytes[at:at+32])
                              + halves(hashlib.sha256(raw(f,'clientData')).digest())
                              + halves(key_point[1:33]) + halves(key_point[33:65])
                              + [before,after,int.from_bytes(raw(original,'aaguid'),'big'),f['category']]
                              + halves(hashlib.sha256(acl).digest()))
        ip = point(issuer) if test else ca_cert.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        subject = parse(original_ca).children[0].children[5].encode()
        f['intermediate_x'], f['intermediate_y'] = hexbytes(ip[1:49]), hexbytes(ip[49:])
        f['public_inputs'] += [int.from_bytes(ip[i:i+16],'big') for i in range(1,97,16)] + halves(hashlib.sha256(subject).digest())
        f['stage'] = 'endorsement' if name.startswith('ca-') else 'leaf'
        f['action'] = 'normal'
        (OUT / (name + '.json')).write_text(json.dumps(f) + '\n')
        rows.append(dict(id=name, description=description, fixture=name + '.json', stage=f['stage'], covers=list(covers)))

    originals = {p: json.loads((ROOT / ('app-attest/contracts/fixtures/' + n + '-apple.json')).read_text()) for p, n in [('mac', 'real'), ('iphone', 'iphone')]}
    for profile, f in originals.items():
        emit(profile + '-real', 'Unmodified private ' + profile + ' fixture and Apple chain', f, raw(f, 'cert'), original_ca, False)
        tbs = parse(raw(f, 'cert')).children[0]
        emit(profile + '-resigned', 'Unmodified ' + profile + ' policy under generated P384 chain', f, sign(tbs, issuer, '2a8648ce3d040302'), signed_ca)

    f = originals['mac']
    base = parse(raw(f, 'cert')).children[0]

    def leaf(name, description, mutate, covers=()):
        t = copy.deepcopy(base)
        mutate(t)
        emit(name, description, f, sign(t, issuer, '2a8648ce3d040302'), signed_ca, covers=covers)

    def field(i, value):
        return lambda t: setattr(t.children[i], 'value', value)

    def value(oid, data):
        return lambda t: setattr(ext(t, oid).children[-1], 'value', data)

    def encoded(name, description, mutate, covers):
        c = sign(copy.deepcopy(base), issuer, '2a8648ce3d040302')
        c = mutate(c)
        emit(name, description, f, c, signed_ca, covers=covers)

    leaf('version', 'Version is v2', lambda t: setattr(t.children[0].children[0], 'value', b'\1'), ['certificate version'])
    for name, data, reason in [('serial-empty', b'', 'DER integer'), ('serial-negative', b'\x80', 'DER negative integer'), ('serial-padded', b'\0\1', 'DER padded integer'), ('serial-wide', b'\1'*21, 'DER integer width')]:
        leaf(name, name, field(1, data), [reason])
    leaf('inner-alg', 'Inner signature algorithm differs', lambda t: setattr(t.children[2].children[0], 'value', bytes.fromhex('2a8648ce3d040303')), ['inner signature algorithm'])
    leaf('issuer', 'Issuer differs from intermediate subject', lambda t: t.children[3].children.reverse(), ['issuer name'])
    for name, data, reason in [('utc-profile', b'260101000000+0000', 'UTC profile'), ('utc-digit', b'2x0101000000Z', 'UTC digit'), ('utc-range', b'261301000000Z', 'UTC range'), ('utc-day', b'260230000000Z', 'UTC day'), ('future', b'490101000000Z', 'certificate validity')]:
        leaf(name, name, lambda t, d=data: setattr(t.children[4].children[0], 'value', d), [reason])
    leaf('expired', 'Leaf expired at harness timestamp', lambda t: setattr(t.children[4].children[1], 'value', b'200101000000Z'), ['certificate validity'])
    leaf('validity-trailing', 'Third validity field', lambda t: t.children[4].children.append(Node(5)), ['validity trailing'])
    leaf('spki-alg', 'Wrong P256 curve OID', lambda t: setattr(t.children[6].children[0].children[-1], 'value', b'\1'), ['P256 SPKI'])
    leaf('spki-point', 'Compressed point marker', lambda t: setattr(t.children[6].children[1], 'value', b'\0\2' + t.children[6].children[1].value[2:]), ['public key encoding'])
    leaf('tbs-trailing', 'Extra TBS field', lambda t: t.children.append(Node(5)), ['TBS trailing'])
    leaf('extensions-trailing', 'Extra field after extensions sequence', lambda t: t.children[7].children.append(Node(5)), ['extensions trailing'])
    for oid, name, data, reason in [('551d13', 'constraints', b'0\3\1\1\xff', 'leaf constraints'), ('551d0f', 'usage', b'\3\2\1\6', 'leaf usage'), ('551d25', 'eku', b'0\0', 'Apple EKU'), ('2a864886f763640802', 'nonce', b'0\0', 'certificate nonce'), ('2a864886f763640806', 'acl', b'0\0', 'key ACL')]:
        leaf(name, 'Wrong ' + name + ' value', value(oid, data), [reason])
    leaf('nonce-digest', 'Correct nonce framing with wrong digest', value('2a864886f763640802', bytes.fromhex('3024a1220420')+bytes(32)), ['certificate nonce'])
    leaf('critical-false', 'Explicit FALSE critical flag', lambda t: setattr(ext(t, '551d13').children[1], 'value', b'\0'), ['critical encoding'])
    leaf('critical-wide', 'Two-byte critical flag', lambda t: setattr(ext(t, '551d13').children[1], 'value', b'\xff\xff'), ['critical encoding'])
    leaf('constraints-noncritical', 'Basic constraints not critical', lambda t: ext(t, '551d13').children.pop(1), ['leaf constraints'])
    leaf('usage-noncritical', 'Key usage not critical', lambda t: ext(t, '551d0f').children.pop(1), ['leaf usage'])
    leaf('unknown-critical', 'Unknown critical certificate extension', lambda t: t.children[7].children[0].children.append(Node(48, children=[Node(6, b'\x2a\3\4'), Node(1, b'\xff'), Node(4, b'')])), ['unsupported critical extension'])
    leaf('unknown-noncritical', 'Unknown noncritical extension is allowed', lambda t: t.children[7].children[0].children.append(Node(48, children=[Node(6, b'\x2a\3\4'), Node(4, b'')])))
    leaf('duplicate-cert-extension', 'Duplicate OID', lambda t: t.children[7].children[0].children.append(copy.deepcopy(ext(t, '551d13'))), ['duplicate certificate extension'])
    leaf('too-many-extensions', 'Seventeen unique extensions', lambda t: t.children[7].children[0].children.extend(Node(48, children=[Node(6, bytes([42, 3, i])), Node(4)]) for i in range(17-len(t.children[7].children[0].children))), ['too many extensions'])
    leaf('missing-cert-extension', 'Missing EKU', lambda t: t.children[7].children[0].children.remove(ext(t, '551d25')), ['missing certificate extension'])
    leaf('extension-wrong-value-tag', 'Extension value is INTEGER', lambda t: setattr(ext(t, '551d25').children[-1], 'tag', 2), ['extension value'])
    leaf('reordered-fields', 'Subject before validity', lambda t: t.children.__setitem__(slice(4,6), list(reversed(t.children[4:6]))), ['DER tag'])
    leaf('reordered-cert-extensions', 'Reordered certificate extensions accepted', lambda t: t.children[7].children[0].children.reverse())
    leaf('wrong-tag', 'Serial has OCTET STRING tag', lambda t: setattr(t.children[1], 'tag', 4), ['DER tag'])
    leaf('long-tag', 'Serial has unsupported long tag', lambda t: setattr(t.children[1], 'tag', 31), ['DER long tag'])
    leaf('nonminimal-length', 'Short serial encoded in long length form', lambda t: setattr(t.children[1], 'raw', b'\2\x81' + bytes([len(t.children[1].value)]) + t.children[1].value), ['DER nonminimal length'])
    leaf('leading-length-zero', 'Serial length has leading zero', lambda t: setattr(t.children[1], 'raw', b'\2\x82\0' + bytes([len(t.children[1].value)]) + t.children[1].value), ['DER leading length zero'])
    leaf('indefinite-length', 'Serial has indefinite length', lambda t: setattr(t.children[1], 'raw', b'\2\x80\0\0'), ['DER length'])
    encoded('cert-size', 'Certificate exceeds 4096 bytes', lambda c: c.encode() + bytes(4097), ['certificate size'])
    encoded('cert-trailing', 'Trailing byte outside certificate', lambda c: c.encode() + b'\0', ['certificate trailing'])
    encoded('cert-truncated', 'Truncated certificate body', lambda c: c.encode()[:-1], ['DER truncated'])
    encoded('cert-empty', 'Empty certificate', lambda c: b'', ['DER bounds'])
    encoded('outer-alg', 'Outer algorithm wrong', lambda c: Node(48, children=[c.children[0], Node(48, children=[Node(6,b'\1')]), c.children[2]]), ['signature algorithm'])
    encoded('signature-bits', 'Nonzero signature unused bits', lambda c: Node(48, children=c.children[:2]+[Node(3,b'\1'+c.children[2].value[1:])]), ['certificate signature bits'])
    encoded('signature-trailing', 'Bytes after signature SEQUENCE', lambda c: Node(48, children=c.children[:2]+[Node(3,c.children[2].value+b'\0')]), ['signature trailing'])
    for name, data, reason in [('scalar-zero', b'\0', 'zero scalar'), ('scalar-range', bytes.fromhex('00ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'), 'scalar range')]:
        def change(c, d=data):
            sig = parse(c.children[2].value[1:]); sig.children[0].value = d
            c.children[2].value = b'\0' + sig.encode()
            return c
        encoded(name, name, change, [reason])
    def sig_extra(c):
        sig = parse(c.children[2].value[1:]); sig.children.append(Node(2,b'\1')); c.children[2].value=b'\0'+sig.encode(); return c
    encoded('signature-fields', 'Third signature INTEGER', sig_extra, ['signature fields'])
    order = int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',16)
    for name, high in [('signature-high-s',True),('signature-low-s',False)]:
        def normalize(c, h=high):
            sig=parse(c.children[2].value[1:]); n=int.from_bytes(sig.children[1].value,'big')
            n=max(n,order-n) if h else min(n,order-n)
            data=n.to_bytes(48,'big').lstrip(b'\0')
            sig.children[1].value=(b'\0' if data[0]&128 else b'')+data
            c.children[2].value=b'\0'+sig.encode(); return c
        encoded(name,name,normalize,[])
    def bad_signature(c):
        sig=parse(c.children[2].value[1:]); sig.children[0].value=b'\1'; c.children[2].value=b'\0'+sig.encode(); return c
    encoded('bad-leaf-signature', 'Valid DER with incorrect leaf signature', bad_signature, ['Apple certificate signature'])

    def auth(name, description, mutate, covers=()):
        a = mutate(bytearray(raw(f, 'auth')))
        ff = copy.deepcopy(f); ff['auth'] = hexbytes(a)
        t = copy.deepcopy(base)
        nonce = hashlib.sha256(a + hashlib.sha256(raw(f, 'clientData')).digest()).digest()
        ext(t, '2a864886f763640802').children[-1].value = bytes.fromhex('3024a1220420') + nonce
        emit(name, description, ff, sign(t, issuer, '2a8648ce3d040302'), signed_ca, covers=covers)

    def setbyte(p, n):
        def mutate(a):
            a[p] = n
            return a
        return mutate

    for name, mut, reason in [('auth-short', lambda a:a[:36], 'auth size'), ('auth-long', lambda a:a+bytes(1025), 'auth size'), ('flags', setbyte(32, 0xc2), 'auth flags'), ('no-ed', setbyte(32, 0x40), 'auth flags'), ('no-at', setbyte(32,0x80), 'enrollment flags/counter'), ('counter', setbyte(36,1), 'enrollment flags/counter'), ('enrollment-short', lambda a:a[:163], 'enrollment flags/counter'), ('aaguid', setbyte(37,0), 'AAGUID/credential length'), ('credential-length', setbyte(54,31), 'AAGUID/credential length'), ('kid', setbyte(55,0), 'credential key'), ('cose', setbyte(87,0xa4), 'COSE key')]:
        auth(name, name, mut, [reason])
    # Split canonical extension items without changing their bytes.
    a = raw(f, 'auth'); start=164
    def cbor_item(data, p):
        h=data[p]; n=h&31; q=p+1
        if n==24: n=data[q]; q+=1
        elif n==25: n=int.from_bytes(data[q:q+2], 'big'); q+=2
        return q+n
    items=[]; p=start+1
    while p<len(a):
        end=cbor_item(a,cbor_item(a,p)); items.append(a[p:end]); p=end
    def extensions(parts, head=None):
        return lambda a: a[:164] + (bytes([0xa0+len(parts)]) if head is None else head) + b''.join(parts)
    auth('cbor-reordered', 'Reversed extension keys accepted', extensions(list(reversed(items))))
    auth('cbor-duplicate', 'Duplicate extension key', extensions(items+[items[0]]), ['duplicate extension'])
    auth('cbor-missing', 'Missing extension key', extensions(items[:-1]), ['missing extension'])
    auth('cbor-unknown', 'Unknown byte-string extension', extensions(items+[b'\x61x\x40']), ['unknown extension'])
    auth('cbor-trailing', 'Trailing byte after extension map', lambda a:a+b'\0', ['auth trailing data'])
    auth('cbor-nonminimal-map', 'Map count uses nonminimal one-byte head', extensions(items,b'\xb8\3'), ['CBOR nonminimal'])
    auth('cbor-nonminimal-map16', 'Map count uses nonminimal two-byte head', extensions(items,b'\xb9\0\3'), ['CBOR nonminimal'])
    auth('cbor-nonminimal-key', 'Short text key uses one-byte length', extensions([b'\x78'+bytes([items[0][0]&31])+items[0][1:]]+items[1:]), ['CBOR nonminimal'])
    auth('cbor-indefinite', 'Indefinite map head', extensions(items,b'\xbf'), ['CBOR length profile'])
    auth('cbor-type', 'Extension map has array tag', extensions(items,b'\x83'), ['CBOR type'])
    auth('cbor-truncated', 'No extension map', lambda a:a[:164], ['CBOR truncated'])
    auth('cbor-truncated-head8', 'Map one-byte count truncated', lambda a:a[:164]+b'\xb8', ['CBOR truncated'])
    auth('cbor-truncated-head16', 'Map two-byte count truncated', lambda a:a[:164]+b'\xb9\0', ['CBOR truncated'])
    auth('cbor-long-head', 'Unsupported four-byte map count', extensions(items,b'\xba\0\0\0\3'), ['CBOR length profile'])
    auth('cbor-bounds', 'Map key text exceeds auth length', lambda a:a[:164]+b'\xa1\x79\x03\xff', ['CBOR bounds'])
    for key, data, reason in [('apple_cd_hash_hash_01', b'\x41x', 'CDHash length'), ('apple_cd_hash_type_01', b'\x41\1', 'CDHash type'), ('apple_validation_category_01', b'\x44\0\0\0\0', 'validation category')]:
        keybytes=key.encode(); item=bytes([0x60+len(keybytes)])+keybytes if len(keybytes)<24 else b'\x78'+bytes([len(keybytes)])+keybytes
        parts=[(item+data if keybytes in i else i) for i in items]
        auth('cbor-'+reason.lower().replace(' ','-'), reason, extensions(parts), [reason])
    auth('optional-bundle', 'Optional bundle text accepted', extensions(items+[b'\x77apple_bundle_version_01\x631.0']))
    auth('bundle-type', 'Bundle version must be text', extensions(items+[b'\x77apple_bundle_version_01\x41x']), ['CBOR type'])
    auth('cose-reordered', 'Reordered COSE map rejected by exact profile', lambda a:a[:87]+b'\xa5\x03\x26\x01\x02'+a[92:], ['COSE key'])
    auth('cose-x', 'Wrong COSE x coordinate', setbyte(97, raw(f,'auth')[97]^1), ['COSE key'])
    auth('cose-y', 'Wrong COSE y coordinate', setbyte(132, raw(f,'auth')[132]^1), ['COSE key'])
    auth('cose-separator', 'Wrong COSE coordinate separator', setbyte(129,0), ['COSE key'])
    auth('extension-count', 'Five extension entries', extensions(items+[items[0],items[1]]), ['duplicate extension'])
    key=b'apple_validation_category_01'
    auth('category-length', 'Three-byte category', extensions([(i[:-5]+b'\x43\0\0\0' if key in i else i) for i in items]), ['validation category'])
    auth('flags-up', 'User-presence flag accepted', setbyte(32,0xc1))

    def intermediate(name, description, mutate, covers):
        t=copy.deepcopy(ca); mutate(t)
        emit(name, description, f, sign(copy.deepcopy(base),issuer,'2a8648ce3d040302'), sign(t,root,'2a8648ce3d040303'), covers=covers)
    intermediate('ca-version', 'Intermediate v2', lambda t:setattr(t.children[0].children[0],'value',b'\1'), ['certificate version'])
    intermediate('ca-validity-trailing', 'Third validity field', lambda t:t.children[4].children.append(Node(5)), ['validity trailing'])
    intermediate('ca-tbs-trailing', 'Extra TBS field', lambda t:t.children.append(Node(5)), ['TBS trailing'])
    intermediate('ca-extensions-trailing', 'Extra extension wrapper field', lambda t:t.children[7].children.append(Node(5)), ['extensions trailing'])
    intermediate('ca-too-many-extensions', 'Seventeen unique extensions', lambda t:t.children[7].children[0].children.extend(Node(48,children=[Node(6,bytes([42,3,i])),Node(4)]) for i in range(17-len(t.children[7].children[0].children))), ['too many extensions'])
    intermediate('ca-critical-false', 'Explicit false critical', lambda t:setattr(ext(t,'551d13').children[1],'value',b'\0'), ['critical encoding'])
    intermediate('ca-extension-value', 'Wrong extension value tag', lambda t:setattr(ext(t,'551d13').children[-1],'tag',2), ['extension value'])
    intermediate('ca-spki', 'Intermediate wrong curve', lambda t:setattr(t.children[6].children[0].children[-1],'value',b'\1'), ['P384 SPKI'])
    intermediate('ca-not-ca', 'Intermediate CA=false', value('551d13',b'0\0'), ['CA constraints'])
    intermediate('ca-usage', 'Intermediate lacks keyCertSign', value('551d0f',b'\3\2\7\x80'), ['CA usage'])
    intermediate('ca-missing-constraints', 'Intermediate missing basic constraints', lambda t:t.children[7].children[0].children.remove(ext(t,'551d13')), ['missing certificate extension'])
    intermediate('ca-missing-usage', 'Intermediate missing key usage', lambda t:t.children[7].children[0].children.remove(ext(t,'551d0f')), ['missing certificate extension'])
    intermediate('ca-future', 'Intermediate validity starts in future', lambda t:setattr(t.children[4].children[0],'value',b'490101000000Z'), ['certificate validity'])
    intermediate('ca-expired', 'Intermediate validity ends in past', lambda t:setattr(t.children[4].children[1],'value',b'200101000000Z'), ['certificate validity'])
    intermediate('ca-inner-alg', 'Intermediate inner algorithm mismatch', lambda t:setattr(t.children[2].children[0],'value',bytes.fromhex('2a8648ce3d040302')), ['inner signature algorithm'])
    intermediate('ca-constraints-noncritical', 'Intermediate constraints must be critical', lambda t:ext(t,'551d13').children.pop(1), ['CA constraints'])
    intermediate('ca-usage-noncritical', 'Intermediate usage must be critical', lambda t:ext(t,'551d0f').children.pop(1), ['CA usage'])
    intermediate('ca-pathlen', 'Intermediate pathLen differs from Apple profile', value('551d13',b'0\6\1\1\xff\2\1\1'), ['CA constraints'])
    intermediate('ca-point', 'Intermediate compressed point marker', lambda t:setattr(t.children[6].children[1],'value',b'\0\2'+t.children[6].children[1].value[2:]), ['public key encoding'])
    intermediate('ca-duplicate', 'Duplicate intermediate extension', lambda t:t.children[7].children[0].children.append(copy.deepcopy(ext(t,'551d13'))), ['duplicate certificate extension'])
    intermediate('ca-unknown-critical', 'Unknown critical intermediate extension', lambda t:t.children[7].children[0].children.append(Node(48,children=[Node(6,b'\x2a\3\4'),Node(1,b'\xff'),Node(4)])), ['unsupported critical extension'])
    intermediate('ca-serial-negative', 'Intermediate negative serial', field(1,b'\x80'), ['DER negative integer'])
    intermediate('ca-wrong-tag', 'Intermediate wrong serial tag', lambda t:setattr(t.children[1],'tag',4), ['DER tag'])
    intermediate('ca-nonminimal-length', 'Intermediate serial nonminimal length', lambda t:setattr(t.children[1],'raw',b'\2\x81'+bytes([len(t.children[1].value)])+t.children[1].value), ['DER nonminimal length'])
    intermediate('ca-reordered-fields', 'Intermediate subject before validity', lambda t:t.children.__setitem__(slice(4,6),list(reversed(t.children[4:6]))), ['DER tag'])
    for name, mutation, reason in [
        ('ca-size', lambda c:c.encode()+bytes(4097), 'certificate size'),
        ('ca-signature-bits', lambda c:Node(48,children=c.children[:2]+[Node(3,b'\1'+c.children[2].value[1:])]), 'certificate signature bits'),
        ('ca-signature-trailing', lambda c:Node(48,children=c.children[:2]+[Node(3,c.children[2].value+b'\0')]), 'signature trailing'),
        ('ca-signature-fields', sig_extra, 'signature fields'),
        ('ca-outer-alg', lambda c:Node(48,children=[c.children[0],Node(48,children=[Node(6,b'\1')]),c.children[2]]), 'signature algorithm'),
        ('ca-trailing', lambda c:c.encode()+b'\0', 'certificate trailing'),
        ('ca-truncated', lambda c:c.encode()[:-1], 'DER truncated'),
    ]:
        emit(name,name,f,sign(copy.deepcopy(base),issuer,'2a8648ce3d040302'),mutation(copy.deepcopy(signed_ca)),covers=[reason])
    bad=copy.deepcopy(signed_ca); sig=parse(bad.children[2].value[1:]); sig.children[0].value=b'\1'; bad.children[2].value=b'\0'+sig.encode()
    emit('ca-signature','Incorrect root endorsement',f,sign(copy.deepcopy(base),issuer,'2a8648ce3d040302'),bad,covers=['root certificate signature'])
    def variant(ident, source, description, action, covers=(), stage='leaf'):
        ff=json.loads((OUT/(source+'.json')).read_text())
        ff['action']=action; ff['stage']=stage
        (OUT/(ident+'.json')).write_text(json.dumps(ff)+'\n')
        rows.append(dict(id=ident,description=description,fixture=ident+'.json',stage=stage,covers=list(covers)))
    variant('endorsement-duplicate','mac-resigned','Duplicate entry id reverts','duplicate',['already endorsed'],'endorsement')
    rotated=ec.generate_private_key(ec.SECP384R1())
    rt=copy.deepcopy(ca);rt.children[6].children[1].value=b'\0'+point(rotated)
    variant('endorsement-same-subject','mac-resigned','Same subject with different key accumulates','rotate',stage='endorsement')
    path=OUT/'endorsement-same-subject.json';ff=json.loads(path.read_text());ff['secondIntermediate']=hexbytes(sign(rt,root,'2a8648ce3d040303').encode());path.write_text(json.dumps(ff)+'\n')
    for ident,source in [('endorsement-future','mac-resigned'),('endorsement-expired','mac-resigned')]:
        variant(ident,source,'Enrollment checks previously endorsed validity','warp',['intermediate validity'])
        path=OUT/(ident+'.json');ff=json.loads(path.read_text());ff['timestamp']=1451606400 if ident.endswith('future') else 1924992000;path.write_text(json.dumps(ff)+'\n')
    for i in range(6):
        ident='entry-key-'+str(i)
        variant(ident,'mac-resigned','Wrong entry key limb '+str(i),'wrong-key',['Apple certificate signature'])
        path=OUT/(ident+'.json');ff=json.loads(path.read_text());ff['public_inputs'][16+i]^=1;ff['wrongLimb']=i;path.write_text(json.dumps(ff)+'\n')
    for i in range(12):
        ident='public-binding-'+str(i)
        variant(ident,'mac-resigned','Public '+('byte' if i<10 else 'validity')+' field '+str(i)+' differs from witness','normal')
        path=OUT/(ident+'.json');ff=json.loads(path.read_text());ff['public_inputs'][i]^=1;path.write_text(json.dumps(ff)+'\n')
    rt=copy.deepcopy(ca);rt.children[4].children[1].value=b'400101000000Z'
    emit('ca-post2030','Post-2030 intermediate accepted',f,sign(copy.deepcopy(base),issuer,'2a8648ce3d040302'),sign(rt,root,'2a8648ce3d040303'))
    path=OUT/'ca-post2030.json';ff=json.loads(path.read_text());ff['timestamp']=1924992000;path.write_text(json.dumps(ff)+'\n')
    (OUT/'manifest.json').write_text(json.dumps({'ids':[r['id'] for r in rows], 'cases':rows},indent=2)+'\n')
    print(f'Generated {len(rows)} cases in {OUT}')


if __name__ == '__main__':
    main()
