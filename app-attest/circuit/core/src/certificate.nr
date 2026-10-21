use crate::der::{Node, expect, node, exact, integer, utc, contents};
use sha256::sha256_var;

pub struct Cert {
    pub tbs: Node, pub issuer: Node, pub ext: Node,
    pub before: u64, pub after: u64, pub x: [u8;48], pub y: [u8;48],
    pub r: [u8;48], pub s: [u8;48],
}

fn scalar(b: [u8;4096], n: Node) -> [u8;48] {
    let raw: [u8;48] = integer(b,n);
    let order: [u8;48] = [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,199,99,77,129,244,55,45,223,88,26,13,178,72,176,167,122,236,236,25,106,204,197,41,115];
    let mut nonzero = false; let mut less = false; let mut equal = true;
    for i in 0..48 {
        nonzero = nonzero | (raw[i] != 0);
        less = less | (equal & (raw[i] < order[i])); equal = equal & (raw[i] == order[i]);
    }
    assert(nonzero, "zero scalar"); assert(less, "scalar range"); raw
}

pub fn parse(b: [u8;4096], len: u32) -> Cert {
    assert(len <= 4096, "certificate size");
    let outer = expect(b,0,len,0x30); assert(outer.end == len, "certificate trailing");
    let tbs = expect(b,outer.body,outer.end,0x30);
    let alg = expect(b,tbs.end,outer.end,0x30);
    exact(b,alg.start,alg.end,[0x30,0x0a,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2]);
    let bits = expect(b,alg.end,outer.end,3);
    assert((bits.end == outer.end) & (b[bits.body] == 0), "certificate signature bits");
    let seq = expect(b,bits.body+1,bits.end,0x30); assert(seq.end == bits.end, "signature trailing");
    let rn = expect(b,seq.body,seq.end,2); let sn = expect(b,rn.end,seq.end,2);
    assert(sn.end == seq.end, "signature fields"); let r = scalar(b,rn); let s = scalar(b,sn);
    let mut n = expect(b,tbs.body,tbs.end,0xa0);
    exact(b,n.start,n.end,[0xa0,3,2,1,2]);
    n = expect(b,n.end,tbs.end,2); let _serial: [u8;20] = integer(b,n);
    n = expect(b,n.end,tbs.end,0x30);
    exact(b,n.start,n.end,[0x30,0x0a,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2]);
    let issuer = expect(b,n.end,tbs.end,0x30);
    n = expect(b,issuer.end,tbs.end,0x30);
    let nb = expect(b,n.body,n.end,0x17); let na = expect(b,nb.end,n.end,0x17);
    assert(na.end == n.end, "validity trailing"); let before = utc(b,nb); let after = utc(b,na);
    let subject = expect(b,n.end,tbs.end,0x30);
    n = expect(b,subject.end,tbs.end,0x30);
    let pkalg = expect(b,n.body,n.end,0x30);
    exact(b,pkalg.start,pkalg.end,[0x30,0x13,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7]);
    let pk = expect(b,pkalg.end,n.end,3);
    let width: u32 = 32;
    assert((pk.end == n.end) & (pk.end-pk.body == 2+2*width) & (b[pk.body] == 0) & (b[pk.body+1] == 4), "public key encoding");
    let mut x = [0;48]; let mut y = [0;48];
    for i in 0..48 { if i < width { x[i] = b[pk.body+2+i]; y[i] = b[pk.body+2+width+i]; } }
    n = expect(b,n.end,tbs.end,0xa3); assert(n.end == tbs.end, "TBS trailing");
    let ext = expect(b,n.body,n.end,0x30); assert(ext.end == n.end, "extensions trailing");
    Cert { tbs, issuer, ext, before, after, x, y, r, s }
}

fn oid(b: [u8;4096], n: Node, id: [u8;9], len: u32) -> bool {
    let mut eq = n.end-n.body == len;
    if eq { for i in 0..9 { if i < len { eq = eq & (b[n.body+i] == id[i]); } } }
    eq
}

pub fn extensions(b: [u8;4096], seq: Node, nonce: [u8;32]) -> [u8;32] {
    let mut p = seq.body; let mut seen = [seq;16]; let mut required: u8 = 0;
    let mut acl_node = seq;
    for i in 0..16 {
        if p < seq.end {
            let ext = expect(b,p,seq.end,0x30); p = ext.end;
            let id = expect(b,ext.body,ext.end,6);
            for j in 0..i {
                let prev = seen[j];
                if id.end-id.body == prev.end-prev.body {
                    let difference = unsafe { different_byte(b,id,prev) };
                    assert(difference < id.end-id.body, "duplicate certificate extension");
                    assert(b[id.body+difference] != b[prev.body+difference], "duplicate certificate extension");
                }
            }
            seen[i] = id;
            let mut value = node(b,id.end,ext.end); let mut critical = false;
            if value.tag == 1 {
                assert((value.end-value.body == 1) & (b[value.body] == 0xff), "critical encoding");
                critical = true; value = node(b,value.end,ext.end);
            }
            assert((value.tag == 4) & (value.end == ext.end), "extension value");
            let bc = oid(b,id,[0x55,0x1d,0x13,0,0,0,0,0,0],3);
            let ku = oid(b,id,[0x55,0x1d,0x0f,0,0,0,0,0,0],3);
            if bc {
                assert(critical, "constraints critical");
                exact(b,value.body,value.end,[0x30,0]);
                required = required | 1;
            } else if ku {
                assert(critical, "usage critical");
                exact(b,value.body,value.end,[3,2,4,0xf0]);
                required = required | 2;
            } else {
                assert(!critical, "unsupported critical extension");
                if oid(b,id,[0x55,0x1d,0x25,0,0,0,0,0,0],3) {
                    exact(b,value.body,value.end,[0x30,0x0b,6,9,0x2a,0x86,0x48,0x86,0xf7,0x63,0x64,4,0x18]); required = required | 4;
                } else if oid(b,id,[0x2a,0x86,0x48,0x86,0xf7,0x63,0x64,8,2],9) {
                    assert(value.end-value.body == 38, "nonce length");
                    exact(b,value.body,value.body+6,[0x30,0x24,0xa1,0x22,4,0x20]);
                    for j in 0..32 { assert(b[value.body+6+j] == nonce[j], "certificate nonce"); } required = required | 8;
                } else if oid(b,id,[0x2a,0x86,0x48,0x86,0xf7,0x63,0x64,8,6],9) {
                    acl_node = value; required = required | 16;
                }
            }
        }
    }
    assert(p == seq.end, "too many extensions");
    assert(required == 31, "missing certificate extension");
    let (bytes,len) = contents(b,acl_node); sha256_var(bytes,len as u64)
}

pub fn pack(b: [u8;32]) -> [Field;2] {
    let mut out = [0;2];
    for i in 0..16 { out[0] = out[0]*256+b[i] as Field; out[1] = out[1]*256+b[16+i] as Field; }
    out
}

// For equal-length OIDs, one differing byte proves inequality. The caller
// constrains both the returned index and the byte inequality.
unconstrained fn different_byte(b: [u8;4096], a: Node, c: Node) -> u32 {
    let len = a.end-a.body;
    let mut result = len;
    for i in 0..len {
        if b[a.body+i] != b[c.body+i] { result = i; break; }
    }
    result
}
