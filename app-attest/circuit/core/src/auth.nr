use sha256::sha256_var;

fn head(b: [u8;1024], len: u32, at: u32, major: u8) -> (u32, u32) {
    assert(at < len, "CBOR truncated");
    let h = b[at]; let mut p = at+1;
    assert(h >> 5 == major, "CBOR type");
    let mut n = (h & 31) as u32;
    assert(n < 26, "CBOR length profile");
    if n == 24 {
        assert(p < len, "CBOR truncated"); n = b[p] as u32; p += 1;
        assert(n >= 24, "CBOR nonminimal");
    } else if n == 25 {
        assert(p+2 <= len, "CBOR truncated"); n = b[p] as u32*256+b[p+1] as u32; p += 2;
        assert(n > 255, "CBOR nonminimal");
    }
    (n,p)
}

fn item(b: [u8;1024], len: u32, at: u32, major: u8) -> (u32, u32, u32) {
    let (size,start) = head(b,len,at,major);
    assert(start+size <= len, "CBOR bounds");
    (size,start,start+size)
}

fn key<let N: u32>(b: [u8;1024], at: u32, len: u32, s: [u8;N]) -> bool {
    let mut equal = len == N;
    // The key lies inside authData; short keys must not cause an out-of-bounds read.
    for i in 0..N { if i < len { equal = equal & (b[at+i] == s[i]); } }
    equal
}

pub fn check(auth: [u8;1024], len: u32, x: [u8;32], y: [u8;32]) -> ([u8;32], [u8;32], Field, u32) {
    assert(len >= 37 & len <= 1024, "auth size");
    let flags = auth[32];
    assert((flags & 0x3e == 0) & (flags & 0x80 != 0), "auth flags");
    assert((flags & 0x40 != 0) & (len >= 164), "enrollment flags/counter");
    for i in 33..37 { assert(auth[i] == 0, "enrollment counter"); }
    let mut guid: Field = 0;
    for i in 37..53 { guid = guid*256+auth[i] as Field; }
    assert((auth[53] == 0) & (auth[54] == 32), "credential length");
    let mut point = [0;65]; point[0] = 4;
    for i in 0..32 { point[1+i] = x[i]; point[33+i] = y[i]; }
    let kid = sha256_var(point,65);
    for i in 0..32 { assert(auth[55+i] == kid[i], "credential key"); }
    let cose = [0xa5,1,2,3,0x26,0x20,1,0x21,0x58,0x20];
    for i in 0..10 { assert(auth[87+i] == cose[i], "COSE key"); }
    for i in 0..32 {
        assert(auth[97+i] == x[i], "COSE x"); assert(auth[132+i] == y[i], "COSE y");
    }
    assert((auth[129] == 0x22) & (auth[130] == 0x58) & (auth[131] == 0x20), "COSE key");
    let (count,start) = head(auth,len,164,5);
    // Uniqueness and the closed four-key vocabulary imply this bound.
    assert(count <= 4, "extension count");
    let mut p = start; let mut seen: u8 = 0;
    let mut cdhash = [0;32]; let mut category: u32 = 0;
    for i in 0..4 {
        if i < count {
            let (ks,kp,next) = item(auth,len,p,3); p = next;
            let bundle = key(auth,kp,ks,"apple_bundle_version_01".as_bytes());
            let cd = key(auth,kp,ks,"apple_cd_hash_hash_01".as_bytes());
            let ty = key(auth,kp,ks,"apple_cd_hash_type_01".as_bytes());
            let cat = key(auth,kp,ks,"apple_validation_category_01".as_bytes());
            assert(bundle | cd | ty | cat, "unknown extension");
            let flag: u8 = if bundle {8} else if cd {1} else if ty {2} else {4};
            let (vs,vp,next) = item(auth,len,p,if bundle {3} else {2}); p = next;
            if cd {
                assert(vs == 32, "CDHash length");
                for j in 0..32 { cdhash[j] = auth[vp+j]; }
            } else if ty { assert((vs == 1) & (auth[vp] == 2), "CDHash type"); }
            else if cat {
                assert(vs == 4, "validation category");
                for j in 0..4 { category += (auth[vp+j] as u32) << (8*j); }
            }
            assert(seen & flag == 0, "duplicate extension"); seen = seen | flag;
        }
    }
    assert(seen & 7 == 7, "missing extension");
    assert(p == len, "auth trailing data");
    let mut rp = [0;32]; for i in 0..32 { rp[i] = auth[i]; }
    (rp,cdhash,guid,category)
}
