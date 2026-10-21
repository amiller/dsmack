use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fr::Secp384r1_Fr as Fr;
use bignum::fields::secp384r1Fq::Secp384r1_Fq as Fq;
use crate::certificate::{parse, extensions, pack};
use crate::der::encoded;
use sha256::sha256_var;

pub fn check(leaf: [u8;4096], leaf_len: u32, intermediate_x: [u8;48], intermediate_y: [u8;48],
    auth: [u8;1024], auth_len: u32, client_hash: [u8;32], public: [Field;24]) {
    let l = parse(leaf,leaf_len);
    let (issuer,len) = encoded(leaf,l.issuer);
    let subject_hash = pack(sha256_var(issuer,len as u64));
    assert((public[22] == subject_hash[0]) & (public[23] == subject_hash[1]), "intermediate subject hash");
    let coords = [intermediate_x,intermediate_y];
    for c in 0..2 {
        for limb in 0..3 {
            let mut value: Field = 0;
            for i in 0..16 { value = value*256+coords[c][16*limb+i] as Field; }
            assert(public[16+3*c+limb] == value, "intermediate key");
        }
    }
    let (tbs,len) = encoded(leaf,l.tbs);
    verify(intermediate_x,intermediate_y,l.r,l.s,sha256_var(tbs,len as u64));
    let mut message = [0;1056]; assert(auth_len <= 1024, "auth size");
    for i in 0..1024 { message[i] = if i < auth_len { auth[i] } else { 0 }; }
    for i in 0..32 { message[auth_len+i] = client_hash[i]; }
    let nonce = sha256_var(message,(auth_len+32) as u64);
    let acl = extensions(leaf,l.ext,nonce);
    let mut x = [0;32]; let mut y = [0;32];
    for i in 0..32 { x[i] = l.x[i]; y[i] = l.y[i]; }
    let (rp,cdhash,guid,category) = crate::auth::check(auth,auth_len,x,y);
    let values = [pack(rp),pack(cdhash),pack(client_hash),pack(x),pack(y)];
    for i in 0..5 { for j in 0..2 { assert(public[2*i+j] == values[i][j], "public bytes"); } }
    assert((public[10] == l.before as Field) & (public[11] == l.after as Field), "public validity");
    assert((public[12] == guid) & (public[13] == category as Field), "public auth policy");
    let acl = pack(acl); assert((public[14] == acl[0]) & (public[15] == acl[1]), "public ACL");
}

fn verify<let N: u32>(x: [u8;48], y: [u8;48], r: [u8;48], s: [u8;48], hash: [u8;N]) {
    let s = Fr::from_be_bytes(s);
    let half = Fr::modulus().udiv(Fr::from(2));
    // Solidity accepts high-s. Normalize the parsed scalar inside the circuit.
    let s = if s > half { Fr::zero()-s } else { s };
    assert(ecdsa::ecdsa::verify_secp384r1_ecdsa(Fq::from_be_bytes(x),Fq::from_be_bytes(y),hash,(Fr::from_be_bytes(r),s)), "certificate signature");
}

