pub struct Node { pub start: u32, pub body: u32, pub end: u32, pub tag: u8 }

pub fn node(b: [u8;4096], at: u32, limit: u32) -> Node {
    assert(limit <= 4096 & at + 2 <= limit, "DER bounds");
    let tag = b[at];
    assert(tag & 31 != 31, "DER long tag");
    let first = b[at+1];
    let mut body = at+2;
    let mut len = first as u32;
    if first >= 128 {
        let count = first & 127;
        assert(count > 0 & count <= 2 & body + count as u32 <= limit, "DER length");
        assert(b[body] != 0, "DER leading length zero");
        len = b[body] as u32;
        body += 1;
        if count == 2 { len = len*256 + b[body] as u32; body += 1; }
        assert(len >= 128, "DER nonminimal length");
    }
    let end = body + len;
    assert(end <= limit, "DER truncated");
    Node { start: at, body, end, tag }
}

pub fn expect(b: [u8;4096], at: u32, limit: u32, tag: u8) -> Node {
    let n = node(b, at, limit);
    assert(n.tag == tag, "DER tag");
    n
}

pub fn exact<let N: u32>(b: [u8;4096], at: u32, end: u32, value: [u8;N]) {
    assert(end == at+N, "DER exact length");
    for i in 0..N { assert(b[at+i] == value[i], "DER exact bytes"); }
}

pub fn encoded(b: [u8;4096], n: Node) -> ([u8;4096], u32) {
    let len = n.end-n.start;
    let mut out = [0;4096];
    for i in 0..4096 { out[i] = if i < len { b[n.start+i] } else { 0 }; }
    (out, len)
}

pub fn contents(b: [u8;4096], n: Node) -> ([u8;4096], u32) {
    encoded(b, Node { start: n.body, body: n.body, end: n.end, tag: n.tag })
}

pub fn integer<let N: u32>(b: [u8;4096], n: Node) -> [u8;N] {
    assert((n.tag == 2) & (n.end > n.body), "DER integer");
    let mut start = n.body;
    assert(b[start] < 128, "DER negative integer");
    if (b[start] == 0) & (n.end-start > 1) {
        assert(b[start+1] >= 128, "DER padded integer"); start += 1;
    }
    let len = n.end-start;
    assert(len <= N, "DER integer width");
    let mut out = [0;N];
    for i in 0..N { if i < len { out[N-len+i] = b[start+i]; } }
    out
}

pub fn utc(b: [u8;4096], n: Node) -> u64 {
    assert((n.tag == 0x17) & (n.end-n.body == 13) & (b[n.end-1] == 0x5a), "UTC profile");
    let mut v: [u32;6] = [0;6];
    for i in 0..6 {
        let a = b[n.body+2*i]; let c = b[n.body+2*i+1];
        assert(a >= 48 & a <= 57 & c >= 48 & c <= 57, "UTC digit");
        v[i] = (a as u32-48)*10+c as u32-48;
    }
    let year = 2000+v[0];
    assert(year >= 2020 & year <= 2049 & v[1] >= 1 & v[1] <= 12 & v[3] < 24 & v[4] < 60 & v[5] < 60, "UTC range");
    let mut days: [u32;12] = [31,28,31,30,31,30,31,31,30,31,30,31];
    if year % 4 == 0 { days[1] = 29; }
    assert(v[2] >= 1 & v[2] <= days[v[1]-1], "UTC day");
    let mut total = 0;
    for y in 1970..2049 { if y < year { total += if y%4 == 0 {366} else {365}; } }
    for m in 1..12 { if m < v[1] { total += days[m-1]; } }
    total += v[2]-1;
    (total as u64)*86400+(v[3] as u64)*3600+(v[4] as u64)*60+v[5] as u64
}
