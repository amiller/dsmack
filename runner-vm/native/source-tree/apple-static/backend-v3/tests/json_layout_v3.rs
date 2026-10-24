//! Strict JSON parsing of the receipt/run-result output and C/Rust struct layout agreement.

use dsmack_backend_v3::ctl_capi_v3::{DsmackCtlDiskSetV3, DsmackCtlLaunchSpecV3};
use dsmack_backend_v3::finalize::{ConsoleDigest, ResultDigest};
use dsmack_backend_v3::receipt_v3::{LaunchReceiptV3, RunResultV3};

// ---------- a minimal strict JSON value + recursive-descent parser ----------

#[derive(Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn new(s: &'a str) -> Self {
        P { b: s.as_bytes(), i: 0 }
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.ws();
        let v = self.value()?;
        self.ws();
        if self.i != self.b.len() {
            return Err(format!("trailing bytes at {}", self.i));
        }
        Ok(v)
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.b.get(self.i).copied() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'n') => self.lit("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            other => Err(format!("unexpected {other:?} at {}", self.i)),
        }
    }
    fn lit(&mut self, s: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // {
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(format!("expected : at {}", self.i));
            }
            self.i += 1;
            let v = self.value()?;
            out.push((k, v));
            self.ws();
            match self.b.get(self.i) {
                Some(&b',') => {
                    self.i += 1;
                }
                Some(&b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(out));
                }
                other => return Err(format!("expected , or }} got {other:?} at {}", self.i)),
            }
        }
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // [
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            let v = self.value()?;
            out.push(v);
            self.ws();
            match self.b.get(self.i) {
                Some(&b',') => self.i += 1,
                Some(&b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(out));
                }
                other => return Err(format!("expected , or ] got {other:?} at {}", self.i)),
            }
        }
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err(format!("expected string at {}", self.i));
        }
        self.i += 1;
        let mut s = String::new();
        loop {
            match self.b.get(self.i).copied() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(s);
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.b.get(self.i).copied() {
                        Some(b'"') => s.push('"'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'/') => s.push('/'),
                        Some(b'n') => s.push('\n'),
                        Some(b't') => s.push('\t'),
                        Some(b'r') => s.push('\r'),
                        Some(b'u') => {
                            let hex = std::str::from_utf8(&self.b[self.i + 1..self.i + 5])
                                .map_err(|_| "bad \\u")?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u hex")?;
                            s.push(char::from_u32(cp).ok_or("bad codepoint")?);
                            self.i += 4;
                        }
                        other => return Err(format!("bad escape {other:?}")),
                    }
                    self.i += 1;
                }
                Some(c) => {
                    s.push(c as char);
                    self.i += 1;
                }
            }
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while self
            .b
            .get(self.i)
            .map(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
            .unwrap_or(false)
        {
            self.i += 1;
        }
        std::str::from_utf8(&self.b[start..self.i])
            .unwrap()
            .parse::<f64>()
            .map(Json::Num)
            .map_err(|_| "bad number".into())
    }
}

fn parse(s: &str) -> Json {
    P::new(s).parse().unwrap_or_else(|e| panic!("JSON PARSE FAILED: {e}\n{s}"))
}

fn get<'a>(j: &'a Json, k: &str) -> &'a Json {
    match j {
        Json::Obj(kv) => &kv.iter().find(|(kk, _)| kk == k).unwrap_or_else(|| panic!("missing key {k}")).1,
        _ => panic!("not an object"),
    }
}

fn sample_receipt() -> LaunchReceiptV3 {
    LaunchReceiptV3 {
        spec_sha256: "a".repeat(64),
        observed_kernel_sha256: "b".repeat(64),
        observed_initrd_sha256: None,
        observed_cmdline_sha256: "c".repeat(64),
        cmdline: "console=hvc0 panic=-1 \"q\"\\z".to_string(), // exercises escaping
        system_sha256: "d".repeat(64),
        system_bytes: 512,
        workload_sha256: "e".repeat(64),
        workload_bytes: 1024,
        scratch_path: "/tmp/vdb".to_string(),
        scratch_template_sha256: "f".repeat(64),
        scratch_template_bytes: 2048,
        result_path: "/tmp/vdd".to_string(),
        result_template_sha256: "0".repeat(64),
        result_template_bytes: 4096,
        runtime_input_present: true,
        verity_root_hash: "1".repeat(64),
        ram_mib: 512,
        vcpus: 1,
        net_present: true,
        consumption: "mock".to_string(),
    }
}

fn sample_result() -> RunResultV3 {
    RunResultV3 {
        result_role: "vdd",
        result_template_sha256: "0".repeat(64),
        result_template_bytes: 4096,
        result: ResultDigest {
            result_sha256: "2".repeat(64),
            result_bytes: 4096,
            steps: vec!["stop_writers", "hash"],
        },
        console: ConsoleDigest {
            console_sha256: "3".repeat(64),
            console_bytes: 10,
            truncated: false,
            limit_bytes: 16 * 1024 * 1024,
        },
        runtime_input_present: true,
        runtime_input_max_bytes: 1 << 30,
        runtime_input_commitment_claim: None,
        vmm_code: 0,
        run_ms: 7,
        backend_abi: 3,
    }
}

#[test]
fn receipt_json_parses() {
    let j = parse(&sample_receipt().to_json());
    assert_eq!(get(&j, "schema"), &Json::Str("dsmack-backend-v3/launch-receipt/1".into()));
    // honesty object is present AND closed (the F06 defect was an unterminated
    // outer object the old substring assertions could not catch).
    let honesty = get(&j, "honesty");
    assert!(matches!(honesty, Json::Obj(_)));
    assert_eq!(get(&j, "runtime_input_present"), &Json::Bool(true));
    // escaping round-trips exactly
    assert_eq!(get(&j, "cmdline"), &Json::Str("console=hvc0 panic=-1 \"q\"\\z".into()));
}

#[test]
fn result_json_parses() {
    let j = parse(&sample_result().to_json());
    assert_eq!(get(get(&j, "lifecycle"), "run_ms"), &Json::Num(7.0));
}

// F06 — C/Rust struct layout agreement. Under LP64 (Apple arm64 AND the x86_64
// Linux host this test runs on) the #[repr(C)] structs must match the header's
// expected sizes/alignments: launch-spec 104/8, disk-set 56/8.
#[test]
fn repr_c_layout_matches_header_expectations() {
    assert_eq!(std::mem::size_of::<DsmackCtlLaunchSpecV3>(), 104);
    assert_eq!(std::mem::align_of::<DsmackCtlLaunchSpecV3>(), 8);
    assert_eq!(std::mem::size_of::<DsmackCtlDiskSetV3>(), 56);
    assert_eq!(std::mem::align_of::<DsmackCtlDiskSetV3>(), 8);
}
