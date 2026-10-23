//! R5 — evidence of what booted.
//!
//! boot-binding-spike DESIGN R5: the receipt records the digests of the
//! OWNED copies (what actually booted), the admission spec_sha256 (what was
//! admitted), the exact cmdline, the verity root from the spec, and the
//! resource profile. The verifier side (ledger 2.9/14.2) recomputes image
//! identity from the checksum manifest and checks BOTH app identity and
//! image identity — this receipt is the backend's half of that binding.
//!
//! Field set mirrors the mac-general-prep app-side receipts
//! (evidence/runs/*/receipt.json) so the SAME verifier can consume both.

use crate::disks::AttachedDisk;
use crate::owned_verified::VerifiedBootImages;
use crate::spec::LaunchSpec;

/// Bound into EVERY receipt verbatim (never claimed established anywhere in
/// this backend). Carried forward from mac-general-prep ctl_boundary.HONESTY
/// with the TOCTOU entry updated to the v2 backend's actual state.
pub const HONESTY_BLOCK_JSON: &str = concat!(
    "\"honesty\":{",
    "\"host_root_confidentiality\":\"NOT established: App Attest / signing / boot do NOT prove ",
    "host-root cannot read guest memory or devices (ledger 13.4)\",",
    "\"backend_verified_boot_binding\":\"R1-R5 owned-copy binding closed against non-root ",
    "same-host attackers and verify-to-consume races; NOT a host-root integrity boundary ",
    "(root can rewrite VMM memory after load)\",",
    "\"disk_verify_on_open\":\"engineering narrowing only: the rootfs security binding is the ",
    "verified initrd's pinned in-guest dm-verity + panic=-1; host-side hashing is not the boundary\",",
    "\"mac_attestation\":\"performed by the app layer (marAttest) AFTER the run via the contract ",
    "attestation interface; this backend performs and claims none\",",
    "\"consumption_model\":\"see consumption label: memory-placement-model runs are engineering ",
    "evidence on Zed, never Mac/VM evidence\""
);

/// The receipt JSON schema label (kept as a constant so the cap arithmetic
/// below cannot drift from the emitted bytes).
pub const RECEIPT_SCHEMA: &str = "dsmack-backend-v2/launch-receipt/1";

/// Maximum scratch-path length the ABI accepts — declared in spec.rs beside
/// the cmdline limit (single definition); re-exported here because the
/// receipt cap arithmetic and the disk-set parse both bind to it.
pub use crate::spec::SCRATCH_PATH_MAX_BYTES;

/// Documented upper bound for a consumption label (the `Consumption::label`
/// strings this crate and the krun integration produce are far shorter).
/// A label over this bound still behaves safely: the receipt simply does
/// not fit the worst-case cap and `dsmack_ctl_join_receipt` refuses
/// (fail-closed evidence, never truncation).
pub const CONSUMPTION_LABEL_MAX_BYTES: usize = 128;

/// Computed worst-case receipt size, NUL included — the value
/// `dsmack_ctl_join_receipt_cap_min()` returns. fable-native-audit F4: the
/// fixed 2048 was not a worst case (a max-length cmdline alone overflows
/// it), so evidence collection could fail at runtime for a LEGAL spec.
/// Every term below is a hard bound the parser actually enforces:
///   - digests are 64 lowercase hex, escaped unchanged;
///   - the cmdline is printable ASCII (spec parse), worst escape 2x
///     (`"` or `\` doubles; control chars are refused at parse);
///   - the scratch path is bounded by SCRATCH_PATH_MAX_BYTES, worst escape
///     6x per byte (a control byte becomes \u00XX);
///   - keys and the honesty block are this file's own constants;
///   - numbers are u64 decimal (20 digits covers every emitted width);
///   - `observed_initrd_sha256` is counted as PRESENT (the superset).
pub fn worst_case_cap() -> usize {
    // Cost of one `"key":"value"` member: ',' + 2 quotes + ':' + 2 quotes.
    let member = |key: &str, value_escaped: usize| key.len() + value_escaped + 6;
    let hex64 = 64;
    let num = 20;
    1 // '{'
        + member("schema", RECEIPT_SCHEMA.len())
        + member("spec_sha256", hex64)
        + member("observed_kernel_sha256", hex64)
        + member("observed_initrd_sha256", hex64)
        + member("observed_cmdline_sha256", hex64)
        + member("cmdline", crate::spec::LaunchSpec::cmdline_max() * 2)
        + member("system_sha256", hex64)
        + member("system_bytes", num)
        + member("workload_sha256", hex64)
        + member("workload_bytes", num)
        + member("scratch_path", SCRATCH_PATH_MAX_BYTES * 6)
        + member("verity_root_hash", hex64)
        + member("ram_mib", num)
        + member("vcpus", num)
        + member("consumption", CONSUMPTION_LABEL_MAX_BYTES)
        + 1 // ',' before honesty
        + HONESTY_BLOCK_JSON.len()
        + 1 // '}'
        + 1 // trailing NUL
}

/// The observed-facts receipt of one successful `join_vm_new`.
#[derive(Clone, Debug)]
pub struct LaunchReceipt {
    pub spec_sha256: String,
    pub observed_kernel_sha256: String,
    pub observed_initrd_sha256: Option<String>,
    pub observed_cmdline_sha256: String,
    pub cmdline: String,
    pub system_sha256: String,
    pub system_bytes: u64,
    pub workload_sha256: String,
    pub workload_bytes: u64,
    pub scratch_path: String,
    pub verity_root_hash: String,
    pub ram_mib: u32,
    pub vcpus: u8,
    pub consumption: String,
}

impl LaunchReceipt {
    pub fn record(
        spec: &LaunchSpec,
        images: &VerifiedBootImages,
        disks: &[AttachedDisk],
        consumption: &str,
    ) -> Self {
        let get = |role: crate::disks::DiskRole| {
            disks
                .iter()
                .find(|d| d.role == role)
                .map(|d| (d.observed_sha256.clone(), d.bytes))
        };
        let (system_sha256, system_bytes) =
            get(crate::disks::DiskRole::System).unwrap_or_default();
        let (workload_sha256, workload_bytes) =
            get(crate::disks::DiskRole::Workload).unwrap_or_default();
        let scratch_path = disks
            .iter()
            .find(|d| d.role == crate::disks::DiskRole::Scratch)
            .map(|d| d.path.clone())
            .unwrap_or_default();
        LaunchReceipt {
            spec_sha256: spec.spec_sha256.clone(),
            observed_kernel_sha256: spec.kernel_sha256.clone(),
            observed_initrd_sha256: spec.initrd_sha256.clone(),
            observed_cmdline_sha256: spec.cmdline_sha256.clone(),
            cmdline: images.cmdline().to_string(),
            system_sha256,
            system_bytes,
            workload_sha256,
            workload_bytes,
            scratch_path,
            verity_root_hash: spec.verity_root_hash.clone(),
            ram_mib: spec.ram_mib,
            vcpus: spec.vcpus,
            consumption: consumption.to_string(),
        }
    }

    /// Deterministic one-line JSON (keys sorted; no timestamps — time is not
    /// a trust anchor here, ledger 10.1). The honesty block is appended
    /// verbatim from HONESTY_BLOCK_JSON. Every emitted string passes the
    /// full JSON escaper below, so the output is valid JSON for ANY consumed
    /// values the parser admits (fable-native-audit F4).
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\"schema\":");
        push_json_string(&mut s, RECEIPT_SCHEMA);
        kv(&mut s, "spec_sha256", &self.spec_sha256);
        kv(&mut s, "observed_kernel_sha256", &self.observed_kernel_sha256);
        if let Some(i) = &self.observed_initrd_sha256 {
            kv(&mut s, "observed_initrd_sha256", i);
        }
        kv(
            &mut s,
            "observed_cmdline_sha256",
            &self.observed_cmdline_sha256,
        );
        kv(&mut s, "cmdline", &self.cmdline);
        kv(&mut s, "system_sha256", &self.system_sha256);
        num(&mut s, "system_bytes", self.system_bytes);
        kv(&mut s, "workload_sha256", &self.workload_sha256);
        num(&mut s, "workload_bytes", self.workload_bytes);
        kv(&mut s, "scratch_path", &self.scratch_path);
        kv(&mut s, "verity_root_hash", &self.verity_root_hash);
        num(&mut s, "ram_mib", self.ram_mib as u64);
        num(&mut s, "vcpus", self.vcpus as u64);
        kv(&mut s, "consumption", &self.consumption);
        s.push(',');
        s.push_str(HONESTY_BLOCK_JSON);
        s.push('}');
        s
    }
}

fn kv(s: &mut String, k: &str, v: &str) {
    s.push(',');
    push_json_string(s, k);
    s.push(':');
    push_json_string(s, v);
}

/// Full JSON string escaper. fable-native-audit F4: the receipt is the R5
/// evidence surface, so it must stay VALID JSON for every value the parser
/// admits — control characters (C0 + DEL) are escaped as \u00XX in addition
/// to the quote and backslash rules; all other scalars are emitted raw as
/// UTF-8 (valid JSON). The worst-case arithmetic in `worst_case_cap` is
/// written against exactly these rules.
fn push_json_string(s: &mut String, v: &str) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                s.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn num(s: &mut String, k: &str, v: u64) {
    s.push_str(&format!(",\"{k}\":{v}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_block_is_verbatim_and_present() {
        assert!(HONESTY_BLOCK_JSON.contains("NOT established"));
        assert!(HONESTY_BLOCK_JSON.contains("ledger 13.4"));
        assert!(HONESTY_BLOCK_JSON.contains("panic=-1"));
    }

    /// fable-native-audit F4: the escaper must keep the receipt VALID JSON
    /// for values the parser admits — control characters escaped, quotes
    /// and backslashes doubled, everything else raw.
    #[test]
    fn json_escaper_covers_control_chars_quotes_and_backslashes() {
        let mut s = String::new();
        push_json_string(&mut s, "a\u{1}b\"c\\d\u{7f}e/f");
        assert_eq!(s, "\"a\\u0001b\\\"c\\\\d\\u007fe/f\"");
        // No raw control character survives inside the emitted literal.
        assert!(!s.chars().any(|c| (c as u32) < 0x20));
    }

    /// The computed cap must sit above the historical fixed 2048 (which a
    /// max cmdline alone overflowed — predetect P2) and inside a generous
    /// sanity ceiling; the exact domination of an emitted worst-case
    /// receipt is asserted at the FFI level (tests/f4_receipt_bounds.rs).
    #[test]
    fn worst_case_cap_is_above_historical_floor() {
        assert!(worst_case_cap() > 2048);
        assert!(worst_case_cap() < 16_384);
    }
}
