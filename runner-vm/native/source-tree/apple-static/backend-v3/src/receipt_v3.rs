//! R5 launch receipt + run-result output for ABI v3.
//!
//! The launch receipt mirrors v2's observed-facts receipt, extended with the
//! admitted template identities (vdb/vdd) and the vde presence flag. The
//! run-result carries the finalized result/console digests in the field shapes
//! the I/O reference envelope uses (protocol.ENVELOPE_RESULT_DISK_KEYS /
//! ENVELOPE_CONSOLE_KEYS / ENVELOPE_RUNTIME_INPUT_KEYS / ENVELOPE_LIFECYCLE_KEYS).
//!
//! CRITICAL privacy invariant: NOTHING about vde content ever appears here —
//! no sha256, no byte length. Only presence, the policy cap, and an optional
//! opaque commitment CLAIM (supplied by the caller, never derived from the
//! private bytes) are recorded. This is asserted by a dedicated test.

use crate::disks_v3::{AttachedDiskV3, DiskRole};
use crate::finalize::{ConsoleDigest, ResultDigest};
use crate::spec_v3::LaunchSpecV3;

pub const RECEIPT_SCHEMA: &str = "dsmack-backend-v3/launch-receipt/1";
pub const RESULT_SCHEMA: &str = "dsmack-backend-v3/run-result/1";

/// Honesty block, carried verbatim (same assumptions as v2 plus the v3
/// result/private invariants).
pub const HONESTY_BLOCK_JSON: &str = concat!(
    "\"honesty\":{",
    "\"host_root_confidentiality\":\"NOT established: signing/boot do NOT prove host-root cannot ",
    "read guest memory or devices; final hashes establish provenance only under the admitted ",
    "signed-process/backend/guest and trusted-host assumptions\",",
    "\"disk_verify_on_open\":\"engineering narrowing; the rootfs security binding is the verified ",
    "initrd dm-verity + panic=-1, not host-side hashing\",",
    "\"vde_unmeasured\":\"vde private input is genuinely UNMEASURED: no content digest or byte ",
    "length enters any evidence, identifier, inventory or diagnostic\",",
    "\"result_finalization\":\"result hash is the retained vdd inode after CHECKED storage flush/sync ",
    "before destruction; a Drop-time log is not success\""
);

#[derive(Clone, Debug)]
pub struct LaunchReceiptV3 {
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
    pub scratch_template_sha256: String,
    pub scratch_template_bytes: u64,
    pub result_path: String,
    pub result_template_sha256: String,
    pub result_template_bytes: u64,
    /// vde presence ONLY — never its content or size.
    pub runtime_input_present: bool,
    pub verity_root_hash: String,
    pub ram_mib: u32,
    pub vcpus: u8,
    pub net_present: bool,
    pub consumption: String,
}

impl LaunchReceiptV3 {
    pub fn record(
        spec: &LaunchSpecV3,
        disks: &[AttachedDiskV3],
        net_present: bool,
        consumption: &str,
    ) -> Self {
        let find = |role: DiskRole| disks.iter().find(|d| d.role == role);
        let (system_sha256, system_bytes) = find(DiskRole::System)
            .map(|d| (d.observed_sha256.clone().unwrap_or_default(), d.bytes))
            .unwrap_or_default();
        let (workload_sha256, workload_bytes) = find(DiskRole::Workload)
            .map(|d| (d.observed_sha256.clone().unwrap_or_default(), d.bytes))
            .unwrap_or_default();
        let scratch_path = find(DiskRole::Scratch).map(|d| d.path.clone()).unwrap_or_default();
        let result_path = find(DiskRole::Result).map(|d| d.path.clone()).unwrap_or_default();
        LaunchReceiptV3 {
            spec_sha256: spec.spec_sha256.clone(),
            observed_kernel_sha256: spec.kernel_sha256.clone(),
            observed_initrd_sha256: spec.initrd_sha256.clone(),
            observed_cmdline_sha256: spec.cmdline_sha256.clone(),
            cmdline: spec.cmdline.clone(),
            system_sha256,
            system_bytes,
            workload_sha256,
            workload_bytes,
            scratch_path,
            scratch_template_sha256: spec.scratch_template_sha256.clone(),
            scratch_template_bytes: spec.scratch_template_bytes,
            result_path,
            result_template_sha256: spec.result_template_sha256.clone(),
            result_template_bytes: spec.result_template_bytes,
            runtime_input_present: find(DiskRole::PrivateInput).is_some(),
            verity_root_hash: spec.verity_root_hash.clone(),
            ram_mib: spec.ram_mib,
            vcpus: spec.vcpus,
            net_present,
            consumption: consumption.to_string(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1536);
        s.push_str("{\"schema\":");
        push_json_string(&mut s, RECEIPT_SCHEMA);
        kv(&mut s, "spec_sha256", &self.spec_sha256);
        kv(&mut s, "observed_kernel_sha256", &self.observed_kernel_sha256);
        if let Some(i) = &self.observed_initrd_sha256 {
            kv(&mut s, "observed_initrd_sha256", i);
        }
        kv(&mut s, "observed_cmdline_sha256", &self.observed_cmdline_sha256);
        kv(&mut s, "cmdline", &self.cmdline);
        kv(&mut s, "system_sha256", &self.system_sha256);
        num(&mut s, "system_bytes", self.system_bytes);
        kv(&mut s, "workload_sha256", &self.workload_sha256);
        num(&mut s, "workload_bytes", self.workload_bytes);
        kv(&mut s, "scratch_path", &self.scratch_path);
        kv(&mut s, "scratch_template_sha256", &self.scratch_template_sha256);
        num(&mut s, "scratch_template_bytes", self.scratch_template_bytes);
        kv(&mut s, "result_path", &self.result_path);
        kv(&mut s, "result_template_sha256", &self.result_template_sha256);
        num(&mut s, "result_template_bytes", self.result_template_bytes);
        boolean(&mut s, "runtime_input_present", self.runtime_input_present);
        kv(&mut s, "verity_root_hash", &self.verity_root_hash);
        num(&mut s, "ram_mib", self.ram_mib as u64);
        num(&mut s, "vcpus", self.vcpus as u64);
        boolean(&mut s, "net_present", self.net_present);
        kv(&mut s, "consumption", &self.consumption);
        s.push(',');
        s.push_str(HONESTY_BLOCK_JSON);
        // F06: `HONESTY_BLOCK_JSON` opens the nested `"honesty":{…` object but
        // does NOT close it, so BOTH braces must be emitted here: the first
        // closes the honesty object, the second closes the outer receipt
        // object. Previously only one was pushed, leaving the receipt JSON
        // unterminated (unparseable). Covered by a strict-parse test.
        s.push_str("}}");
        s
    }
}

/// The finalized run-result: envelope-aligned result_disk / console /
/// runtime_input / lifecycle sections. `runtime_input` carries NO vde content.
#[derive(Clone, Debug)]
pub struct RunResultV3 {
    pub result_role: &'static str,
    pub result_template_sha256: String,
    pub result_template_bytes: u64,
    pub result: ResultDigest,
    pub console: ConsoleDigest,
    pub runtime_input_present: bool,
    pub runtime_input_max_bytes: u64,
    pub runtime_input_commitment_claim: Option<String>,
    pub vmm_code: i32,
    pub run_ms: u64,
    pub backend_abi: i32,
}

impl RunResultV3 {
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\"schema\":");
        push_json_string(&mut s, RESULT_SCHEMA);
        // result_disk (ENVELOPE_RESULT_DISK_KEYS)
        s.push_str(",\"result_disk\":{\"role\":");
        push_json_string(&mut s, self.result_role);
        kv(&mut s, "template_sha256", &self.result_template_sha256);
        num(&mut s, "template_bytes", self.result_template_bytes);
        kv(&mut s, "sha256", &self.result.result_sha256);
        num(&mut s, "bytes", self.result.result_bytes);
        s.push('}');
        // console (ENVELOPE_CONSOLE_KEYS)
        s.push_str(",\"console\":{\"sha256\":");
        push_json_string(&mut s, &self.console.console_sha256);
        num(&mut s, "bytes", self.console.console_bytes);
        boolean(&mut s, "truncated", self.console.truncated);
        num(&mut s, "limit_bytes", self.console.limit_bytes);
        s.push('}');
        // runtime_input (ENVELOPE_RUNTIME_INPUT_KEYS) — NO vde content/size/hash
        s.push_str(",\"runtime_input\":{\"present\":");
        s.push_str(if self.runtime_input_present { "true" } else { "false" });
        num(&mut s, "max_bytes", self.runtime_input_max_bytes);
        s.push_str(",\"commitment_claim\":");
        match &self.runtime_input_commitment_claim {
            Some(c) => push_json_string(&mut s, c),
            None => s.push_str("null"),
        }
        s.push('}');
        // lifecycle (ENVELOPE_LIFECYCLE_KEYS)
        s.push_str(",\"lifecycle\":{\"vmm_code\":");
        s.push_str(&self.vmm_code.to_string());
        num(&mut s, "run_ms", self.run_ms);
        num(&mut s, "backend_abi", self.backend_abi as u64);
        s.push('}');
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

fn num(s: &mut String, k: &str, v: u64) {
    s.push_str(&format!(",\"{k}\":{v}"));
}

fn boolean(s: &mut String, k: &str, v: bool) {
    s.push_str(&format!(",\"{k}\":{}", if v { "true" } else { "false" }));
}

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
