//! Generic native backend, control-profile ABI v3 — the stable GENERIC native
//! device/FD mechanisms for the dsmack general launcher.
//!
//! native-v3-backend lane, 2026-10-21. v3 is an ADDITIVE, EXPLICITLY VERSIONED
//! successor to the v2 backend (mac-compile-preflight/work/integrated/
//! apple-static/backend-v2): the owned-buffer verified boot (R1-R5), the
//! external admitted launch_spec, and the resource profile
//! are all preserved; v3 extends the device set and adds the output path the
//! output-continuity contract (astra-gate R06, device_roles) requires:
//!
//!   vda  measured RO system          (unchanged from v2 verify-on-open)
//!   vdb  fresh RW scratch            (now initialized from an admitted blank
//!                                      filesystem template — a distinct fresh
//!                                      inode, byte-copied, never a hardlink)
//!   vdc  measured RO public workload (unchanged from v2 verify-on-open)
//!   vdd  fresh RW result             (admitted blank template; the verified
//!                                      inode itself is retained and finalized
//!                                      with CHECKED storage flush/sync BEFORE
//!                                      destruction, then hashed through the
//!                                      retained descriptor — R06)
//!   vde  OPTIONAL unmeasured RO      (genuinely private: no content hash in
//!        private input                spec/receipt/trace/diagnostics)
//!
//! plus a single BOUNDED, ALLOWLISTED generic virtio-net option over a
//! caller-handed connected SOCK_STREAM fd (the far end is an external NAT
//! helper; see NATIVE-V3-NETWORK.md), and a run-result accessor returning the
//! envelope-shaped result/console/runtime_input/lifecycle digests.
//!
//! This crate is PROSPECTIVE source pending independent review. It compiles and
//! unit-tests on host Linux with a MOCK platform and the ACTUAL file/FD/storage
//! layers (no VM/HVF/network/credentials). The aarch64-macOS HVF consumption
//! and the libkrun block/net/builder changes are the `source-changes/`
//! proposals; this crate alone refuses to execute a guest.
//!
//! No Claude / marketplace / receipt-format / task policy lives here: the
//! backend never learns workload semantics. Every image/policy identity arrives
//! in the admitted launch_spec — zero compiled-in image/harness/task pins.

/// Vendored from src/arch/src/aarch64/layout.rs:63 (upstream aarch64 value).
pub mod arch {
    pub const CMDLINE_MAX_SIZE: usize = 2048;
}

pub mod consumption_v3;
pub mod ctl_capi_v3;
pub mod disks_v3;
pub mod finalize;
pub mod framing;
pub mod net;
pub mod owned_verified;
pub mod receipt_v3;
pub mod spec_v3;

pub use consumption_v3::{
    install_consumption_factory, install_mock_for_test, BuildRefusedV3, ConsumptionV3, GuestVmV3,
    LifecyclePhase, MockPlatform, MOCK_LABEL,
};
pub use disks_v3::{AdmittedTemplate, AttachedDiskV3, DiskError, DiskRole, PrivateInputError};
pub use finalize::{
    supervise_finalize, ConsoleDigest, ConsoleLimiter, FinalizeError, LimitedConsoleWriter,
    ResultDigest, ResultStorage, CONSOLE_SLACK_BYTES, FINALIZE_DEADLINE_SECONDS,
    MAX_CONSOLE_BYTES, RESULT_TEMPLATE_BYTES_MAX, SUPERVISE_POLL_MILLIS,
};
pub use framing::{
    read_frame, reject_aliased, validate_control_transport, write_frame, BoundedNetWorker,
    ControlError, FrameError, MAX_ETHERNET_FRAME_BYTES, NET_WORKER_SHUTDOWN_TIMEOUT,
};
pub use net::{NetError, NetTransport, GENERIC_NIC_MAC, GUEST_DNS, GUEST_GATEWAY, GUEST_STATIC_IP};
pub use owned_verified::{VerifiedBootError, VerifiedBootImages, VerifiedBootPins};
pub use receipt_v3::{LaunchReceiptV3, RunResultV3};
pub use spec_v3::{LaunchSpecV3, SpecError};
