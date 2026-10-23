"""dsmack run-result composition protocol — normative constants (v2).

io-contract-reference. This module is the SINGLE source of truth for every
domain string, schema identifier, exact key set and numeric bound in the
replacement SPEC; SPEC.md embeds these values and the test suite asserts
SPEC/code agreement. Frozen /4 domains are referenced, never redefined.
"""

# ---- frozen /4 domains (referenced; owned by contract10, UNCHANGED) ----
EVIDENCE_DOMAIN = "dsmack.receipt-evidence/4"
LAUNCH_ASSERTION_DOMAIN = "dsmack.appattest.assertion/4"

# ---- new additive domains (this protocol) ----
ENVELOPE_DOMAIN = "dsmack.run-result-envelope/1"
RESULT_ASSERTION_DOMAIN = "dsmack.appattest.run-result/1"
PAIR_DOMAIN = "dsmack.runresult-pair-evidence/1"

ENVELOPE_SCHEMA = "dsmack-general-launcher/run-result-envelope/1"
STATEMENT_SCHEMA = "dsmack-general-launcher/v2-run-statement/1"  # actual producer
REQUEST_SCHEMA = "dsmack.runresult-request/2"
ATTACHMENT_INDEX_SCHEMA = "dsmack.runresult-attachments/1"
REPORT_SCHEMA = "dsmack.runresult-report/3"
ENROLLMENT_SCHEMA = "dsmack.runresult-enrollment/1"
CHECKER_CONTEXT_SCHEMA = "dsmack.runresult-checker-context/2"
EXTRACTION_CONTRACT = "dsmack.safe-extract-result/1"
PRIVATE_TRANSPORT_CONTRACT = "dsmack.private-input-transport/1"

VERIFIER_ID = "dsmack-runresult-verifier"
VERIFIER_VERSION = "2"

# ---- pinned external identities ----
CORE_SHA256 = "13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5"

# ---- enrollment classes (R02: no fake enrollment flags) ----
ENROLLMENT_CLASS_PRODUCTION = "apple-appattest-production"
ENROLLMENT_CLASS_FIXTURE = "software-test-fixture-nonhardware"
ENROLLMENT_CLASSES = (ENROLLMENT_CLASS_PRODUCTION, ENROLLMENT_CLASS_FIXTURE)
EVIDENCE_CLASS_PRODUCTION = "apple-hardware-assertion"
EVIDENCE_CLASS_FIXTURE = "software-fixture-nonhardware"

# ---- exact key sets (unknown or missing key = refusal everywhere) ----
REQUEST_KEYS = frozenset({
    "runresult_request_version", "manifest_sha256", "receipt_selector",
    "challenge", "key_id_b64",
    "launch_statement_b64", "launch_assertion_b64", "launch_counter",
    "envelope_b64", "result_assertion_b64", "result_counter",
    "result_image_sha256", "result_image_bytes",
})
REQUEST_VERSION = 2

# attachment roles; exactly one of each required role per request
ATTACHMENT_ROLES_REQUIRED = ("manifest", "result_image", "enrollment")
ATTACHMENT_ROLES_OPTIONAL = ("runtime_envelope_private",)
ATTACHMENT_ENTRY_KEYS = frozenset({"role", "sha256", "bytes"})
# role runtime_envelope_private is EXCLUDED transport: its sha256 entry is
# OMITTED from the index (bytes bound only by frozen envelope validation);
# entry keys for it are {"role", "bytes"}.
ATTACHMENT_PRIVATE_ENTRY_KEYS = frozenset({"role", "bytes"})

ENVELOPE_KEYS = frozenset({
    "schema", "launch", "result_disk", "console", "runtime_input",
    "lifecycle", "status",
})
ENVELOPE_LAUNCH_KEYS = frozenset({
    "evidence_sha256", "manifest_sha256", "challenge", "key_id_b64", "counter",
})
ENVELOPE_RESULT_DISK_KEYS = frozenset({
    "role", "template_sha256", "template_bytes", "sha256", "bytes",
})
ENVELOPE_CONSOLE_KEYS = frozenset({"sha256", "bytes", "truncated", "limit_bytes"})
ENVELOPE_RUNTIME_INPUT_KEYS = frozenset({"present", "max_bytes", "commitment_claim"})
ENVELOPE_LIFECYCLE_KEYS = frozenset({"vmm_code", "run_ms", "backend_abi"})

# statement.json (actual V2Launch.swift producer shape).  AUTHENTICATED
# content is EXCLUSIVELY statement.assertion.receipt_evidence_body (R01);
# everything else is either a BOUND DUPLICATE (must equal a value recomputed
# from authenticated/retained bytes) or an explicitly UNAUTHENTICATED
# DIAGNOSTIC (never compared, never trusted, never quoted as evidence).
STATEMENT_KEYS = frozenset({
    "schema", "challenge", "key_id", "assertion", "identity", "consumed",
    "workload", "resources", "staging", "lifecycle", "output",
    "contract10_receipt_fragment", "honesty", "trace",
})
STATEMENT_ASSERTION_KEYS = frozenset({
    "assertion_domain", "evidence_domain", "manifest_sha256",
    "evidence_sha256", "client_data_sha256", "receipt_evidence_body",
})
EVIDENCE_BODY_KEYS = frozenset({
    "attestation", "base_vm", "base_vm_launch", "harness_sha256",
    "manifest_sha256", "observed", "outputs", "run_id",
    "runtime_inputs_commitment",
})
# Bound duplicates (R01).  Each entry: (statement path, recomputed source).
STATEMENT_BOUND_DUPLICATES = (
    ("assertion.manifest_sha256", "M = sha256(exact manifest attachment bytes)"),
    ("assertion.evidence_sha256", "L = sha256_obj([dsmack.receipt-evidence/4, receipt_evidence_body])"),
    ("assertion.assertion_domain", "literal dsmack.appattest.assertion/4"),
    ("assertion.evidence_domain", "literal dsmack.receipt-evidence/4"),
    ("assertion.client_data_sha256", "sha256(NUL-join(domain, M, L, challenge))"),
    ("challenge", "request.challenge"),
    ("key_id", "request.key_id_b64"),
    ("contract10_receipt_fragment.base_vm", "receipt_evidence_body.base_vm"),
    ("contract10_receipt_fragment.base_vm_launch", "receipt_evidence_body.base_vm_launch"),
    ("consumed", "receipt_evidence_body.observed"),
    ("identity.compose_manifest_sha256", "M"),
)
# Statement members that are DIAGNOSTICS: unauthenticated, uncompared.
STATEMENT_DIAGNOSTIC_KEYS = frozenset({
    "identity", "workload", "resources", "staging", "lifecycle", "output",
    "honesty", "trace",
})

# shared-fact comparison (R01): exact fields compared guest-receipt vs
# authenticated native receipt_evidence_body.  Guest observations stay
# independent; base_vm_launch.boot is NEVER compared or overwritten.
SHARED_BASE_VM_FIELDS = (
    "architecture", "cmdline", "initrd_sha256", "kernel_sha256", "memory_mb",
    "metadata_sha256", "os_image_hash", "rootfs_sha256", "vcpus",
    "verity_root_hash",
)
SHARED_ADMISSION_FIELDS = (
    "decision", "os_image_hash", "admission_sha256", "admission_version",
)

PAIR_EVIDENCE_KEYS = frozenset({
    "schema", "challenge", "key_id_b64", "enrollment_sha256",
    "enrollment_class", "launch_assertion_b64", "result_assertion_b64",
    "launch_counter", "result_counter",
    "launch_client_data_sha256", "result_client_data_sha256",
})

ENROLLMENT_KEYS = frozenset({
    "schema", "enrollment_class", "key_id_b64", "assertion_public_key",
    "app_id", "team_id", "environment", "apple_attestation_b64",
    "apple_receipt_b64", "apple_receipt_status", "provenance",
})
ENROLLMENT_PROVENANCE_KEYS = frozenset({
    "verified_by_core_sha256", "verified_at_unix_s", "attestation_challenge",
})
APPLE_RECEIPT_STATUS = "retained_not_validated"

REPORT_KEYS = frozenset({
    "runresult_report_version", "verifier", "verifier_context", "verified",
    "subject", "apple", "report_sig",
})
REPORT_VERSION = 2
REPORT_VERIFIER_KEYS = frozenset({"id", "version", "key_id"})
REPORT_CONTEXT_KEYS = frozenset({
    "core_sha256", "extractor_tool_sha256", "extraction_contract",
    "enrollment_sha256",
})
REPORT_SUBJECT_KEYS = frozenset({
    "manifest_sha256", "receipt_selector", "challenge", "key_id_b64",
    "launch_evidence_sha256", "envelope_sha256", "pair_evidence_sha256",
    "launch_counter", "result_counter",
    "result_image_sha256", "result_image_bytes",
    "console_sha256", "console_bytes",
    "receipt_path", "receipt_sha256", "receipt_evidence_sha256", "export_index_sha256",
    "receipt_environment", "receipt_status", "outputs_verified",
    "commitment_status", "evidence_class",
})
REPORT_APPLE_KEYS = frozenset({
    "assertion_counters_authenticated", "receipt_status", "environment",
    "verified_at_unix_s",
})
REPORT_SIG_KEYS = frozenset({"alg", "key_id", "sig_b64"})

CHECKER_CONTEXT_KEYS = frozenset({
    "schema", "verifier_id", "verifier_version", "report_verify_key_b64",
    "report_key_id", "core_sha256", "extractor_tool_sha256", "expected",
})
CHECKER_EXPECTED_KEYS = frozenset({
    "challenge", "manifest_sha256", "receipt_selector", "key_id_b64",
    "enrollment_class", "app_id", "team_id", "environment",
    # REF03: the relying party MUST externally pin the expected workload
    # outcome and VM environment; the checker enforces these against the
    # validated receipt so a different status/exit/environment cannot pass.
    "workload_status", "exit_code", "receipt_environment", "closure_context",
})

# REF03: the externally pinnable workload outcomes.
WORKLOAD_STATUSES = ("completed", "failed", "cancelled")

COMMITMENT_STATUSES = ("absent", "recorded-unchecked", "bound-to-validated-envelope")

# ---- numeric bounds (exact; R02/R04/R05/R06) ----
MAX_REQUEST_BYTES = 1048576            # one-line canonical request document
MAX_STATEMENT_B64 = 262144
MAX_ASSERTION_B64 = 65536
MAX_ENVELOPE_B64 = 65536
MAX_CHALLENGE_CHARS = 4096
MAX_KEY_ID_B64 = 60
MAX_SELECTOR_CHARS = 63                # manifest NAME_RE bound

# result/console (R06; exact numbers, no undefined slack)
MAX_CONSOLE_BYTES = 16777216           # console writer hard cap
CONSOLE_SLACK_BYTES = 0                # limiter truncates the final write;
                                       # final size <= MAX_CONSOLE_BYTES exactly
RESULT_TEMPLATE_BYTES_MAX = 1073741824
FINALIZE_DEADLINE_SECONDS = 600

# staged extraction (R04)
EXTRACT_MARKER_NAME = "EXPORT-COMPLETE"
EXTRACT_MARKER_BYTES = b"dsmack-export/1\n"
EXTRACT_MARKER_CAP = 64
EXTRACT_RECEIPT_CAP = 1048576          # fixed cap BEFORE receipt is parsed
EXTRACT_SUMMARY_CAP = 1048576
EXTRACT_FILE_COUNT_MAX = 256
EXTRACT_TOTAL_BYTES_MAX = 67108864
EXTRACT_WALL_SECONDS = 300
EXTRACT_SNAPSHOT_SECONDS = 120
EXTRACT_TOOL_TIMEOUT_SECONDS = 30
EXTRACT_TOOL_RLIMIT_AS = 536870912
EXTRACT_TOOL_RLIMIT_CPU = 30
EXTRACT_TOOL_STDOUT_CAP = 65536
EXTRACT_TOOL_STDERR_CAP = 65536
EXTRACT_SEGMENT_RE = r"^[A-Za-z0-9._-]{1,128}$"   # plus explicit '.'/'..' refusal
EXTRACT_DEPTH_MAX = 4

# private-input transport (R05)
PT_MAGIC_ENTRY_TYPES = ("0", "5")      # regular file, directory; nothing else
PT_ENTRY_COUNT_MAX = 64
PT_FILE_BYTES_MAX = 16777216
PT_TOTAL_BYTES_MAX = 67108864
PT_DEPTH_MAX = 4
PT_SEGMENT_RE = EXTRACT_SEGMENT_RE
PT_FILE_MODE = 0o600
PT_DIR_MODE = 0o700
PT_IMAGE_ALIGN = 512
PT_IMAGE_BYTES_MAX = 1073741824

# replay store (R03)
CHALLENGE_TTL_SECONDS_MAX = 86400
