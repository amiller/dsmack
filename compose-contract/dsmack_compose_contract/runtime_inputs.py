"""Runtime-input envelope validation for dsmack.runtime-input/4 (contract4).

Runtime inputs are UNMEASURED caller data (env/files/stdin/user_config),
separate from the measured manifest. v4 repairs (contract3-review):

  D04 - _decode_b64_bounded enforces the DECODED length (the v3 pre-decode
        text bound was approximate: a one-byte slot accepted 'QUFB', which
        decodes to three bytes). Env values containing NUL are rejected
        (execve env cannot carry them). Omitted opaque user_config has an
        EXPLICIT delivery entry (materialize-empty). Delivery is keyed by
        target segment and delivery tests verify the actual bytes per
        destination.
  D05 - commitment scope null selection arrays are handled (a scope
        include=['stdin'] with env_names:null used to reach list(None));
        normalized scopes omit empty selection arrays so library and schema
        agree (schema keeps minItems:1 on selection arrays, which are now
        omitted rather than emitted empty).
  D06 - rejected-input diagnostics are VALUE-FREE: unknown envelope keys,
        undeclared env names and commitment selection entries are withheld;
        only names already admitted by the measured declaration (required
        names/slots from the manifest) may be echoed. Rejected requests
        never trigger commitment computation (C08, unchanged).

Commitments remain SCOPED and DOMAIN-SEPARATED: dsmack.task-commitment/3
(the default) refuses broker-audience values; dsmack.secret-commitment/3 is
the distinct explicit choice for secret-inclusive scope. Canonical base64
over decoded bytes; transport spelling never matters.
"""

import base64
import binascii

from .canonical import load_json_bytes, sha256_hex, sha256_obj
from .errors import MultiError, RuntimeInputError
from .manifest import (
    DEFAULT_USER_CONFIG_TARGET,
    ENV_NAME_RE,
    MAX_STREAM_INPUT_BYTES,
    SLOT_RE,
    _effective_limits,
    _is_reserved_env,
    validate_manifest_bytes,
)

#: Scoped, credential-excluding commitment (the DEFAULT and recommended form).
TASK_COMMITMENT_ALG = "dsmack.task-commitment/3"
#: Distinct EXPLICIT choice to commit secret-inclusive input values.
SECRET_COMMITMENT_ALG = "dsmack.secret-commitment/3"
COMMITMENT_ALGS = (TASK_COMMITMENT_ALG, SECRET_COMMITMENT_ALG)

#: Field groups selectable into a commitment scope.
COMMITMENT_INCLUDE_FIELDS = ("env", "files", "stdin", "user_config")

#: Per-value and total env caps (policy constants; mirrored in CONTRACT.json).
MAX_ENV_VALUE_BYTES = 1048576
MAX_ENV_TOTAL_BYTES = 1048576

#: Raw envelope parse bound: 16 MiB decoded stream cap x base64 expansion
#: (4/3) x small margin, so every legal envelope fits and illegal ones are
#: rejected before parsing (C05: bounded raw-envelope parsing).
MAX_ENVELOPE_BYTES = 33554432

ENVELOPE_REQUIRED_KEYS = {"runtime_input_version", "manifest_sha256"}
ENVELOPE_OPTIONAL_KEYS = {"env", "files", "stdin_b64", "user_config_b64", "commitments"}

MAX_DECODED_DEFAULT = MAX_ENVELOPE_BYTES


def _decode_b64_bounded(value, path, max_bytes, errors):
    """Decode base64 with a PRE-DECODE text bound AND a POST-DECODE byte
    bound (D04).

    The text bound keeps adversarial base64 from allocating beyond the
    declared caps; the decoded-length check closes the v3 gap where the
    approximate 4/3 expansion let 'QUFB' (three decoded bytes) through a
    one-byte cap. Returns decoded bytes or None (with an error appended).
    """
    if not isinstance(value, str):
        errors.append(RuntimeInputError("%s must be a base64 string" % path))
        return None
    max_b64_len = 4 * (max_bytes // 3) + 8
    if len(value) > max_b64_len:
        errors.append(
            RuntimeInputError(
                "%s base64 text is %d characters, exceeding the cap implied by a %d-byte limit"
                % (path, len(value), max_bytes)
            )
        )
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        errors.append(RuntimeInputError("%s is not valid standard base64" % path))
        return None
    if len(data) > max_bytes:
        # D04: the DECODED length is enforced for every input type.
        errors.append(
            RuntimeInputError(
                "%s decodes to %d bytes, exceeding the %d-byte cap" % (path, len(data), max_bytes)
            )
        )
        return None
    return data


def canonical_b64(value, path, errors):
    """Return the CANONICAL base64 spelling of decoded bytes (C09).

    The commitment covers decoded BYTES re-encoded with standard padded
    base64, so transport spelling never affects a commitment.
    """
    data = _decode_b64_bounded(value, path, MAX_SLOT_BYTES_FOR_COMMITMENT, errors)
    if data is None:
        return None
    return base64.b64encode(data).decode("ascii")


# Commitment payloads may cover up to any declared slot cap; the pre-decode
# bound here is the raw-parse bound (the envelope itself was already
# length-bounded before parsing).
MAX_SLOT_BYTES_FOR_COMMITMENT = MAX_ENVELOPE_BYTES


def validate_runtime_inputs_bytes(manifest_bytes, envelope_bytes):
    """Validate a runtime-input envelope (exact bytes) against manifest bytes."""
    envelope = load_json_bytes(envelope_bytes, "runtime-input envelope", max_bytes=MAX_ENVELOPE_BYTES)
    return validate_runtime_inputs(manifest_bytes, envelope)


def validate_runtime_inputs(manifest_bytes, envelope):
    """Validate a parsed envelope against exact manifest bytes.

    Returns a summary dict. Raises MultiError listing every violation
    (bounded). Diagnostics are value-free (D06).
    """
    errors = []
    if not isinstance(envelope, dict):
        raise MultiError([RuntimeInputError("envelope must be a JSON object")])

    found_keys = set(envelope)
    # D06: the offending key text is caller-controlled and withheld.
    for _key in found_keys - (ENVELOPE_REQUIRED_KEYS | ENVELOPE_OPTIONAL_KEYS):
        errors.append(
            RuntimeInputError(
                "envelope: unsupported key rejected (key text withheld); allowed keys are %s"
                % sorted(ENVELOPE_REQUIRED_KEYS | ENVELOPE_OPTIONAL_KEYS)
            )
        )
    for key in ENVELOPE_REQUIRED_KEYS - found_keys:
        errors.append(RuntimeInputError("envelope.%s is required" % key))
    if errors:
        raise MultiError(errors)

    if envelope["runtime_input_version"] != 4:
        errors.append(RuntimeInputError("envelope.runtime_input_version must be 4"))

    # E07: one consistent absent/null policy -- explicit null optional keys
    # are REJECTED (never silently treated as absent), matching the schema
    # (string/array types) and the manifest validator's explicit-null rule.
    for key in sorted(ENVELOPE_OPTIONAL_KEYS):
        if key in envelope and envelope[key] is None:
            errors.append(
                RuntimeInputError(
                    "envelope.%s must not be null; omit the key entirely when the input is absent "
                    "(explicit null is rejected)" % key
                )
            )

    manifest, _summary = validate_manifest_bytes(manifest_bytes)
    limits = _effective_limits(manifest)

    if envelope["manifest_sha256"] != sha256_hex(manifest_bytes):
        errors.append(
            RuntimeInputError("envelope.manifest_sha256 does not match the manifest bytes (exact-bytes hash)")
        )

    env_decl = manifest["runtime_inputs"]["env"]
    audience_by_name = {
        entry["name"]: entry["audience"]
        for entry in manifest["allowed_envs"]
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    permit_reserved = manifest.get("env_policy", {}).get("permit_reserved_envs", [])

    env = envelope.get("env", {})
    if not isinstance(env, dict):
        errors.append(RuntimeInputError("envelope.env must be an object"))
        env = {}
    if env and env_decl["mode"] != "inject":
        errors.append(RuntimeInputError("manifest declares runtime_inputs.env.mode 'none'; env input is forbidden"))
    provided_names = set()
    total_env_bytes = 0
    for name, value in sorted(env.items()):
        if not isinstance(name, str) or not ENV_NAME_RE.match(name):
            errors.append(RuntimeInputError("envelope.env has an invalid env name"))
            continue
        if name not in audience_by_name:
            # D06: undeclared caller-supplied names are withheld.
            errors.append(
                RuntimeInputError(
                    "envelope.env contains an undeclared name (name withheld); names must be declared in "
                    "manifest.allowed_envs"
                )
            )
            continue
        if audience_by_name[name] == "workload" and _is_reserved_env(name) and name not in permit_reserved:
            errors.append(RuntimeInputError("envelope.env name %s is contract-reserved and not permitted by this manifest" % name))
        if not isinstance(value, str):
            errors.append(RuntimeInputError("envelope.env[%s] value must be a string" % name))
            continue
        if "\x00" in value:
            # D04: values that cannot be delivered faithfully through the
            # env ABI (execve environment entries are NUL-terminated) are
            # rejected, never truncated or split. Value-free diagnostic.
            errors.append(
                RuntimeInputError(
                    "envelope.env[%s] contains an embedded NUL byte, which the env delivery ABI cannot "
                    "carry faithfully; delivery would corrupt the value" % name
                )
            )
            continue
        value_bytes = len(value.encode("utf-8"))
        if value_bytes > MAX_ENV_VALUE_BYTES:
            errors.append(
                RuntimeInputError(
                    "envelope.env[%s] is %d bytes, exceeding the per-value cap %d"
                    % (name, value_bytes, MAX_ENV_VALUE_BYTES)
                )
            )
        total_env_bytes += value_bytes
        provided_names.add(name)
    if total_env_bytes > MAX_ENV_TOTAL_BYTES:
        errors.append(
            RuntimeInputError("envelope.env totals %d bytes, exceeding the env cap %d" % (total_env_bytes, MAX_ENV_TOTAL_BYTES))
        )
    for name in manifest["required_envs"]:
        # Required names are MEASURED (manifest-declared): echoing them is
        # permitted metadata (D06 boundary: only measured names may be named).
        if name not in provided_names:
            errors.append(RuntimeInputError("envelope.env is missing required name %s" % name))

    slot_defs = {f["slot"]: f for f in manifest["allowed_files"]}
    files = envelope.get("files", [])
    if not isinstance(files, list):
        errors.append(RuntimeInputError("envelope.files must be an array"))
        files = []
    seen_slots = set()
    decoded_files = {}  # slot -> decoded bytes (validated only)
    input_total = total_env_bytes
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"slot", "content_base64"}:
            errors.append(RuntimeInputError("envelope.files[] entries must have exactly {slot, content_base64}"))
            continue
        slot = entry["slot"]
        if not isinstance(slot, str) or slot not in slot_defs:
            errors.append(
                RuntimeInputError(
                    "envelope.files slot is not a declared manifest slot; undeclared file targets are rejected"
                )
            )
            continue
        if slot in seen_slots:
            errors.append(RuntimeInputError("envelope.files has duplicate slot %s" % slot))
            continue
        seen_slots.add(slot)
        data = _decode_b64_bounded(entry["content_base64"], "envelope.files[%s].content_base64" % slot, slot_defs[slot]["max_bytes"], errors)
        if data is not None:
            decoded_files[slot] = data
            input_total += len(data)
    # required file slots must be present (slot names are measured).
    for entry in manifest["allowed_files"]:
        if entry.get("required") and entry["slot"] not in seen_slots:
            errors.append(RuntimeInputError("envelope.files is missing required slot %s" % entry["slot"]))

    stdin_b64 = envelope.get("stdin_b64")
    stdin_decl = manifest["runtime_inputs"]["stdin"]
    stdin_data = None
    if stdin_b64 is not None:
        if stdin_decl["mode"] != "pipe":
            errors.append(RuntimeInputError("manifest declares stdin mode 'none'; stdin input is forbidden"))
        else:
            stdin_data = _decode_b64_bounded(stdin_b64, "envelope.stdin_b64", MAX_STREAM_INPUT_BYTES, errors)
            if stdin_data is not None:
                if len(stdin_data) > stdin_decl["max_bytes"]:
                    errors.append(
                        RuntimeInputError(
                            "envelope.stdin_b64 is %d bytes, exceeding the manifest cap %d"
                            % (len(stdin_data), stdin_decl["max_bytes"])
                        )
                    )
                input_total += len(stdin_data)

    user_config_b64 = envelope.get("user_config_b64")
    uc_decl = manifest["runtime_inputs"]["user_config"]
    user_config_data = None
    if user_config_b64 is not None:
        if uc_decl["mode"] != "opaque-file":
            errors.append(RuntimeInputError("manifest declares user_config mode 'none'; user_config input is forbidden"))
        else:
            user_config_data = _decode_b64_bounded(user_config_b64, "envelope.user_config_b64", uc_decl["max_bytes"], errors)
            if user_config_data is not None:
                input_total += len(user_config_data)

    # Total workspace input cap (initial input bytes; growth is bounded at
    # runtime by the workspace quota, see compose-runner-interface.md).
    if input_total > limits["workspace_max_bytes"]:
        errors.append(
            RuntimeInputError(
                "envelope inputs total %d bytes, exceeding the manifest workspace cap %d"
                % (input_total, limits["workspace_max_bytes"])
            )
        )

    commitment = None
    commitments = envelope.get("commitments")
    if commitments is not None:
        valid_scope = _validate_commitments(commitments, envelope, manifest, audience_by_name, slot_defs, decoded_files, seen_slots, errors)
        # C08: compute ONLY when every scope/audience/input check passed. A
        # rejected request never triggers commitment computation, so no
        # recomputed (secret-derived) digest can exist to leak.
        if not errors and valid_scope is not None:
            commitment = {
                "alg": commitments["alg"],
                "scope": valid_scope,
                "inputs_sha256": commitments["inputs_sha256"],
            }
            expected = compute_commitment(envelope, manifest)
            if commitments["inputs_sha256"] != expected:
                # Value-free mismatch diagnostic (C08): the recomputed digest
                # is NEVER printed.
                errors.append(
                    RuntimeInputError(
                        "envelope.commitments.inputs_sha256 does not match the recomputed %s commitment "
                        "over the selected scope (recomputed digest withheld)" % (commitments["alg"],)
                    )
                )

    if errors:
        raise MultiError(errors)
    return {
        "manifest_sha256": envelope["manifest_sha256"],
        "env_names": sorted(provided_names),
        "broker_env_names": sorted(n for n in provided_names if audience_by_name.get(n) == "broker"),
        "file_slots": sorted(seen_slots),
        "stdin_bytes": None if stdin_data is None else len(stdin_data),
        "user_config_bytes": None if user_config_data is None else len(user_config_data),
        "input_total_bytes": input_total,
        "commitment": commitment,
    }


def _normalized_scope(scope):
    """Normalized receipt-visible scope (sorted unique string lists).

    D05 schema parity: empty selection arrays are OMITTED, not emitted as
    empty lists (the schemas require minItems:1 on selection arrays, which
    are present only when their field is selected). Selection fields always
    present in the pre-normalized shape collapse to their sorted unique
    form; empty ones disappear.
    """
    normalized = {"include": sorted(scope.get("include", []))}
    env_names = sorted(scope.get("env_names") or [])
    file_slots = sorted(scope.get("file_slots") or [])
    if env_names:
        normalized["env_names"] = env_names
    if file_slots:
        normalized["file_slots"] = file_slots
    return normalized


def validate_commitment_scope_shape(scope):
    """Shared scope shape validation (envelope + receipt paths).

    Returns (ok, include, env_names, file_slots). ok=False means the scope is
    malformed; callers append their own path-specific error.

    R06: ONE absent/empty policy across schemas and validators. When a field
    is NOT selected its array must be ABSENT -- an explicit null or an empty
    array is rejected (the schemas reject both: type array + minItems 1).
    Null/missing selection arrays are handled explicitly (D05: scope
    include=['stdin'] with env_names=null used to reach list(None) and
    crash).
    """
    if not isinstance(scope, dict) or set(scope) - {"include", "env_names", "file_slots"} or "include" not in scope:
        return False, None, None, None
    include = scope["include"]
    if (
        not isinstance(include, list)
        or not include
        or any(not isinstance(f, str) for f in include)
        or len(include) != len(set(include))
        or any(f not in COMMITMENT_INCLUDE_FIELDS for f in include)
    ):
        return False, None, None, None
    env_names = scope.get("env_names")
    file_slots = scope.get("file_slots")
    if "env" in include:
        if (
            not isinstance(env_names, list)
            or not env_names
            or any(not isinstance(n, str) or not ENV_NAME_RE.match(n) for n in env_names)
            or len(env_names) != len(set(env_names))
        ):
            return False, None, None, None
    else:
        # Not selected: must be ABSENT. Null and empty arrays are rejected
        # (schema parity: the property is type array with minItems 1).
        if "env_names" in scope:
            return False, None, None, None
        env_names = []
    if "files" in include:
        if (
            not isinstance(file_slots, list)
            or not file_slots
            or any(not isinstance(s, str) or not SLOT_RE.match(s) for s in file_slots)
            or len(file_slots) != len(set(file_slots))
        ):
            return False, None, None, None
    else:
        if "file_slots" in scope:
            return False, None, None, None
        file_slots = []
    return True, list(include), list(env_names), list(file_slots)


def _validate_commitments(commitments, envelope, manifest, audience_by_name, slot_defs, decoded_files, seen_slots, errors):
    """Full commitment validation; returns the normalized scope when valid.

    C08: this function performs EVERY check that must gate commitment
    computation; callers compute only when it returned a scope and no errors
    were recorded. Selection-entry diagnostics are value-free (D06).
    """
    if not isinstance(commitments, dict) or set(commitments) != {"alg", "scope", "inputs_sha256"}:
        errors.append(
            RuntimeInputError(
                "envelope.commitments must have exactly {alg, scope, inputs_sha256} "
                "(free-text notes are not permitted in commitments; F08)"
            )
        )
        return None
    alg = commitments["alg"]
    if alg not in COMMITMENT_ALGS:
        # Value-free diagnostic (C08): the supplied alg value is not echoed.
        errors.append(
            RuntimeInputError(
                "envelope.commitments.alg must be one of %s (scoped and domain-separated); a disallowed "
                "value was supplied" % (list(COMMITMENT_ALGS),)
            )
        )
        return None
    ok, include, env_names, file_slots = validate_commitment_scope_shape(commitments["scope"])
    if not ok:
        errors.append(
            RuntimeInputError(
                "envelope.commitments.scope must be {include} plus env_names when 'env' is included plus "
                "file_slots when 'files' is included (explicit selected scope; unique string lists)"
            )
        )
        return None
    if not isinstance(commitments["inputs_sha256"], str) or len(commitments["inputs_sha256"]) != 64:
        errors.append(RuntimeInputError("envelope.commitments.inputs_sha256 must be a 64-hex digest"))
        return None

    # env selection must reference PROVIDED inputs (not merely declared ones).
    provided_env = envelope.get("env") if isinstance(envelope.get("env"), dict) else {}
    for name in env_names:
        if name not in provided_env:
            errors.append(
                RuntimeInputError(
                    "envelope.commitments.scope selects an env name that is not present in envelope.env "
                    "(selection entry withheld)"
                )
            )
        elif audience_by_name.get(name) == "broker" and alg == TASK_COMMITMENT_ALG:
            errors.append(
                RuntimeInputError(
                    "envelope.commitments with alg %s must NOT include broker-audience (credential) env "
                    "%s; committing credentials requires the distinct explicit alg %s"
                    % (TASK_COMMITMENT_ALG, name, SECRET_COMMITMENT_ALG)
                )
            )
    # C09: file selection is per-slot and must reference PROVIDED slots.
    for slot in file_slots:
        if slot not in slot_defs:
            errors.append(
                RuntimeInputError(
                    "envelope.commitments.scope selects a file slot that is not a declared slot "
                    "(selection entry withheld)"
                )
            )
        elif slot not in seen_slots:
            errors.append(
                RuntimeInputError(
                    "envelope.commitments.scope selects a file slot that is not present in envelope.files "
                    "(selection entry withheld)"
                )
            )
        elif slot_defs[slot].get("audience") == "broker" and alg == TASK_COMMITMENT_ALG:
            errors.append(
                RuntimeInputError(
                    "envelope.commitments with alg %s must NOT include broker-audience (credential) file "
                    "slot %s; committing it requires the distinct explicit alg %s"
                    % (TASK_COMMITMENT_ALG, slot, SECRET_COMMITMENT_ALG)
                )
            )
    if errors:
        return None
    return _normalized_scope({"include": include, "env_names": env_names, "file_slots": file_slots})


def compute_commitment(envelope, manifest):
    """Recompute the scoped commitment digest for a VALIDATED envelope.

    Restricted portable encoding: the committed payload is a JSON array of
    [alg, manifest_sha256, scope, values] serialized in the contract's
    canonical form. `values` contains ONLY strings (canonical base64 for
    bytes), bounded ints and canonically-keyed objects, so any language
    implementing the canonical profile reproduces the digest. Fields selected
    by the scope are ALWAYS present (null when absent) so "selected but
    empty" is distinguishable from "not selected". The scope uses the
    normalized shape (empty selection arrays omitted; D05).

    Audience policy is ENFORCED HERE TOO (C08): the task algorithm refuses to
    hash broker-audience selected inputs even if a caller bypassed envelope
    validation.

    A commitment alone does NOT make execution deterministic or the inputs
    authentic: the runner/verifier must additionally bind this digest to the
    exact bytes executed (see CONTRACT.json semantics.commitments).
    """
    commitments = envelope.get("commitments") if isinstance(envelope.get("commitments"), dict) else {}
    alg = commitments.get("alg")
    if alg not in COMMITMENT_ALGS:
        raise RuntimeInputError("commitment alg is not a defined algorithm")
    ok, include, env_names, file_slots = validate_commitment_scope_shape(commitments.get("scope"))
    if not ok:
        raise RuntimeInputError("commitment scope is malformed")
    normalized_scope = _normalized_scope({"include": include, "env_names": env_names, "file_slots": file_slots})

    env_in = envelope.get("env") if isinstance(envelope.get("env"), dict) else {}
    files_in = envelope.get("files") if isinstance(envelope.get("files"), list) else []
    content_by_slot = {f.get("slot"): f.get("content_base64") for f in files_in if isinstance(f, dict)}

    slot_audiences = {}
    if isinstance(manifest, dict):
        slot_audiences = {
            entry["slot"]: entry.get("audience")
            for entry in manifest.get("allowed_files", [])
            if isinstance(entry, dict) and isinstance(entry.get("slot"), str)
        }

    values = {}
    if "env" in include:
        values["env"] = {
            name: env_in[name]
            for name in env_names
            if name in env_in and isinstance(env_in[name], str)
        }
        if alg == TASK_COMMITMENT_ALG:
            env_audiences = {
                entry.get("name"): entry.get("audience")
                for entry in manifest.get("allowed_envs", [])
                if isinstance(entry, dict) and isinstance(entry.get("name"), str)
            }
            selected_broker = [n for n in env_names if env_audiences.get(n) == "broker"]
            if selected_broker:
                raise RuntimeInputError(
                    "the task commitment refuses broker-audience (credential) env selection"
                )
    if "files" in include:
        # Selected slots only (C09); canonical base64 over decoded bytes; the
        # credential-excluding default never hashes broker-audience slots.
        committed = []
        for slot in file_slots:
            if slot not in content_by_slot or not isinstance(content_by_slot[slot], str):
                raise RuntimeInputError("commitment references a file slot that is not present in the envelope")
            if alg == TASK_COMMITMENT_ALG and slot_audiences.get(slot) == "broker":
                raise RuntimeInputError("the task commitment refuses broker-audience (credential) file slot selection")
            canonical = canonical_b64(content_by_slot[slot], "envelope.files[%s].content_base64" % slot, [])
            if canonical is None:
                raise RuntimeInputError("commitment references a file slot whose bytes are not valid standard base64")
            committed.append({"content_base64": canonical, "slot": slot})
        values["files"] = sorted(committed, key=lambda f: f["slot"])
    if "stdin" in include:
        values["stdin_b64"] = canonical_b64(envelope.get("stdin_b64"), "envelope.stdin_b64", [])
        if values["stdin_b64"] is None and envelope.get("stdin_b64") is not None:
            raise RuntimeInputError("commitment references stdin bytes that are not valid standard base64")
    if "user_config" in include:
        values["user_config_b64"] = canonical_b64(envelope.get("user_config_b64"), "envelope.user_config_b64", [])
        if values["user_config_b64"] is None and envelope.get("user_config_b64") is not None:
            raise RuntimeInputError("commitment references user_config bytes that are not valid standard base64")

    payload = [alg, envelope.get("manifest_sha256"), normalized_scope, values]
    return sha256_obj(payload)


def redact(manifest_bytes, envelope):
    """Return the redacted form: names and byte counts only, never values.

    The envelope is VALIDATED FIRST (against the manifest) so the output is
    constructed from a fixed allowlist over validated data. Caller-controlled
    free text and arbitrary caller objects are never copied. Invalid input
    raises ContractError -- no partial output is produced (F08).
    """
    summary = validate_runtime_inputs(manifest_bytes, envelope)
    manifest, _ = validate_manifest_bytes(manifest_bytes)
    out = {
        "runtime_input_version": 4,
        "manifest_sha256": summary["manifest_sha256"],
        "redaction": "names-and-sizes-only (validated first; values never included)",
    }
    audience_by_name = {
        entry["name"]: entry["audience"]
        for entry in manifest["allowed_envs"]
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    env = envelope.get("env") or {}
    if not isinstance(env, dict):
        env = {}
    out["env"] = {
        name: {
            "audience": audience_by_name.get(name),
            "redacted": True,
            "value_bytes": len(value.encode("utf-8")) if isinstance(value, str) else None,
        }
        for name, value in sorted(env.items())
        if isinstance(name, str)
    }
    slot_audience = {f["slot"]: f.get("audience") for f in manifest["allowed_files"]}
    redacted_files = []
    for entry in envelope.get("files") or []:
        slot = entry.get("slot") if isinstance(entry, dict) else None
        raw = entry.get("content_base64") if isinstance(entry, dict) else None
        try:
            nbytes = len(base64.b64decode(raw, validate=True)) if isinstance(raw, str) else None
        except (binascii.Error, ValueError):
            nbytes = None
        redacted_files.append({"audience": slot_audience.get(slot), "content_bytes": nbytes, "redacted": True, "slot": slot})
    out["files"] = redacted_files
    if isinstance(envelope.get("stdin_b64"), str):
        try:
            nbytes = len(base64.b64decode(envelope["stdin_b64"], validate=True))
        except (binascii.Error, ValueError):
            nbytes = None
        out["stdin"] = {"redacted": True, "content_bytes": nbytes}
    if isinstance(envelope.get("user_config_b64"), str):
        try:
            nbytes = len(base64.b64decode(envelope["user_config_b64"], validate=True))
        except (binascii.Error, ValueError):
            nbytes = None
        out["user_config"] = {"redacted": True, "content_bytes": nbytes}
    if summary["commitment"] is not None:
        out["commitments"] = {
            "alg": summary["commitment"]["alg"],
            "scope": summary["commitment"]["scope"],
            "inputs_sha256": summary["commitment"]["inputs_sha256"],
        }
    return out


def delivery_plan(manifest, envelope):
    """Deterministic delivery instructions for the runner (pure function).

    Maps validated runtime inputs to their ABI destinations. Broker-audience
    values/files are delivered ONLY to the guest-root credential broker,
    NEVER to the workload container (C03: broker files are not materialized
    under the workload workspace at all).

    D04 delivery semantics (each destination's bytes are unambiguous):
      - workload/broker files: `segment` is the TARGET segment, which is the
        single host source file name under <workspace>/inputs/ (mounts are
        keyed by this segment; target-segment collisions are rejected at
        manifest validation).
      - omitted OPTIONAL slots have an explicit entry with
        materialize_empty=true (uniform: every declared slot is always
        mounted; reading an omitted file yields an empty file).
      - user_config with mode opaque-file ALWAYS has an entry: delivered
        bytes or materialize_empty=true when the envelope omitted it.
    """
    if not isinstance(envelope, dict):
        raise RuntimeInputError("envelope must be a JSON object")
    plan = {
        "workload_env": {},
        "broker_env": {},
        "workload_files": [],
        "broker_files": [],
        "stdin_b64": envelope.get("stdin_b64"),
        "user_config": None,
    }
    env = envelope.get("env") or {}
    audience_by_name = {
        entry["name"]: entry["audience"]
        for entry in manifest["allowed_envs"]
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    for name, value in sorted(env.items()):
        if audience_by_name.get(name) == "broker":
            plan["broker_env"][name] = value
        else:
            plan["workload_env"][name] = value
    slot_defs = {f["slot"]: f for f in manifest["allowed_files"]}
    provided_slots = {
        entry["slot"]: entry["content_base64"]
        for entry in (envelope.get("files") or [])
        if isinstance(entry, dict) and isinstance(entry.get("slot"), str) and isinstance(entry.get("content_base64"), str)
    }
    for slot, slot_def in sorted(slot_defs.items()):
        if slot_def.get("audience") == "broker":
            if slot in provided_slots:
                plan["broker_files"].append(
                    {
                        "slot": slot,
                        "segment": _target_segment(slot_def["target"]),
                        "target": slot_def["target"],
                        "mode": slot_def["mode"],
                        "content_base64": provided_slots[slot],
                        "materialize_empty": False,
                    }
                )
            continue
        # workload-audience: every declared slot is delivered (empty when the
        # optional envelope omitted it).
        plan["workload_files"].append(
            {
                "slot": slot,
                "segment": _target_segment(slot_def["target"]),
                "target": slot_def["target"],
                "mode": slot_def["mode"],
                "content_base64": provided_slots.get(slot),
                "materialize_empty": slot not in provided_slots,
            }
        )
    uc_decl = manifest["runtime_inputs"]["user_config"]
    if uc_decl.get("mode") == "opaque-file":
        # D04: omitted opaque user_config is EXPLICIT (materialize-empty);
        # the v3 plan dropped the entry while lowering still mounted a file.
        plan["user_config"] = {
            "segment": _target_segment(uc_decl.get("target", DEFAULT_USER_CONFIG_TARGET)),
            "target": uc_decl.get("target", DEFAULT_USER_CONFIG_TARGET),
            "content_base64": envelope.get("user_config_b64"),
            "materialize_empty": "user_config_b64" not in envelope,
        }
    return plan


def _target_segment(target):
    """The single path segment under /workspace/inputs/ for a target."""
    prefix = "/workspace/inputs/"
    if isinstance(target, str) and target.startswith(prefix):
        return target[len(prefix):]
    return target
