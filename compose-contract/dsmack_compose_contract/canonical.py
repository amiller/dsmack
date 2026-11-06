"""Strict JSON parsing, canonical serialization and hashing (v3).

Identity rule (F11): manifest identity is ALWAYS the SHA256 of the exact
submitted UTF-8 bytes. Canonical bytes exist for comparisons, commitments and
evidence digests -- never as a substitute for exact-byte identity.

Canonical profile (complete, portable, frozen; astra C07):
  - object keys sorted lexicographically by Unicode code point, recursively
  - compact separators (","  ":"), no whitespace
  - UTF-8 output, non-ASCII characters emitted directly (no \\uXXXX escaping
    for printable characters), no Unicode normalization forms applied
  - strings use RFC 8259 minimal escaping: only '"', '\\' and the control
    characters U+0000..U+001F are escaped. Short escapes \\b \\f \\n \\r \\t
    are used where defined; every other control character is \\u00XX with
    lowercase hex. (This is exactly Python json.dumps(ensure_ascii=False)
    behavior; frozen by examples/hash-vectors.json vectors.)
  - numbers: INTEGERS ONLY, bounded to the signed 64-bit range
    (-(2**63) <= n <= 2**63-1) so independent implementations with fixed
    width can reproduce every digest. Floats, exponents, NaN, Infinity are
    rejected at parse time; one serialization per value.
  - duplicate object keys rejected at parse time
  - strings containing Unicode surrogate code points (U+D800..U+DFFF),
    including those arriving via \\uD800-style escapes, are rejected at
    parse time: they are not valid Unicode scalar values and cannot be
    encoded as UTF-8 (astra C07: they previously survived parsing and later
    raised uncaught UnicodeEncodeError).
  - ONE strict parser serves validation, hashing and the hash CLI -- there
    is no looser secondary parser.

Restricted commitment encoding: commitments hash arrays of strings/ints and
canonically-keyed objects built ONLY from strings, canonical base64 text and
bounded ints, so the digest is reproducible in any language implementing the
profile above. Test vectors: examples/hash-vectors.json (frozen).
"""

import hashlib
import json
import math

from .errors import ContractError

#: Canonical profile integer bound (frozen): signed 64-bit.
MIN_INT = -(2**63)
MAX_INT = 2**63 - 1

#: Hard cap on raw document size accepted by load_json_bytes (astra C05:
#: bounded raw-envelope parsing). Callers may pass a smaller limit.
MAX_DOCUMENT_BYTES = 268435456  # 256 MiB absolute


def canonicalize(obj):
    """Return canonical JSON text for a JSON-compatible object."""
    _assert_canonicalizable(obj)
    return _dumps(obj)


def _assert_canonicalizable(obj):
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise ContractError("floats are not permitted in canonical form (integers only)")
    if isinstance(obj, int):
        if not (MIN_INT <= obj <= MAX_INT):
            raise ContractError("integer out of the frozen signed 64-bit canonical range")
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ContractError("object keys must be strings")
            _assert_canonicalizable(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _assert_canonicalizable(value)
    elif not isinstance(obj, str) and obj is not None:
        raise ContractError("not JSON-serializable: %s" % type(obj).__name__)


def _dumps(obj):
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as exc:
        raise ContractError("value is not serializable in canonical form") from exc
    except TypeError as exc:
        raise ContractError("not JSON-serializable: %s" % exc) from exc


def canonical_bytes(obj):
    _assert_canonicalizable(obj)
    return _dumps(obj).encode("utf-8")


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_obj(obj):
    """SHA256 hex over the canonical serialization of obj."""
    return sha256_hex(canonical_bytes(obj))


def exact_and_canonical_sha256(raw_bytes, what="input", max_bytes=MAX_DOCUMENT_BYTES):
    """Given exact file bytes, return (exact_sha256, canonical_sha256).

    Uses the SAME strict parser as every validator (duplicate keys, floats,
    surrogates, NaN/Infinity, int range rejected) -- there is no looser
    secondary parser (F11).
    """
    exact = sha256_hex(raw_bytes)
    obj = load_json_bytes(raw_bytes, what, max_bytes=max_bytes)
    return exact, sha256_obj(obj)


def _check_int(value, what):
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not (MIN_INT <= value <= MAX_INT):
        raise ContractError("%s contains an integer outside the frozen signed 64-bit range" % what)


def _no_nan(obj, what):
    """Reject non-finite floats, out-of-range ints, non-str keys and lone
    surrogates anywhere in a decoded structure."""
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        raise ContractError("%s: NaN/Infinity are not permitted" % what)
    _check_int(obj, what)
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise ContractError(
                "%s contains a string that is not a valid Unicode scalar sequence "
                "(surrogate code points are rejected)" % what
            ) from None
        return obj
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ContractError("%s: object keys must be strings" % what)
            _no_nan(key, what)
            _no_nan(value, what)
    elif isinstance(obj, list):
        for value in obj:
            _no_nan(value, what)
    return obj


def _reject_float(_text, what):
    # Value-free diagnostic (C08): the offending numeric token is NOT echoed.
    raise ContractError(
        "%s: a non-integer number is not permitted (canonical profile is integers-only)" % what
    )


def _parse_int(text, what):
    """Bounded integer-token conversion (E07): the frozen canonical range is
    signed 64-bit, so any token longer than 20 characters (sign + 19 digits)
    can never be in range. Oversized tokens are a fixed contract error, never
    an interpreter ValueError from an unbounded int() conversion."""
    if len(text) > 20:
        raise ContractError("%s contains an integer token beyond the bounded canonical range" % what)
    return int(text)


def _reject_constant(name):
    raise ContractError("%s constant is not permitted anywhere in this contract" % name)


def load_json_bytes(raw_bytes, what="document", max_bytes=MAX_DOCUMENT_BYTES):
    """Parse exact bytes into JSON under the contract's strict profile.

    Rejects: input above max_bytes (bounded parsing), invalid UTF-8,
    duplicate object keys, floats/NaN/Infinity, integers outside the frozen
    signed 64-bit range, and strings containing surrogate code points.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise ContractError("%s must be bytes" % what)
    if len(raw_bytes) > max_bytes:
        raise ContractError(
            "%s is %d bytes, exceeding the parse bound %d" % (what, len(raw_bytes), max_bytes)
        )
    try:
        text = bytes(raw_bytes).decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("%s is not valid UTF-8" % what) from None

    def _pairs(pairs):
        seen = {}
        for key, _value in pairs:
            if key in seen:
                # Value-free diagnostic (C08): the duplicated key text is not
                # echoed -- caller-controlled text never enters diagnostics.
                raise ContractError("%s has a duplicate object key (key text withheld)" % what)
            seen[key] = _value
        return seen

    try:
        obj = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=lambda _t: _reject_float(_t, what),
            parse_int=lambda _t: _parse_int(_t, what),
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        # json.JSONDecodeError messages can embed document context; replace
        # with a value-free positional diagnostic (C08).
        raise ContractError("%s is not valid JSON (at character offset %d)" % (what, exc.pos)) from None
    except RecursionError:
        # D05: excessive nesting is a bounded contract error, never an
        # interpreter traceback (the parse bound is a contract property).
        raise ContractError("%s nesting exceeds the parser bound" % what) from None
    try:
        return _no_nan(obj, what)
    except RecursionError:
        # E07: the _no_nan traversal is recursive too -- a deeply nested but
        # parser-survivable structure must fail as a bounded contract error,
        # never as an interpreter traceback.
        raise ContractError("%s nesting exceeds the parser bound" % what) from None
