// CanonicalJSON.swift — deterministic JSON emission + strict scalar rules
// for the v2 launcher core (mac-app-join lane, 2026-10-21).
//
// The v2 launch binds identity by DIGESTS OF EXACT BYTES (spec_sha256 over
// the canonical launch-spec document, admission over exact manifest/policy
// bytes, AND the contract10 receipt-evidence digest), so emission must be
// byte-deterministic AND byte-exact with the contract10 canonical profile
// (lib/dsmack_compose_contract/canonical.py == Python json.dumps with
// sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).
// Rules: keys sorted by Unicode code point; compact separators; UTF-8
// passthrough for non-ASCII; RFC 8259 minimal string escaping — only '"',
// '\\' and the control characters U+0000..U+001F are escaped, with the SHORT
// escapes \b \t \n \f \r where defined and \u00XX (lowercase) for every other
// C0 control char; DEL (0x7f) is NOT escaped (it is >= 0x20). (SERIALIZATION
// PARITY REPAIR, mac-source-integration-early lane: the prior escaper
// emitted \u0008 \u0009 \u000a \u000c \u000d instead of the short escapes
// \b \t \n \f \r, and also escaped DEL (0x7f) as \u007f — both diverge
// from contract10 canonical for any value carrying those bytes, only
// agreeing by accident because the frozen evidence body is control-free
// ASCII. Aligned here so the Swift evidence digest stays byte-exact with
// execution_evidence_digest() across the full value domain.)
// Values are restricted to String / Int / Bool / NSNull / [Any] /
// [String: Any]; Double is refused (it would not serialize deterministically
// across platforms). NSNull IS accepted: the frozen receipt-evidence body
// carries explicit null members (contract10 canonical emits `null` identically).

import CryptoKit
import Foundation

/// Deterministic canonical JSON bytes for the restricted value domain.
/// Keys are sorted by Unicode code point (contract10 canonical profile); no
/// whitespace.
func canonicalJSONData(_ obj: Any) throws -> Data {
    var out = Data()
    try appendCanonical(obj, to: &out)
    return out
}

private func appendCanonical(_ obj: Any, to out: inout Data) throws {
    switch obj {
    case let s as String:
        appendJSONString(s, to: &out)
    case let n as Int:
        out.append(Data(String(n).utf8))
    case let b as Bool:
        out.append(Data((b ? "true" : "false").utf8))
    case is NSNull:
        // JSON null — accepted for the contract10 receipt-evidence body, whose
        // frozen preimage carries explicit null members (e.g. "attestation":
        // null, and the compose-runner-world fields this launcher does not
        // populate). The contract10 canonical profile (canonical.py) emits
        // null the same way; this keeps the Swift evidence digest byte-exact
        // with execution_evidence_digest(). (mac-runtime-seam-repair lane.)
        out.append(Data("null".utf8))
    case let a as [Any]:
        out.append(Data("[".utf8))
        for (i, v) in a.enumerated() {
            if i > 0 { out.append(Data(",".utf8)) }
            try appendCanonical(v, to: &out)
        }
        out.append(Data("]".utf8))
    case let d as [String: Any]:
        out.append(Data("{".utf8))
        for (i, k) in d.keys.sorted(by: { $0.unicodeScalars.lexicographicallyPrecedes($1.unicodeScalars) }).enumerated() {
            if i > 0 { out.append(Data(",".utf8)) }
            appendJSONString(k, to: &out)
            out.append(Data(":".utf8))
            try appendCanonical(d[k]!, to: &out)
        }
        out.append(Data("}".utf8))
    default:
        throw Fail("canonical JSON: unsupported value type \(type(of: obj)) (String/Int/Bool/array/dict only)")
    }
}

private func appendJSONString(_ s: String, to out: inout Data) {
    out.append(Data("\"".utf8))
    for c in s.unicodeScalars {
        switch c {
        case "\"": out.append(Data("\\\"".utf8))
        case "\\": out.append(Data("\\\\".utf8))
        // Short escapes where RFC 8259 / json.dumps(ensure_ascii=False) define
        // them; every OTHER C0 control char is \u00XX (lowercase). DEL (0x7f)
        // and all >= 0x20 pass through unescaped — byte-exact with contract10
        // canonical.py.
        case "\u{08}": out.append(Data("\\b".utf8))
        case "\u{09}": out.append(Data("\\t".utf8))
        case "\u{0a}": out.append(Data("\\n".utf8))
        case "\u{0c}": out.append(Data("\\f".utf8))
        case "\u{0d}": out.append(Data("\\r".utf8))
        case let c where c.value < 0x20:
            out.append(Data(String(format: "\\u%04x", c.value).utf8))
        default:
            out.append(Data(String(c).utf8))
        }
    }
    out.append(Data("\"".utf8))
}

/// Lowercase-hex sha256 syntax (64 chars) — the same rule as the backend
/// spec parser: uppercase is a refusal, never silently canonicalized.
func isHex64(_ s: String) -> Bool {
    s.count == 64 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
}

/// Printable-ASCII check (0x20..0x7e) with the byte length reported on
/// refusal — the same class of rule as the backend cmdline check.
func printableASCII(_ s: String, maxBytes: Int) -> Bool {
    let b = Data(s.utf8)
    return b.count <= maxBytes && b.allSatisfy { (0x20...0x7e).contains($0) }
}

/// Strict JSON integer: JSONSerialization delivers NSNumber; a Bool also
/// bridges to Int, so the objectCType is checked — booleans ("c"/"B") and
/// floating values ("d"/"f") are refused rather than coerced. This is the
/// Swift side of the Python mirror's `isinstance(x, bool)` refusals.
func strictJSONInt(_ v: Any, _ what: String) throws -> Int {
    guard let n = v as? NSNumber else { throw Fail("\(what): integer required") }
    let t = String(cString: n.objCType)
    switch t {
    case "q", "l", "i", "s", "Q", "I", "L", "S":
        return n.intValue
    default:
        throw Fail("\(what): integer required (got objCType \"\(t)\")")
    }
}

/// Strict JSON boolean (same objectCType discipline, inverted).
func strictJSONBool(_ v: Any, _ what: String) throws -> Bool {
    guard let n = v as? NSNumber else { throw Fail("\(what): boolean required") }
    let t = String(cString: n.objCType)
    guard t == "c" || t == "B" else { throw Fail("\(what): boolean required (got objCType \"\(t)\")") }
    return n.boolValue
}

/// Exact-key-set check for a parsed JSON object (fail-closed: unknown keys
/// refuse — no silent reinterpretation, ledger 4.2).
func requireExactKeys(_ obj: Any, _ expected: Set<String>, _ what: String) throws -> [String: Any] {
    guard let d = obj as? [String: Any] else { throw Fail("\(what): must be a JSON object") }
    let keys = Set(d.keys)
    guard keys == expected else {
        throw Fail("\(what): keys must be exactly \(expected.sorted()), got \(keys.sorted())")
    }
    return d
}

/// Non-empty-string check used across every parsed document.
func requireNonEmptyString(_ d: [String: Any], _ k: String, _ what: String) throws -> String {
    guard let s = d[k] as? String, !s.isEmpty else { throw Fail("\(what).\(k): non-empty string required") }
    return s
}
