"""Minimal draft-07 subset enforcer used to keep schema and library in parity.

The contract deliberately has NO third-party jsonschema dependency, which is
how v1 drifted from its schemas (F03). This module implements exactly the
schema features this contract's schemas use, so tests can enforce parity BY
CONSTRUCTION: every shipped example and every generated violation must be
accepted or rejected identically by schema_check and by the semantic library
validators.

Supported keywords: type (incl. unions), const, enum, pattern, required,
properties, additionalProperties (bool or schema), propertyNames, items,
minItems, maxItems, uniqueItems, minLength, maxLength, minimum, maximum,
maxProperties, oneOf, $ref (local "#/definitions/..." only),
$id/$title/$description/$comment/$schema (ignored).

v3 fixes (astra C07):
  - keywords are applied for UNION types whenever the document matches that
    branch's type (v2 returned early and silently skipped pattern/
    minLength/... for (string|null) and (object|null) unions).
  - maxProperties is enforced.
  - const distinguishes booleans from integers (True no longer equals 1).
"""

import json
import re

from .errors import ContractError, SchemaViolation


def _type_ok(value, type_name):
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "null":
        return value is None
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ContractError("schema uses unsupported type %r" % type_name)


def _const_equal(doc, const):
    """Strict const equality: booleans never equal integers (C07)."""
    if isinstance(doc, bool) or isinstance(const, bool):
        return doc is const if isinstance(const, bool) else False
    return doc == const


class _Resolver:
    def __init__(self, root):
        self.root = root

    def resolve(self, ref):
        if not ref.startswith("#/"):
            raise ContractError("only local $ref is supported, got %r" % ref)
        node = self.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise ContractError("unresolvable $ref %r" % ref)
            node = node[part]
        return node


def check(doc, schema, root=None, path="doc"):
    """Validate doc against schema; raise SchemaViolation on first mismatch."""
    root = schema if root is None else root
    if "$ref" in schema:
        target = _Resolver(root).resolve(schema["$ref"])
        return check(doc, target, root=root, path=path)

    if "oneOf" in schema:
        passed = 0
        last = None
        for branch in schema["oneOf"]:
            try:
                check(doc, branch, root=root, path=path)
            except SchemaViolation as exc:
                last = exc
                continue
            passed += 1
        if passed != 1:
            raise SchemaViolation(
                "%s: matches %d oneOf branches (exactly 1 required)%s"
                % (path, passed, "" if last is None or passed else "; last branch: %s" % last)
            )
        return True

    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(doc, t) for t in types):
            raise SchemaViolation("%s: expected type %s, got %s" % (path, schema["type"], type(doc).__name__))

    # C07: remaining keywords apply whenever the doc's JSON type makes them
    # meaningful -- including under unions (v2 skipped them entirely).
    if "const" in schema and not _const_equal(doc, schema["const"]):
        raise SchemaViolation("%s: does not match the required const value" % path)

    if "enum" in schema:
        if not any(_const_equal(doc, option) for option in schema["enum"]):
            raise SchemaViolation("%s: value is not one of the enumerated options" % path)

    if isinstance(doc, str):
        if "pattern" in schema and not re.search(schema["pattern"], doc):
            raise SchemaViolation("%s: does not match pattern %r" % (path, schema["pattern"]))
        if "minLength" in schema and len(doc) < schema["minLength"]:
            raise SchemaViolation("%s: shorter than minLength %d" % (path, schema["minLength"]))
        if "maxLength" in schema and len(doc) > schema["maxLength"]:
            raise SchemaViolation("%s: longer than maxLength %d" % (path, schema["maxLength"]))

    if isinstance(doc, bool):
        pass
    elif isinstance(doc, (int, float)):
        if "minimum" in schema and doc < schema["minimum"]:
            raise SchemaViolation("%s: below minimum %r" % (path, schema["minimum"]))
        if "maximum" in schema and doc > schema["maximum"]:
            raise SchemaViolation("%s: above maximum %r" % (path, schema["maximum"]))

    if isinstance(doc, list):
        if "minItems" in schema and len(doc) < schema["minItems"]:
            raise SchemaViolation("%s: fewer than minItems %d" % (path, schema["minItems"]))
        if "maxItems" in schema and len(doc) > schema["maxItems"]:
            raise SchemaViolation("%s: more than maxItems %d" % (path, schema["maxItems"]))
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in doc]
            if len(encoded) != len(set(encoded)):
                raise SchemaViolation("%s: items are not unique" % path)
        if "items" in schema:
            for index, item in enumerate(doc):
                check(item, schema["items"], root=root, path="%s[%d]" % (path, index))

    if isinstance(doc, dict):
        if "maxProperties" in schema and len(doc) > schema["maxProperties"]:
            raise SchemaViolation("%s: more than maxProperties %d" % (path, schema["maxProperties"]))
        for key in schema.get("required", []):
            if key not in doc:
                raise SchemaViolation("%s: missing required key %r" % (path, key))
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in doc.items():
            if key in properties:
                check(value, properties[key], root=root, path="%s.%s" % (path, key))
            elif additional is False:
                # E08: caller-controlled key text is withheld (value-free
                # diagnostic parity with the semantic validators).
                raise SchemaViolation("%s: unsupported key rejected (key text withheld)" % path)
            elif isinstance(additional, dict):
                # R07: the key text is caller-controlled and must never
                # construct a diagnostic path; a fixed segment is used.
                check(value, additional, root=root, path="%s.<additional-key>" % path)
        if "propertyNames" in schema:
            for key in doc:
                check(key, schema["propertyNames"], root=root, path="%s.<key>" % path)
    return True


def validate(doc, schema):
    """Public entry: validate doc, raising SchemaViolation on first mismatch."""
    try:
        check(doc, schema)
    except SchemaViolation as exc:
        raise SchemaViolation(str(exc)) from exc
    return True
