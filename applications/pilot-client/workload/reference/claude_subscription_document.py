"""Strict claudeAiOauth subscription-credential document validator.

Profile `claude-subscription/1` (dsmack.runtime-input/4). Dependency-free:
shared by the adapter importer (adapter/claude_subscription_importer.py) and
the guest-root sentinel (sentinel/sentinel_oauth.py).

Accepted document — EXACTLY one JSON object of this shape (source: pinned
Claude Code 2.1.187 credential store; see ../research/
claude-2.1.187-subscription-auth-evidence.md):

    {
      "claudeAiOauth": {
        "accessToken":      <string, 1..8192 UTF-8 bytes, no NUL>,
        "refreshToken":     <string, 1..8192 UTF-8 bytes, no NUL>,
        "expiresAt":        <integer, 1..4102444800000 epoch-ms>,
        "scopes":           [<string>*, >=1, <=16, each ^[A-Za-z0-9:_.-]{1,128}$,
                             must include "user:inference"],
        "subscriptionType": <optional string, 1..256, printable, no NUL>,
        "rateLimitTier":    <optional string, 1..256, printable, no NUL>,
        "clientId":         <optional UUID string>
      }
    }

`accessToken` is required. `refreshToken` and `expiresAt` must either both
be present (refreshable subscription) or both be absent (inference-only
setup-token credential). Bare sk-ant-oat01 tokens are normalized to this
document by parse_credential_source; they have no refresh or expiry fields.
Everything else is rejected fail-closed with VALUE-FREE diagnostics: the
caller-controlled field text is withheld, no value is echoed, and no
secret-derived digest is ever computed on rejected input.

Configuration-injection classes (settings/hooks/MCP/slash-command/agent/
provider-URL/model/env overrides) are classified explicitly and rejected
whether they appear at the top level or nested — the profile carries a
credential and NOTHING else.
"""

import json
import re

PROFILE = "claude-subscription/1"
TOP_LEVEL_FIELDS = ("claudeAiOauth",)
REQUIRED_OAUTH_FIELDS = ("accessToken",)
OPTIONAL_OAUTH_FIELDS = ("refreshToken", "expiresAt", "scopes", "subscriptionType", "rateLimitTier", "clientId")
ACCEPTED_OAUTH_FIELDS = REQUIRED_OAUTH_FIELDS + OPTIONAL_OAUTH_FIELDS

MAX_FIELD_BYTES = 8192
MAX_DOCUMENT_BYTES = 65536
MAX_EXPIRES_AT_MS = 4102444800000  # 2100-01-01T00:00:00Z
INFERENCE_SCOPE = "user:inference"
MAX_SCOPES = 16
SCOPE_RE = re.compile(r"^[A-Za-z0-9:_.\-]{1,128}$")
CLIENT_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TIER_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,256}$")

# Field-name classes that indicate CONFIGURATION INJECTION attempts. Applied
# to LOWERCASE field names at ANY depth; matched text is never echoed.
INJECTION_MARKERS = (
    "base_url",
    "baseurl",
    "api_url",
    "apikeyurl",
    "apikeyhelper",
    "settings",
    "hooks",
    "mcp",
    "permissions",
    "permissionmode",
    "allowedtools",
    "model",
    "env",
    "config",
    "profile",
    "awsauth",
    "route",
    "proxy",
    "endpoint",
    "url",
    "tokenurl",
    "clientsecret",
)

# Error codes (same value-free diagnostic vocabulary as the api-key profile).
E_SOURCE = "explicit-source-unreadable"
E_CONFIG_INJECTION = "configuration-injection-rejected"
E_UNDECLARED = "undeclared-input-name"


class SubscriptionDocumentError(ValueError):
    """Value-free rejection. Never carries input values or secret-derived
    digests; field text is withheld."""

    def __init__(self, code, message):
        super().__init__("[%s] %s" % (code, message))
        self.code = code


def _classify_field_name(name):
    """Classify a caller-controlled field name WITHOUT echoing it."""
    lk = name.lower() if isinstance(name, str) else ""
    if any(m in lk for m in INJECTION_MARKERS):
        return E_CONFIG_INJECTION
    return E_UNDECLARED


def _check_string(value, what, cap, regex=None):
    if value is None:
        raise SubscriptionDocumentError(E_SOURCE, "%s must not be null" % what)
    if not isinstance(value, str):
        raise SubscriptionDocumentError(E_SOURCE, "%s must be a string" % what)
    n = len(value.encode("utf-8"))
    if n == 0:
        raise SubscriptionDocumentError(E_SOURCE, "%s is empty" % what)
    if n > cap:
        raise SubscriptionDocumentError(
            E_SOURCE, "%s is %d bytes, exceeding the %d-byte profile cap" % (what, n, cap)
        )
    if "\x00" in value:
        raise SubscriptionDocumentError(E_SOURCE, "%s contains NUL" % what)
    if regex is not None and not regex.match(value):
        raise SubscriptionDocumentError(E_SOURCE, "%s does not match the profile format" % what)
    return value


def validate_subscription_object(obj):
    """Validate an already-parsed claudeAiOauth object. Returns it unchanged
    (never a copy with altered values). Raises SubscriptionDocumentError
    (value-free) on any violation."""
    if not isinstance(obj, dict):
        raise SubscriptionDocumentError(E_SOURCE, "claudeAiOauth must be a JSON object")
    keys = set(obj)
    unknown = keys - set(ACCEPTED_OAUTH_FIELDS)
    for k in sorted(unknown, key=lambda x: str(x)):
        raise SubscriptionDocumentError(
            _classify_field_name(k),
            "claudeAiOauth carries a field outside the %s profile %s; rejected (field text withheld)"
            % (PROFILE, "matching the configuration-injection classes" if _classify_field_name(k) == E_CONFIG_INJECTION else ""),
        )
    missing = [f for f in REQUIRED_OAUTH_FIELDS if f not in keys]
    if missing:
        raise SubscriptionDocumentError(
            E_SOURCE,
            "claudeAiOauth is missing required profile field(s) (names withheld): %d missing"
            % len(missing),
        )
    _check_string(obj["accessToken"], "accessToken", MAX_FIELD_BYTES)
    if ("refreshToken" in keys) != ("expiresAt" in keys):
        raise SubscriptionDocumentError(E_SOURCE, "refreshToken and expiresAt must be supplied together")
    if "refreshToken" in keys:
        _check_string(obj["refreshToken"], "refreshToken", MAX_FIELD_BYTES)
        exp = obj["expiresAt"]
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise SubscriptionDocumentError(E_SOURCE, "expiresAt must be an integer (epoch milliseconds)")
        if exp <= 0 or exp > MAX_EXPIRES_AT_MS:
            raise SubscriptionDocumentError(E_SOURCE, "expiresAt is outside the accepted epoch-ms range")
    if "scopes" in keys:
        scopes = obj["scopes"]
        if not isinstance(scopes, list):
            raise SubscriptionDocumentError(E_SOURCE, "scopes must be an array of strings")
        if len(scopes) == 0:
            raise SubscriptionDocumentError(E_SOURCE, "scopes must not be empty when present")
        if len(scopes) > MAX_SCOPES:
            raise SubscriptionDocumentError(E_SOURCE, "scopes exceeds the %d-entry profile cap" % MAX_SCOPES)
        for s in scopes:
            _check_string(s, "scope entry", 128, regex=SCOPE_RE)
        if INFERENCE_SCOPE not in scopes:
            raise SubscriptionDocumentError(
                E_SOURCE, "scopes must include the inference scope for this profile"
            )
    if "subscriptionType" in keys:
        _check_string(obj["subscriptionType"], "subscriptionType", 256, regex=_TIER_RE)
    if "rateLimitTier" in keys:
        _check_string(obj["rateLimitTier"], "rateLimitTier", 256, regex=_TIER_RE)
    if "clientId" in keys:
        _check_string(obj["clientId"], "clientId", 64, regex=CLIENT_ID_RE)
    return obj


def parse_subscription_document(raw_bytes):
    """Parse + fully validate the credential document bytes. Returns the
    validated claudeAiOauth object. Every rejection is value-free."""
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise SubscriptionDocumentError(E_SOURCE, "credential document must be bytes")
    raw_bytes = bytes(raw_bytes)
    if len(raw_bytes) > MAX_DOCUMENT_BYTES:
        raise SubscriptionDocumentError(
            E_SOURCE,
            "credential document exceeds the %d-byte document bound; rejected" % MAX_DOCUMENT_BYTES,
        )
    try:
        doc = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError):
        raise SubscriptionDocumentError(
            E_SOURCE, "credential document is not a single valid JSON document"
        ) from None
    if not isinstance(doc, dict):
        raise SubscriptionDocumentError(E_SOURCE, "credential document must be a JSON object")
    keys = set(doc)
    unknown = keys - set(TOP_LEVEL_FIELDS)
    for k in sorted(unknown, key=lambda x: str(x)):
        raise SubscriptionDocumentError(
            _classify_field_name(k),
            "credential document carries a field outside the %s profile %s; rejected "
            "(field text withheld). The profile accepts exactly %s and no configuration."
            % (
                PROFILE,
                "matching the settings/hooks/MCP/provider-URL configuration-injection classes"
                if _classify_field_name(k) == E_CONFIG_INJECTION
                else "",
                list(TOP_LEVEL_FIELDS),
            ),
        )
    if not keys:
        raise SubscriptionDocumentError(
            E_SOURCE, "credential document is missing the required profile field (withheld)"
        )
    inner = doc["claudeAiOauth"]
    if not isinstance(inner, dict):
        raise SubscriptionDocumentError(E_SOURCE, "claudeAiOauth must be a JSON object")
    inner_unknown = set(inner) - set(ACCEPTED_OAUTH_FIELDS)
    for k in sorted(inner_unknown, key=lambda x: str(x)):
        raise SubscriptionDocumentError(
            _classify_field_name(k),
            "claudeAiOauth carries a field outside the %s profile %s; rejected (field text withheld)"
            % (
                PROFILE,
                "matching the configuration-injection classes"
                if _classify_field_name(k) == E_CONFIG_INJECTION
                else "",
            ),
        )
    return validate_subscription_object(inner)


def canonical_env_value(oauth_obj):
    """Serialize the validated credential to the broker-audience env string
    (canonical JSON of the object). The sentinel parses this exact string
    back with parse_subscription_document — one vocabulary everywhere."""
    return json.dumps({"claudeAiOauth": oauth_obj}, sort_keys=True, separators=(",", ":"))


def _unique(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise SubscriptionDocumentError(E_SOURCE, "duplicate credential member")
        result[key] = value
    return result


def parse_credential_source(raw_bytes):
    """Accept a credential document or a bare setup-token, with value-free errors."""
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) > MAX_DOCUMENT_BYTES:
        raise SubscriptionDocumentError(E_SOURCE, "credential source exceeds the byte bound")
    raw = bytes(raw_bytes).strip()
    if raw.startswith(b"sk-ant-oat01-"):
        if not re.fullmatch(rb"sk-ant-oat01-[A-Za-z0-9_-]+", raw):
            raise SubscriptionDocumentError(E_SOURCE, "invalid setup-token format")
        return validate_subscription_object({"accessToken": raw.decode("ascii"), "scopes": [INFERENCE_SCOPE]})
    return parse_subscription_document(raw)


def default_credential_path(private_inputs):
    """Prefer setup-token when installed; an invalid preferred token must fail."""
    token = private_inputs / "claude-oauth-token"
    return token if token.exists() else private_inputs / "claude-subscription.json"
