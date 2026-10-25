#!/usr/bin/env python3
"""Per-run SUBSCRIPTION credential sentinel (profile `claude-subscription/1`).

PROPOSED DELTA lane: `claude-subscription-import`. Extends the frozen
per-run sentinel lifecycle (compose-runner-interface.md D07 +
claude-adapter-interface.md) with the OAuth-bearer credential class. The
frozen api-key behavior in sentinel.py is UNCHANGED; integration wires this
mode through `--auth-mode claude-subscription` (see
../../integration/claude-subscription-1.patch, pending independent review).

Differences from the api-key sentinel (everything else identical):

  credential  the run's broker-held claudeAiOauth object (accessToken,
              refreshToken, expiresAt [epoch-ms], optional scopes/
              subscriptionType/rateLimitTier/clientId), parsed with the SAME
              strict validator as the importer (memory-only; never logged,
              never workload-side, never written back to disk by default)
  mapping     identical: upstream_url = provider_route + <client path after
              '/<token>'>; only '/v1/<path>' accepted; token removed from
              the forwarded path
  upstream    the client credential headers (x-api-key, Authorization) are
              NEVER forwarded. Subscription mode injects
              `Authorization: Bearer <accessToken>` — per the pinned
              2.1.187 harness: OAuth rides Bearer, NOT x-api-key ("a header
              change, not a key swap") — and MERGES
              `anthropic-beta: oauth-2025-04-20` into any client-supplied
              anthropic-beta list (append-if-missing, the exact SDK
              provider behavior). No x-api-key is ever constructed: a
              subscription run never touches API-key credits.
  refresh     when the access token is expired or within the refresh window,
              the sentinel refreshes ONCE per demand toward the measured
              origin: POST {provider_route}/v1/oauth/token,
              Content-Type: application/json,
              anthropic-beta: oauth-2025-04-20,
              body {"grant_type":"refresh_token","refresh_token":...,
              "client_id":<credential clientId>}, over TLS-verified HTTPS
              (CA bundle + hostname; same verify-on rule). Response fields
              access_token / expires_in (seconds, → epoch-ms) / optional
              rotated refresh_token update the memory-only credential. A
              401 from upstream triggers at most ONE forced-refresh retry
              per request. Refresh failures are logged value-free
              (event class only) and surface as 502; the stale token is
              never retried unbounded.
  teardown    identical: credential (all fields) and token die with the
              instance.

TLS verification toward the provider is ALWAYS ON. Disabling TLS is not an
option. The CA bundle is an explicit argument (guest/image CA bundle in
production; TEST-ONLY CA in the labeled fake-provider test).

This process is ordinary runner/broker-side userland tooling: NOT the signed
app; it holds the credential only on behalf of the run (bound to run_id).
"""

import json
import threading
import time

try:  # patched layout: same package as the frozen sentinel
    from .sentinel import (
        FORBIDDEN_REQUEST_HEADERS,
        HOP_BY_HOP,
        MAX_RESPONSE_BYTES,
        REDACTED_TOKEN,
        ROUTE_UNKNOWN_TOKEN,
        ROUTE_V1_PROXY,
        UPSTREAM_CONNECT_TIMEOUT_S,
        UPSTREAM_TOTAL_TIMEOUT_S,
        RunSentinel,
        SentinelError,
        _load_credential,
        _redact_path,
    )
except ImportError:  # lane-test layout: claude-inputs checkout on sys.path
    from harness.sentinel.sentinel import (  # type: ignore
        FORBIDDEN_REQUEST_HEADERS,
        HOP_BY_HOP,
        MAX_RESPONSE_BYTES,
        REDACTED_TOKEN,
        ROUTE_UNKNOWN_TOKEN,
        ROUTE_V1_PROXY,
        UPSTREAM_CONNECT_TIMEOUT_S,
        UPSTREAM_TOTAL_TIMEOUT_S,
        RunSentinel,
        SentinelError,
        _load_credential,
        _redact_path,
    )

try:  # patched layout
    from ..adapter.claude_subscription_document import parse_subscription_document
except ImportError:  # lane-test layout
    from harness.adapter.claude_subscription_document import parse_subscription_document  # type: ignore

import http.client
import ssl

AUTH_MODE = "claude-subscription"
OAUTH_BETA = "oauth-2025-04-20"
TOKEN_PATH = "/v1/oauth/token"
REFRESH_WINDOW_SECONDS = 300  # refresh when < 5 min of validity remains
# S06: ABSOLUTE wall-clock ceiling on one refresh exchange (TCP+TLS connect +
# send + full response read). A watchdog closes the upstream socket at the
# deadline, so a trickling refresh response cannot hold the request slot:
# 25 s (refresh) < UPSTREAM_TOTAL_TIMEOUT_S (40 s) < MAX_REQUEST_SECONDS
# (50 s), keeping the whole-request ceiling intact even when a request pays
# for one refresh plus one upstream exchange is impossible by construction —
# the request watchdog still ends the request at 50 s regardless.
REFRESH_TOTAL_TIMEOUT_S = 25
REFRESH_CONNECT_TIMEOUT_S = 10   # idle-socket timeout (connect/read gaps)
MAX_REFRESH_RESPONSE_BYTES = 65536

# Fallback OAuth client id observed in the pinned 2.1.187 harness (prod
# CLIENT_ID constant). Used ONLY when the credential document omits
# clientId; the credential's own clientId takes precedence (that is what
# the pinned SDK sends).
FALLBACK_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"


class SubscriptionCredential:
    """Memory-only holder of the parsed claudeAiOauth credential with lazy
    TLS-verified refresh. No attribute is ever logged or stringified into
    diagnostics; error paths carry event classes only."""

    def __init__(self, oauth, provider_route, ca_bundle, log=lambda _msg: None):
        self._oauth = oauth  # validated dict (strict parser output)
        self._provider_route = provider_route
        self._ca_bundle = ca_bundle
        self._lock = threading.Lock()
        self._log = log
        self.refresh_count = 0
        self.last_refresh_error = None  # event class string, value-free

    # -- views ----------------------------------------------------------

    @property
    def access_token(self):
        with self._lock:
            return self._oauth["accessToken"]

    @property
    def expires_at_ms(self):
        with self._lock:
            return self._oauth["expiresAt"]

    def needs_refresh(self, now_ms=None, window_seconds=REFRESH_WINDOW_SECONDS):
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        return self.expires_at_ms <= now_ms + window_seconds * 1000

    # -- refresh --------------------------------------------------------

    def _parse_origin(self):
        # partition("://") => (scheme, "://", origin). The CONNECT host is the
        # origin (after "://"), never the scheme — same derivation as the
        # frozen sentinel's upstream_host.
        _scheme, _, route_origin = self._provider_route.partition("://")
        if not route_origin or "/" in route_origin:
            raise SentinelError("provider_route must be scheme://origin")
        return route_origin

    def refresh(self):
        """One documented-protocol refresh toward the measured origin over
        TLS-verified HTTPS. Raises SentinelError (value-free) on failure.
        On success replaces accessToken/expiresAt and (if the provider
        rotated it) refreshToken, in memory only."""
        if self._provider_route is None:
            raise SentinelError("files-only sentinel performs no refresh")
        with self._lock:
            refresh_token = self._oauth["refreshToken"]
            client_id = self._oauth.get("clientId") or FALLBACK_CLIENT_ID
        origin = self._parse_origin()
        body = json.dumps(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "anthropic-beta": OAUTH_BETA,
            "User-Agent": "dsmack-sentinel/1 (userOAuthProvider protocol)",
        }
        conn = http.client.HTTPSConnection(
            origin,
            timeout=REFRESH_CONNECT_TIMEOUT_S,
            context=ssl.create_default_context(cafile=self._ca_bundle),
        )
        # S06: one ABSOLUTE deadline over the whole refresh exchange. The
        # watchdog closes the socket at the deadline, which terminates a
        # blocked connect/send/read (the blocked call raises); the chunked
        # read below additionally checks the same deadline between chunks so
        # a trickling-but-never-idle response is also cut. The timeout above
        # bounds only idle gaps and does NOT bound the total.
        deadline = time.monotonic() + REFRESH_TOTAL_TIMEOUT_S
        watchdog = threading.Timer(REFRESH_TOTAL_TIMEOUT_S, conn.close)
        watchdog.daemon = True
        watchdog.start()
        try:
            try:
                conn.request("POST", TOKEN_PATH, body=body, headers=headers)
                resp = conn.getresponse()
                chunks = []
                total = 0
                while True:
                    if time.monotonic() > deadline:
                        self.last_refresh_error = "refresh-deadline-exceeded"
                        raise SentinelError("credential refresh exceeded the absolute deadline")
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_REFRESH_RESPONSE_BYTES:
                        self.last_refresh_error = "refresh-response-too-large"
                        raise SentinelError("credential refresh response exceeded the byte bound")
                    chunks.append(chunk)
                payload = b"".join(chunks)
            except (OSError, ssl.SSLError):
                # The watchdog (or network) terminated the exchange; value-free.
                self.last_refresh_error = self.last_refresh_error or "refresh-terminated"
                raise SentinelError("credential refresh terminated (event %s)" % self.last_refresh_error) from None
            if resp.status != 200:
                self.last_refresh_error = "refresh-http-%d" % resp.status
                raise SentinelError("credential refresh refused (event %s)" % self.last_refresh_error)
            try:
                data = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise SentinelError("credential refresh returned a malformed document") from None
            access = data.get("access_token")
            expires_in = data.get("expires_in")
            rotated = data.get("refresh_token")
            if not isinstance(access, str) or not access:
                raise SentinelError("credential refresh response lacks an access token")
            if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)) or expires_in <= 0:
                raise SentinelError("credential refresh response lacks a validity window")
            with self._lock:
                self._oauth = dict(self._oauth)
                self._oauth["accessToken"] = access
                self._oauth["expiresAt"] = int(time.time() * 1000 + float(expires_in) * 1000)
                if isinstance(rotated, str) and rotated:
                    self._oauth["refreshToken"] = rotated
                self.refresh_count += 1
            self._log("credential refreshed (event ok, count %d)" % self.refresh_count)
        finally:
            watchdog.cancel()
            conn.close()

    def get_access_token_for_request(self):
        """Return the current access token, refreshing first when within the
        window. Refresh failure raises SentinelError (the caller answers 502
        rather than forwarding a known-stale token unrefreshed when the
        provider told us it is expired)."""
        if self.needs_refresh():
            self.refresh()
        return self.access_token


class SubscriptionSentinel(RunSentinel):
    """RunSentinel with the subscription credential class: upstream-side
    Authorization: Bearer replacement (never x-api-key), oauth-beta merge,
    bounded refresh. Path mapping, token auth, redacted logging, teardown
    are inherited unchanged."""

    def __init__(self, run_id, token, provider_route, ca_bundle, subscription_credential):
        if provider_route is None:
            raise SentinelError("subscription sentinel requires the measured provider route")
        super().__init__(
            run_id=run_id,
            token=token,
            provider_route=provider_route,
            ca_bundle=ca_bundle,
            credential=None,
        )
        self.subscription = subscription_credential

    # -- upstream -------------------------------------------------------

    def _upstream_request(self, method, client_path_after_token, headers, body):
        if self._torn_down:
            raise SentinelError("torn-down")
        if not client_path_after_token.startswith("/v1/") and client_path_after_token != "/v1":
            return 404, {"content-type": "application/json"}, b'{"error":{"type":"not_found"}}'
        # (scheme, "://", origin-host[:port]) — connect host is the ORIGIN,
        # exactly the frozen sentinel's upstream_host derivation.
        _scheme, _, path_base = self.provider_route.partition("://")
        if not path_base:
            raise SentinelError("provider_route must be scheme://origin")
        upstream_path = "/" + path_base.split("/", 1)[1] if "/" in path_base else "/"
        upstream_path = upstream_path.rstrip("/")
        upstream_host = path_base.split("/", 1)[0]
        forward_path = upstream_path + client_path_after_token

        retried = False
        while True:
            try:
                access_token = self.subscription.get_access_token_for_request()
            except SentinelError as exc:
                self.log("upstream-auth unavailable (%s)" % exc.__class__.__name__)
                return 502, {"content-type": "application/json"}, b'{"error":"upstream-auth-unavailable"}'
            conn = http.client.HTTPSConnection(
                upstream_host,
                timeout=UPSTREAM_CONNECT_TIMEOUT_S,
                context=ssl.create_default_context(cafile=self.ca_bundle),
            )
            # R07: absolute upstream deadline (total connect+send+read), as in
            # the api-key sentinel -- a slow upstream cannot hold the slot open.
            watchdog = threading.Timer(UPSTREAM_TOTAL_TIMEOUT_S, conn.close)
            watchdog.daemon = True
            watchdog.start()
            try:
                fwd_headers = {}
                for name, value in headers.items():
                    lname = name.lower()
                    if lname in FORBIDDEN_REQUEST_HEADERS or lname in HOP_BY_HOP:
                        continue  # client credential headers are never forwarded
                    fwd_headers[name] = value
                fwd_headers["Host"] = upstream_host
                # Credential replacement happens HERE (upstream-side only),
                # as a BEARER header — never x-api-key.
                fwd_headers["Authorization"] = "Bearer %s" % access_token
                # Merge the OAuth beta into any client-supplied beta list
                # (append-if-missing — the pinned SDK provider behavior).
                existing_beta = fwd_headers.get("anthropic-beta")
                betas = [b.strip() for b in existing_beta.split(",")] if existing_beta else []
                betas = [b for b in betas if b]
                if OAUTH_BETA not in betas:
                    betas.append(OAUTH_BETA)
                fwd_headers["anthropic-beta"] = ",".join(betas)
                fwd_headers.setdefault("anthropic-version", "2023-06-01")
                conn.request(method, forward_path, body=body, headers=fwd_headers)
                resp = conn.getresponse()
                # F06: bound the upstream response read; over-cap fails closed.
                resp_body = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(resp_body) > MAX_RESPONSE_BYTES:
                    return 502, {"content-type": "application/json"}, b'{"error":{"type":"upstream_too_large"}}'
                status = resp.status
                resp_headers = {k: v for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP}
            finally:
                watchdog.cancel()
                conn.close()
            if status == 401 and not retried:
                # Force a refresh retry ONLY when the provider explicitly
                # marked the bearer token invalid; bounded to one attempt.
                www = str(resp_headers.get("WWW-Authenticate", ""))
                if "invalid_token" in www:
                    retried = True
                    self.log("upstream 401 invalid_token; one forced refresh retry")
                    try:
                        self.subscription.refresh()
                        continue
                    except SentinelError:
                        return 502, {"content-type": "application/json"}, b'{"error":"upstream-auth-unavailable"}'
            return status, resp_headers, resp_body


def load_subscription_credential(args, log):
    """Read the broker-provided credential document ONCE (fd or 0600 file —
    same channels as the frozen sentinel) and parse it with the strict
    profile validator. Memory-only."""
    class _Args:
        pass

    a = _Args()
    a.credential_fd = args.credential_fd
    a.credential_file = args.credential_file
    a.allow_group_readable_credential_file = args.allow_group_readable_credential_file
    raw = _load_credential(a)  # returns the document as a stripped string
    try:
        oauth = parse_subscription_document(raw.encode("utf-8"))
    except ValueError as exc:
        # Value-free: the parser's message carries no values, but the event
        # class is logged, never the message with any caller field text.
        raise SentinelError("subscription credential document rejected (%s)" % exc.code) from None
    return SubscriptionCredential(oauth, args.provider_route, args.ca_bundle, log=log)
