#!/usr/bin/env python3
"""Per-run credential sentinel — guest-root/broker side (claude-inputs lane).

Implements the FROZEN per-run sentinel lifecycle from
contract10/candidate/interfaces/compose-runner-interface.md (D07) and
claude-adapter-interface.md for the env-transport profile `claude-api-key/1`
(plus the files-only `dsmack.broker-file-disclosure/1` route):

  endpoint      http://<gateway-ip>:<port>/<token>   (ends AT the token;
                NO '/v1' suffix — the pinned client appends '/v1/<path>')
  auth          the per-run bearer token is path segment 1; unknown/stale
                tokens are refused (404, no information disclosed)
  mapping       upstream_url = provider_route + <client path after '/<token>'>
                — the client path after the token is forwarded VERBATIM to
                the measured upstream ORIGIN; only '/v1/<path>' is accepted
                under env-transport (anything else: 404)
  credential    the run's broker-held provider key is injected UPSTREAM-side:
                client credential headers (x-api-key, Authorization) are
                NEVER forwarded — they are replaced. The key lives only in
                this process's memory (read once from the broker-provided
                source), never in logs, never workload-side.
  TLS           verification toward the provider is ALWAYS ON (CA bundle +
                hostname). Disabling TLS is not an option. The CA bundle is
                an explicit argument (the guest/image CA bundle in
                production; a TEST-ONLY CA in the labeled fake-provider
                test).
  privacy       logs carry method, redacted path ('/<token-redacted>/…'),
                status and byte counts only — never bodies, never
                credential material, never full URLs.
  teardown      shutdown() closes the listener, drops the credential and the
                token; post-teardown requests fail closed (connection
                refused / 404).

Files-only profile (generic-broker-file/1, provider_route null): the ONLY
route is GET /<token>/broker-file/<slot>, returning that slot's caller-
supplied bytes bounded by the slot max_bytes from the broker's per-run
store. Any other path/method is 404/405.

This process is ordinary runner/broker-side userland tooling: it is NOT the
signed app and holds the credential only on behalf of the run (bound to
run_id), per the existing root-TLS-broker/sentinel model (prior lanes,
read-only reference).
"""

import argparse
import hmac
import http.client
import http.server
import json
import os
import socket
import ssl
import sys
import threading

REDACTED_TOKEN = "<token>"
# F06 bounds (fail-closed; no unbounded read or wait, no caller text in logs).
MAX_REQUEST_BYTES = 8 * 1024 * 1024      # request body cap (413 over)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024    # upstream response cap (502 over)
SOCKET_READ_TIMEOUT_S = 30               # explicit deadline on incoming reads
MAX_CONCURRENT_REQUESTS = 16             # bounded in-flight requests
# R07: ABSOLUTE deadlines (total wall-clock, not merely idle-socket time) and
# capacity acquired BEFORE a handler thread is spawned (see SentinelServer).
UPSTREAM_CONNECT_TIMEOUT_S = 10          # TCP+TLS establishment ceiling to the provider
UPSTREAM_TOTAL_TIMEOUT_S = 210            # total upstream request+response ceiling
GATE_ACQUIRE_TIMEOUT_S = 5               # wait for a free slot before 503 (in the accept loop)
MAX_REQUEST_SECONDS = 220                 # hard ceiling on one request's whole lifetime
# Fixed route CLASSES logged instead of caller-controlled path/query text.
ROUTE_HEALTH = "health"
ROUTE_BROKER_FILE = "broker-file"
ROUTE_V1_PROXY = "v1-proxy"
ROUTE_UNRECOGNIZED = "unrecognized"
ROUTE_UNKNOWN_TOKEN = "unknown-token"
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
# Client credential headers are replaced upstream-side, never forwarded.
CREDENTIAL_HEADERS = ("x-api-key", "authorization")
FORBIDDEN_REQUEST_HEADERS = CREDENTIAL_HEADERS + ("host", "content-length", "connection")


def provider_connection(host, ca_bundle, timeout):
    """TLS remains in the guest when a measured CONNECT proxy is configured."""
    from urllib.parse import urlsplit
    proxy = os.environ.get('HTTPS_PROXY')
    if not proxy:
        return http.client.HTTPSConnection(host, timeout=timeout,
                                          context=ssl.create_default_context(cafile=ca_bundle))
    route = urlsplit(proxy)
    if host != 'api.anthropic.com' or route.scheme != 'http' or not route.hostname or not route.port or route.username or route.path:
        raise SentinelError('invalid measured CONNECT route')
    conn = http.client.HTTPSConnection(route.hostname, route.port, timeout=timeout,
                                      context=ssl.create_default_context(cafile=ca_bundle))
    conn.set_tunnel(host, 443)
    return conn


class SentinelError(Exception):
    pass


def _redact_path(raw_path, token):
    if raw_path.startswith("/" + token):
        return "/" + REDACTED_TOKEN + raw_path[1 + len(token):]
    return "/" + REDACTED_TOKEN + "/(unrecognized)"


class RunSentinel:
    """One per-run sentinel instance: fresh token, one measured route class."""

    def __init__(self, run_id, token, provider_route, ca_bundle,
                 credential, broker_files=None, broker_file_caps=None):
        self.run_id = run_id
        self.token = token.encode("utf-8") if isinstance(token, str) else token
        self.provider_route = provider_route  # None => files-only profile
        self.ca_bundle = ca_bundle
        self.credential = credential  # provider key; memory-only
        self.broker_files = broker_files or {}  # slot -> bytes
        self.broker_file_caps = broker_file_caps or {}  # slot -> max_bytes
        self._torn_down = False
        self._http = None
        self.log_lock = threading.Lock()

    # -- logging -------------------------------------------------------

    def log(self, line):
        with self.log_lock:
            sys.stderr.write("sentinel[%s]: %s\n" % (self.run_id, line))
            sys.stderr.flush()

    # -- upstream ------------------------------------------------------

    def _upstream_request(self, method, client_path_after_token, headers, body):
        """Forward to the measured provider origin over TLS-verified HTTPS."""
        if self._torn_down:
            raise SentinelError("torn-down")
        if self.provider_route is None:
            raise SentinelError("files-only sentinel proxies no provider route")
        if not client_path_after_token.startswith("/v1/") and client_path_after_token != "/v1":
            return 404, {"content-type": "application/json"}, b'{"error":{"type":"not_found"}}'
        origin, _, path_base = self.provider_route.partition("://")
        if not path_base:
            raise SentinelError("provider_route must be scheme://origin")
        upstream_path = "/" + path_base.split("/", 1)[1] if "/" in path_base else "/"
        upstream_path = upstream_path.rstrip("/")
        upstream_host = path_base.split("/", 1)[0]
        forward_path = upstream_path + client_path_after_token
        conn = provider_connection(upstream_host, self.ca_bundle, UPSTREAM_CONNECT_TIMEOUT_S)
        # R07: impose an ABSOLUTE upstream deadline (total connect+send+read),
        # not just a per-operation idle timeout. A watchdog closes the socket
        # when the whole exchange exceeds UPSTREAM_TOTAL_TIMEOUT_S, so a slow
        # or trickling upstream cannot hold the request (and its slot) open
        # beyond the ceiling.
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
            # Credential replacement happens HERE (upstream-side only).
            fwd_headers["x-api-key"] = self.credential
            fwd_headers["anthropic-version"] = fwd_headers.get("anthropic-version", "2023-06-01")
            conn.request(method, forward_path, body=body, headers=fwd_headers)
            resp = conn.getresponse()
            # F06: bound the upstream response read; an over-cap body fails
            # closed rather than being buffered unbounded.
            resp_body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(resp_body) > MAX_RESPONSE_BYTES:
                return 502, {"content-type": "application/json"}, b'{"error":{"type":"upstream_too_large"}}'
            resp_headers = {k: v for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP}
            return resp.status, resp_headers, resp_body
        finally:
            watchdog.cancel()
            conn.close()

    def _broker_file_response(self, slot):
        """generic-broker-file/1 measured disclosure route (bounded, GET
        only). Audience enforcement (which service may fetch) is the
        runner/broker's per-service capability split; this listener is
        reachable only by the declared audience per the lowered transport."""
        if slot not in self.broker_files:
            return 404, {"content-type": "application/json"}, b'{"error":"unknown-slot"}'
        data = self.broker_files[slot]
        cap = self.broker_file_caps.get(slot)
        if cap is not None and len(data) > cap:
            return 500, {"content-type": "application/json"}, b'{"error":"slot-cap-violation"}'
        return 200, {"content-type": "application/octet-stream"}, data

    # -- request routing -----------------------------------------------

    def handle(self, method, raw_path, headers, body):
        """Route one request. Returns (status, headers, body). The token is
        path segment 1 and is REMOVED from the forwarded path."""
        if self._torn_down:
            return 503, {"content-type": "application/json"}, b'{"error":"sentinel-torn-down"}'
        parts = raw_path.lstrip("/").split("/", 1)
        supplied = parts[0].encode("utf-8")
        rest = "/" + (parts[1] if len(parts) > 1 else "")
        if not hmac.compare_digest(supplied, self.token):
            # Unknown/stale/foreign-run token: refused, no information. F06:
            # log the fixed route CLASS only -- never the caller-supplied path.
            self.log("%s route=%s -> 404" % (method, ROUTE_UNKNOWN_TOKEN))
            return 404, {"content-type": "application/json"}, b'{"error":{"type":"not_found"}}'
        if rest == "/health":
            # Liveness only (no credential material in the response).
            self.log("%s route=%s -> 200" % (method, ROUTE_HEALTH))
            return 200, {"content-type": "application/json"}, b'{"ok":true}'
        if rest.startswith("/broker-file/"):
            if method != "GET":
                self.log("%s route=%s -> 405" % (method, ROUTE_BROKER_FILE))
                return 405, {"content-type": "application/json"}, b'{"error":"method-not-allowed"}'
            if self.provider_route is not None:
                self.log("%s route=%s -> 404" % (method, ROUTE_BROKER_FILE))
                return 404, {"content-type": "application/json"}, b'{"error":{"type":"not_found"}}'
            status, hdrs, payload = self._broker_file_response(rest[len("/broker-file/"):])
            self.log("%s route=%s -> %d (%d bytes)" % (method, ROUTE_BROKER_FILE, status, len(payload)))
            return status, hdrs, payload
        if self.provider_route is not None:
            # F06: only the fixed /v1 route class is proxied; log that class,
            # the status and byte count -- never the caller path or query.
            route = ROUTE_V1_PROXY if (rest == "/v1" or rest.startswith("/v1/")) else ROUTE_UNRECOGNIZED
            status, hdrs, payload = self._upstream_request(method, rest, headers, body)
            self.log("%s route=%s -> %d (%d bytes)" % (method, route, status, len(payload)))
            return status, hdrs, payload
        self.log("%s route=%s -> 404" % (method, ROUTE_UNRECOGNIZED))
        return 404, {"content-type": "application/json"}, b'{"error":{"type":"not_found"}}'


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "dsmack-sentinel/1"
    sys_version = ""
    # F06: explicit deadline on incoming socket reads (no unbounded wait).
    timeout = SOCKET_READ_TIMEOUT_S

    def log_message(self, fmt, *args):  # default logging would echo paths
        pass

    def _reply(self, status, hdrs, payload):
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _proxy(self):
        sent = self.server.sentinel
        # R07: the concurrency slot was already acquired in the serialized
        # accept loop (SentinelServer.process_request) BEFORE this handler
        # thread existed, and is released in process_request_thread's finally.
        # A connection flood therefore cannot create unbounded header-reading
        # threads here -- saturated connections are shed (503) and closed in
        # the accept loop without a worker thread ever being spawned.
        # F06: cap the request body; an over-cap or unparseable Content-Length
        # fails closed (413) before any read.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, {"content-type": "application/json"}, b'{"error":"bad-length"}')
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._reply(413, {"content-type": "application/json"}, b'{"error":"request-too-large"}')
            return
        body = self.rfile.read(length) if length else None
        self._handle_body(sent, body)

    def _handle_body(self, sent, body):
        try:
            status, hdrs, payload = sent.handle(
                self.command, self.path, dict(self.headers.items()), body
            )
        except SentinelError as exc:
            sent.log("%s (refused: %s)" % (self.command, exc))
            status, hdrs, payload = 503, {"content-type": "application/json"}, b'{"error":"refused"}'
        except (OSError, ssl.SSLError) as exc:
            sent.log("%s upstream-failure (%s)" % (self.command, type(exc).__name__))
            status, hdrs, payload = 502, {"content-type": "application/json"}, b'{"error":"upstream-failure"}'
        self._reply(status, hdrs, payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _proxy


class SentinelServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, sentinel):
        self.sentinel = sentinel
        # F06/R07: bounded concurrency gate acquired in the accept loop.
        self.request_gate = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(addr, _Handler)

    def process_request(self, request, client_address):
        # R07: acquire the concurrency slot HERE, in the single serialized
        # accept loop, BEFORE a worker thread is spawned. When the server is
        # already at capacity, shed load (503) and close the connection WITHOUT
        # creating a thread -- so a flood cannot spawn unbounded header-reading
        # threads that merely wait on the semaphore (the prior ThreadingHTTPServer
        # spawned a thread per connection first and gated only inside _proxy).
        if not self.request_gate.acquire(timeout=GATE_ACQUIRE_TIMEOUT_S):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 16\r\n"
                    b"Connection: close\r\n\r\n"
                    b'{"error":"busy"}'
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        # R07: impose an ABSOLUTE wall-clock deadline on the whole request
        # (read + route + upstream), not just an idle-socket timeout, then
        # ALWAYS release the slot. A watchdog closes the client socket if the
        # handler exceeds MAX_REQUEST_SECONDS so total request lifetime (and
        # thus how long a slot is held) is bounded.
        deadline = threading.Timer(MAX_REQUEST_SECONDS, lambda: self.shutdown_request(request))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self.request_gate.release()


def _load_credential(args):
    """Read the provider credential ONCE from the broker-provided source.
    Supported: --credential-fd N (broker passes a pipe/fd; preferred — keeps
    the credential out of argv and the filesystem) or --credential-file P
    (broker per-run store, 0600). No other channel exists; no discovery."""
    if (args.credential_fd is None) == (args.credential_file is None):
        raise SentinelError("exactly one credential source is required: --credential-fd or --credential-file")
    if args.credential_fd is not None:
        with os.fdopen(int(args.credential_fd), "rb") as fh:
            data = fh.read(65536)
    else:
        st = os.lstat(args.credential_file)
        if (st.st_mode & 0o077) and not args.allow_group_readable_credential_file:
            raise SentinelError("credential file must not be group/world readable")
        with open(args.credential_file, "rb") as fh:
            data = fh.read(65536)
    cred = data.decode("utf-8").strip()
    if not cred or "\x00" in cred:
        raise SentinelError("credential source is empty or malformed")
    return cred


def main(argv=None):
    p = argparse.ArgumentParser(description="dsmack per-run credential sentinel (claude-api-key/1 + claude-subscription/1)")
    p.add_argument("--run-id", required=True)
    p.add_argument("--token", required=True, help="fresh per-run bearer token (path segment 1)")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, required=True)
    p.add_argument("--provider-route", default=None,
                   help="measured upstream origin, e.g. https://api.anthropic.com; omit for the files-only profile")
    p.add_argument("--ca-bundle", required=True, help="CA bundle for provider TLS verification (ALWAYS verified)")
    p.add_argument("--auth-mode", choices=("api-key", "claude-subscription"), default="api-key",
                   help="credential class (claude-subscription/1 is a PROPOSED delta pending "
                        "independent review): api-key injects x-api-key upstream (frozen "
                        "claude-api-key/1 behavior, unchanged); claude-subscription injects "
                        "Authorization: Bearer + merges the oauth beta header, with documented-"
                        "protocol refresh (sentinel_oauth)")
    p.add_argument("--credential-fd", type=int, default=None)
    p.add_argument("--credential-file", default=None)
    p.add_argument("--allow-group-readable-credential-file", action="store_true",
                   help="test-only escape for container test environments")
    p.add_argument("--broker-files-manifest", default=None,
                   help="JSON {slot: path} of broker per-run store files for the files-only route")
    p.add_argument("--broker-file-caps", default=None, help="JSON {slot: max_bytes}")
    p.add_argument("--ready-file", default=None, help="created (empty) after listen; runner readiness poll")
    p.add_argument("--serving-seconds", type=int, default=0,
                   help="test/one-shot mode: serve N seconds then teardown (0 = until SIGTERM)")
    p.add_argument("--broker-config", default=None,
                   help="F06: reviewed broker configuration JSON binding the ALLOWED upstream "
                        "route and CA; when given, --provider-route and --ca-bundle MUST match it "
                        '(shape {"provider_route": <origin|null>, "ca_bundle": <path>}). This '
                        "prevents an arbitrary route/CA from being selected outside the review.")
    args = p.parse_args(argv)

    # F06: bind route + CA selection to the reviewed broker configuration.
    if args.broker_config is not None:
        try:
            with open(args.broker_config) as fh:
                bc = json.load(fh)
        except (OSError, ValueError):
            sys.stderr.write("sentinel: broker-config unreadable; refusing\n")
            return 2
        if not isinstance(bc, dict) or "provider_route" not in bc or "ca_bundle" not in bc:
            sys.stderr.write("sentinel: broker-config must bind provider_route and ca_bundle; refusing\n")
            return 2
        if args.provider_route != bc["provider_route"] or args.ca_bundle != bc["ca_bundle"]:
            sys.stderr.write("sentinel: selected route/CA do not match the reviewed broker configuration; refusing\n")
            return 2

    # F06: when a provider route is proxied it must be an explicit https origin
    # (TLS stays ON) and the CA bundle must be a real file -- no plaintext
    # upstream, no silently-missing trust anchor.
    if args.provider_route is not None:
        if not args.provider_route.startswith("https://"):
            sys.stderr.write("sentinel: provider-route must be an https origin (TLS verification is mandatory); refusing\n")
            return 2
        if not os.path.isfile(args.ca_bundle):
            sys.stderr.write("sentinel: CA bundle for provider TLS verification is missing; refusing\n")
            return 2

    if args.auth_mode == "claude-subscription" and (args.broker_files_manifest or args.broker_file_caps):
        # The broker-file disclosure route is NOT part of the subscription
        # profile; refuse rather than silently co-mount another route class.
        sys.stderr.write("sentinel: broker-file routes are not part of auth-mode claude-subscription; refusing\n")
        return 2

    broker_files, caps = {}, {}
    if args.broker_files_manifest:
        with open(args.broker_files_manifest) as fh:
            for slot, path in json.load(fh).items():
                with open(path, "rb") as fh2:
                    broker_files[slot] = fh2.read(1 << 26)
    if args.broker_file_caps:
        caps = {k: int(v) for k, v in json.load(open(args.broker_file_caps)).items()}

    try:
        if args.auth_mode == "claude-subscription":
            # PROPOSED DELTA (claude-subscription/1): the credential source is
            # the caller-staged claudeAiOauth document (same fd/0600-file
            # channels); strict validation + memory-only holder + Bearer-mode
            # upstream live in sentinel_oauth.
            try:
                from .sentinel_oauth import SubscriptionSentinel, load_subscription_credential
            except ImportError:
                # Run as a flat script: put the harness PACKAGE PARENT (three
                # levels up: candidate/ <- harness/ <- sentinel/ <- this file)
                # on sys.path so `harness.sentinel.sentinel_oauth` and its
                # own relative imports resolve.
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
                from harness.sentinel.sentinel_oauth import SubscriptionSentinel, load_subscription_credential

            def _sub_log(msg):
                sys.stderr.write("sentinel[%s]: %s\n" % (args.run_id, msg))
                sys.stderr.flush()

            subscription = load_subscription_credential(args, _sub_log)
            sentinel = SubscriptionSentinel(
                run_id=args.run_id,
                token=args.token,
                provider_route=args.provider_route,
                ca_bundle=args.ca_bundle,
                subscription_credential=subscription,
            )
        else:
            credential = _load_credential(args)
            sentinel = RunSentinel(
                run_id=args.run_id,
                token=args.token,
                provider_route=args.provider_route,
                ca_bundle=args.ca_bundle,
                credential=credential,
                broker_files=broker_files,
                broker_file_caps=caps,
            )
    except (SentinelError, OSError, ValueError) as exc:
        sys.stderr.write("sentinel: credential load refused (%s)\n" % type(exc).__name__)
        return 2
    try:
        server = SentinelServer((args.listen_host, args.listen_port), sentinel)
    except OSError as exc:
        sys.stderr.write("sentinel: listen failed (%s)\n" % type(exc).__name__)
        return 2

    if args.ready_file:
        with open(args.ready_file, "w") as fh:
            fh.write("ready\n")
    sentinel.log(
        "listening %s:%d profile=%s auth-mode=%s teardown-after=%ds"
        % (args.listen_host, args.listen_port, "files-only" if not args.provider_route else "env-transport",
           args.auth_mode, args.serving_seconds)
    )

    def _teardown(signum, _frame):
        sentinel.log("teardown (signal %s)" % signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    import signal

    signal.signal(signal.SIGTERM, _teardown)
    signal.signal(signal.SIGINT, _teardown)

    if args.serving_seconds > 0:
        threading.Timer(args.serving_seconds, lambda: _teardown("timeout", None)).start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        # Teardown: the credential and token die with this instance; the
        # ready-file is removed so stale readiness is observable.
        sentinel.credential = None
        sentinel._torn_down = True
        if args.ready_file:
            try:
                os.unlink(args.ready_file)
            except OSError:
                pass
        sentinel.log("teardown complete")
    return 0


if __name__ == "__main__" and __package__ in (None, ""):
    # Script execution: re-enter through the package path so THIS module and
    # the subscription sibling (sentinel_oauth) share ONE class set —
    # otherwise sentinel_oauth's raises/excepts split across __main__ and
    # harness.sentinel.sentinel and the load refusal would escape main().
    _pkg_parent = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if _pkg_parent not in sys.path:
        sys.path.insert(0, _pkg_parent)
    from harness.sentinel.sentinel import main as _main
    sys.exit(_main())
elif __name__ == "__main__":
    sys.exit(main())
