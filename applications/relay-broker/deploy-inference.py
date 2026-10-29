#!/usr/bin/env python3
"""Prepare and explicitly apply a relay-broker update to shared Deno."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

APP = Path(__file__).resolve().parent
REPO = APP.parents[1]
SECRET_FIELDS = {"near_api_key", "near_management_token", "near_reporting_token", "managementtoken",
                 "reportingtoken", "api_key", "apikey", "password", "secret", "credential"}


def public_config(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SECRET_FIELDS:
                raise ValueError("configuration must contain no provider credentials")
            public_config(child)
    elif isinstance(value, list):
        for child in value:
            public_config(child)


def envelope(value):
    if not isinstance(value, dict) or set(value) != {"v", "ephemeralPublicKey", "iv", "ciphertext"}:
        raise ValueError("encrypted environment must contain only ciphertext envelope fields")
    if type(value["v"]) is not int or value["v"] != 1 or not isinstance(value["ephemeralPublicKey"], str) or not re.fullmatch(r"0x04[0-9a-fA-F]{128}", value["ephemeralPublicKey"]):
        raise ValueError("invalid encrypted environment version or public key")
    if not isinstance(value["iv"], str) or not re.fullmatch(r"[0-9a-f]{24}", value["iv"]):
        raise ValueError("invalid encrypted environment IV")
    if not isinstance(value["ciphertext"], str) or not 32 <= len(value["ciphertext"]) <= 131104 or not re.fullmatch(r"(?:[0-9a-f]{2})+", value["ciphertext"]):
        raise ValueError("invalid encrypted environment ciphertext")
    return value


def write_json(path, value):
    with path.open("x") as out:
        out.write(json.dumps(value, indent=2) + "\n")


def prepare(args):
    config = json.loads(args.config.read_text())
    public_config(config)
    if not config.get("payments") or not config.get("inference"):
        raise ValueError("configuration needs payments and inference blocks")
    if not re.fullmatch(r"[0-9a-f]{64}", args.operator_token_sha256):
        raise ValueError("operator token SHA256 must be 64 lowercase hex characters")
    manifest = {"name": "relay-broker", "source": "tarball://relay-broker",
                "ref": subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip(),
                "runtime": "deno", "entry": "applications/relay-broker/server.ts", "isolation": "shared",
                "env": {"OPERATOR_TOKEN_SHA256": args.operator_token_sha256}}
    if args.encrypted_env:
        manifest["env"]["NEAR_ENCRYPTED_ENV"] = json.dumps(envelope(json.loads(args.encrypted_env.read_text())))
    args.out.mkdir(parents=True, exist_ok=True)
    for name in ("relay-broker.tgz", "relay-broker.manifest.json"):
        if (args.out / name).exists():
            raise ValueError("output already exists; choose a fresh preparation directory")
    if not (APP / "inference.mjs").is_file():
        raise ValueError("inference module is missing")
    with tempfile.TemporaryDirectory(prefix="inference-package-") as temporary:
        bundled = Path(temporary) / "schema.mjs"
        subprocess.run(["deno", "bundle", "--platform=browser", "--minify",
                        str(REPO / "applications/payments/schema.mjs"), "-o", str(bundled)], check=True)
        with tarfile.open(args.out / "relay-broker.tgz", "x:gz") as archive:
            for source in sorted(APP.iterdir()):
                if source.suffix in (".mjs", ".ts") and source.name not in ("near-attestation.mjs", "deno-forwarder.mjs", "encrypt-provider-env.mjs") and not source.name.endswith((".test.mjs", ".test.ts", "_test.ts")):
                    archive.add(source, arcname="applications/relay-broker/" + source.name)
            for name in ("quorum.mjs", "admission.mjs"):
                archive.add(REPO / "applications/payments" / name, arcname="applications/payments/" + name)
            archive.add(bundled, arcname="applications/payments/schema.mjs")
            attestation = Path(temporary) / "near-attestation.mjs"
            subprocess.run(["deno", "bundle", "--platform=deno", "--minify",
                            str(APP / "near-attestation.mjs"), "-o", str(attestation)], check=True)
            archive.add(attestation, arcname="applications/relay-broker/near-attestation.mjs")
            forwarder = Path(temporary) / "deno-forwarder.mjs"
            subprocess.run(["deno", "bundle", "--platform=deno", "--minify", str(APP / "deno-forwarder.mjs"), "-o", str(forwarder)], check=True)
            archive.add(forwarder, arcname="applications/relay-broker/deno-forwarder.mjs")
            archive.add(REPO / "applications/browser-p2p/tunnels.mjs", arcname="applications/browser-p2p/tunnels.mjs")
            archive.add(APP / "project.json", arcname="project.json")
            archive.add(REPO / "dstack-compat/secret-release/policy.mjs", arcname="dstack-compat/secret-release/policy.mjs")
            body = json.dumps(config).encode()
            info = tarfile.TarInfo("applications/relay-broker/config.json")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    write_json(args.out / "relay-broker.manifest.json", manifest)
    print("Prepared relay-broker upload files in " + str(args.out))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def token():
    value = os.environ.pop("TEE_DAEMON_TOKEN", "")
    if value:
        return value
    # Parse one existing assignment; never source or execute a secrets file.
    source = Path.home() / ".oauth3-prod-secrets.env"
    rows = [line for line in source.read_text().splitlines()
            if re.match(r"^\s*(?:export\s+)?TEE_DAEMON_TOKEN=", line)]
    if len(rows) != 1:
        raise ValueError("expected one static TEE_DAEMON_TOKEN assignment")
    raw = rows[0].split("=", 1)[1]
    values = shlex.split(raw, comments=True)
    if len(values) != 1 or "$" in raw or "`" in raw or not values[0]:
        raise ValueError("TEE_DAEMON_TOKEN must be static or supplied in the environment")
    return values[0]


def client(url, admin=None):
    base, opener = url.rstrip("/"), build_opener(NoRedirect)
    def api(path, *, method="GET", body=None, kind=None, auth=False, timeout=30):
        headers = {}
        if auth:
            if not admin:
                raise ValueError("admin authentication required")
            headers["Authorization"] = "Bearer " + admin
        if kind:
            headers["Content-Type"] = kind
        try:
            with opener.open(Request(base + path, method=method, data=body, headers=headers), timeout=timeout) as response:
                return json.load(response)
        except HTTPError as error:
            raise RuntimeError(f"{method} {path}: HTTP {error.code}") from None
        except (URLError, TimeoutError, json.JSONDecodeError):
            raise RuntimeError(f"{method} {path}: request failed") from None
    return api


def deploy(args):
    manifest = json.loads((args.prepared / "relay-broker.manifest.json").read_text())
    required = {"name": "relay-broker", "runtime": "deno", "entry": "applications/relay-broker/server.ts",
                "isolation": "shared", "source": "tarball://relay-broker"}
    if any(manifest.get(key) != value for key, value in required.items()):
        raise ValueError("prepared project must be relay-broker shared Deno")
    if set(manifest.get("env", {})) - {"OPERATOR_TOKEN_SHA256", "NEAR_ENCRYPTED_ENV"}:
        raise ValueError("prepared environment contains unsupported fields")
    if "NEAR_ENCRYPTED_ENV" in manifest["env"]:
        envelope(json.loads(manifest["env"]["NEAR_ENCRYPTED_ENV"]))
    archive = (args.prepared / "relay-broker.tgz").read_bytes()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        public_config(json.load(package.extractfile("applications/relay-broker/config.json")))
    if not args.apply:
        print("Prepared broker package accepted; use --apply to upload and promote")
        return
    args.evidence.mkdir(parents=True, exist_ok=True)
    api = client(args.url, token())
    boundary = "relay-broker-" + secrets.token_hex(16)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
            + json.dumps(manifest).encode()
            + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="relay-broker.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
            + archive + f"\r\n--{boundary}--\r\n".encode())
    project = api("/_api/projects", method="POST", body=body,
                  kind="multipart/form-data; boundary=" + boundary, auth=True)
    if project.get("runtime") != "deno" or project.get("isolation") != "shared":
        raise ValueError("deployed broker did not select shared Deno")
    api("/_api/projects/relay-broker/promote", method="POST", auth=True)
    deadline = time.monotonic() + 30
    while True:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("broker did not become ready within 30 seconds")
            api("/relay-broker/key", timeout=min(5, remaining))
            break
        except RuntimeError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("broker did not become ready within 30 seconds") from None
            time.sleep(min(1, remaining))
    write_json(args.evidence / "result.json", {"project": "relay-broker", "ref": manifest["ref"]})
    print("Updated relay-broker shared Deno")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("prepare", help="local packaging only")
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--operator-token-sha256", required=True)
    p.add_argument("--encrypted-env", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(run=prepare)
    p = sub.add_parser("deploy", help="upload and promote only with --apply")
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(run=deploy)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
    except (OSError, subprocess.CalledProcessError, tarfile.TarError):
        raise SystemExit("Broker deployment command failed; inspect the named configuration and sanitized evidence") from None
