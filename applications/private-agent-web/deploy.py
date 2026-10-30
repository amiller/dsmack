#!/usr/bin/env python3
"""Deploy the built private-agent page to dstack-webhost's shared Deno runtime."""
import argparse
import fcntl
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

APP = Path(__file__).resolve().parent
PROJECT = "private-agent"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def token():
    value = os.environ.pop("TEE_DAEMON_TOKEN", "")
    if value:
        return value
    # Read the existing static assignment without executing the rest of the file.
    source = Path.home() / ".oauth3-prod-secrets.env"
    rows = [line for line in source.read_text().splitlines()
            if re.match(r"^\s*(?:export\s+)?TEE_DAEMON_TOKEN=", line)]
    if len(rows) != 1:
        raise ValueError("Expected one TEE_DAEMON_TOKEN assignment in the local secrets file")
    raw = rows[0].split("=", 1)[1]
    values = shlex.split(raw, comments=True)
    if len(values) != 1 or "$" in raw or "`" in raw or not values[0]:
        raise ValueError("TEE_DAEMON_TOKEN must be a static value or supplied in the environment")
    return values[0]


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def package(dist):
    if not (dist / "index.html").is_file():
        raise ValueError("Build the page first: dist/index.html is missing")
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        bundled=subprocess.check_output(["deno","bundle","--platform=deno",str(APP/"server.ts")])
        info=tarfile.TarInfo("server.ts");info.size=len(bundled)
        archive.addfile(info,io.BytesIO(bundled))
        archive.add(APP / "project.json", arcname="project.json")
        for path in sorted(dist.rglob("*")):
            relative = path.relative_to(dist)
            if path.is_symlink():
                raise ValueError("Built assets must not contain symlinks")
            if path.is_file():
                if any(part.startswith(".") for part in relative.parts) or path.suffix in (".key", ".pem"):
                    raise ValueError("Built assets contain a private filename")
                archive.add(path, arcname="dist/" + relative.as_posix(), recursive=False)
    return data.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=APP / "dist")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--url", default="https://pod.dstack.soc1024.com")
    parser.add_argument("--operator-token-sha256")
    parser.add_argument("--smtp-env", type=Path, help="Private JSON file containing SMTP and email receiver configuration")
    args = parser.parse_args()
    if args.operator_token_sha256 and not re.fullmatch(r"[0-9a-f]{64}",args.operator_token_sha256):
        raise ValueError("operator token SHA256 must be lowercase hex")
    smtp_env = json.loads(args.smtp_env.read_text()) if args.smtp_env else {}
    if not isinstance(smtp_env, dict) or set(smtp_env) - {"SMTP_HOST", "SMTP_PORT", "SMTP_TLS", "SMTP_FROM", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_RECOVERY_ADDRESS"}:
        raise ValueError("SMTP configuration contains unsupported keys")
    if any(not isinstance(value, str) for value in smtp_env.values()):
        raise ValueError("SMTP configuration values must be strings")
    archive = package(args.dist.resolve())
    ref = subprocess.check_output(["git", "-C", str(APP), "rev-parse", "HEAD"], text=True).strip()
    args.evidence.mkdir(parents=True, exist_ok=True)
    admin = token()
    base = args.url.rstrip("/")
    opener = build_opener(NoRedirect)

    def api(path, *, method="GET", body=None, kind=None, auth=False):
        headers = {}
        if auth:
            headers["Authorization"] = "Bearer " + admin
        if kind:
            headers["Content-Type"] = kind
        request = Request(base + path, method=method, data=body, headers=headers)
        try:
            with opener.open(request, timeout=60) as response:
                return response.read()
        except HTTPError as error:
            # Never echo a server response that might reflect environment values.
            raise RuntimeError(f"{method} {path}: HTTP {error.code}") from None

    substrate = json.loads(api("/_api/substrate"))
    if "shared" not in substrate["isolation_modes"]:
        raise ValueError("Webhost does not support shared Deno")
    manifest = {
        "name": PROJECT,
        "source": "tarball://" + PROJECT,
        "ref": ref,
        "runtime": "deno",
        "entry": "server.ts",
        "isolation": "shared",
        "env": {**smtp_env, **({"OPERATOR_TOKEN_SHA256":args.operator_token_sha256} if args.operator_token_sha256 else {})},
    }
    boundary = "private-agent-" + secrets.token_hex(16)
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
        + json.dumps(manifest).encode()
        + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="private-agent.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
        + archive
        + f"\r\n--{boundary}--\r\n".encode()
    )
    project = json.loads(api("/_api/projects", method="POST", body=body,
                             kind="multipart/form-data; boundary=" + boundary, auth=True))
    if project["runtime"] != "deno" or project["isolation"] != "shared":
        raise ValueError("Deployment did not select shared Deno")
    if project.get("mode") != "attested":
        project = json.loads(api("/_api/projects/private-agent/promote", method="POST", auth=True))
    for attempt in range(30):
        try:
            page = api("/private-agent/")
            if page != (args.dist / "index.html").read_bytes():
                raise RuntimeError("Deployed page has not loaded the built index.html")
            break
        except (RuntimeError, URLError):
            if attempt == 29:
                raise
            time.sleep(2)
    summary = {"url": base + "/private-agent/", "runtime": project["runtime"],
               "isolation": project["isolation"], "mode": project["mode"],
               "ref": ref}
    write(args.evidence / "result.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    try:
        # Shared Deno reloads affect both projects. Hold one upload/promote
        # transaction at a time so another project cannot remove its key socket.
        lock_path = Path.home() / ".cache/dsmack-webhost-deploy.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a") as deployment_lock:
            fcntl.flock(deployment_lock, fcntl.LOCK_EX)
            main()
    except (OSError, ValueError, RuntimeError, URLError) as error:
        raise SystemExit(str(error)) from None
