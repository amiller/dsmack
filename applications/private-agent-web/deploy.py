#!/usr/bin/env python3
"""Deploy the built private-agent page to dstack-webhost's shared Deno runtime."""
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
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

APP = Path(__file__).resolve().parent
PROJECT = "private-agent"
FIELDS = ("name", "runtime", "entry", "isolation", "mode", "source", "tree_hash", "ref", "deployed_at")


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
        archive.add(APP / "server.ts", arcname="server.ts")
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
    args = parser.parse_args()
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

    def snapshot():
        projects = json.loads(api("/_api/projects", auth=True))
        summaries = [{key: project.get(key) for key in FIELDS} for project in projects]
        return {
            "projects": summaries,
            "secret_release": next(p for p in summaries if p["name"] == "secret-release"),
            "secret_release_key": json.loads(api("/secret-release/public-key")),
            "broker_key": json.loads(api("/relay-broker/key")),
            "payments_key": json.loads(api("/relay-broker/payments/key")),
        }

    substrate = json.loads(api("/_api/substrate"))
    if "shared" not in substrate["isolation_modes"]:
        raise ValueError("Webhost does not support shared Deno")
    write(args.evidence / "substrate.json", substrate)
    before = snapshot()
    write(args.evidence / "before.json", before)
    existing = next((p for p in before["projects"] if p["name"] == PROJECT), None)
    if existing and any(existing.get(key) != value for key, value in {
        "runtime": "deno", "entry": "server.ts", "isolation": "shared",
        "source": "tarball://private-agent",
    }.items()):
        raise ValueError("Existing private-agent project does not match this deployment")
    manifest = {
        "name": PROJECT,
        "source": "tarball://" + PROJECT,
        "ref": ref,
        "runtime": "deno",
        "entry": "server.ts",
        "isolation": "shared",
        "env": {},
    }
    boundary = "private-agent-" + secrets.token_hex(16)
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
        + json.dumps(manifest).encode()
        + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="private-agent.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
        + archive
        + f"\r\n--{boundary}--\r\n".encode()
    )
    try:
        project = json.loads(api("/_api/projects", method="POST", body=body,
                                 kind="multipart/form-data; boundary=" + boundary, auth=True))
        write(args.evidence / "deployment.json", {key: project.get(key) for key in FIELDS})
        if project["runtime"] != "deno" or project["isolation"] != "shared":
            raise ValueError("Deployment did not select shared Deno")
        if project.get("mode") != "attested":
            project = json.loads(api("/_api/projects/private-agent/promote", method="POST", auth=True))
            write(args.evidence / "promotion.json", {key: project.get(key) for key in FIELDS})
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
    finally:
        after = snapshot()
        write(args.evidence / "after.json", after)
        for field in ("secret_release", "secret_release_key", "broker_key", "payments_key"):
            if before[field] != after[field]:
                raise ValueError(field + " changed during private-agent deployment")
    summary = {"url": base + "/private-agent/", "runtime": project["runtime"],
               "isolation": project["isolation"], "mode": project["mode"],
               "tree_hash": project["tree_hash"], "ref": ref,
               "broker_and_secret_release_keys_unchanged": True}
    write(args.evidence / "result.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, URLError) as error:
        raise SystemExit(str(error)) from None
