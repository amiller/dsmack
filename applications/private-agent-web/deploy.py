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
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

APP = Path(__file__).resolve().parent
PROJECT = "private-agent"
sys.path.insert(0, str(APP))
sys.path.insert(0, str(APP.parents[1] / "tools"))
from deploy_idle import wait_for_idle
from deploy_target import WEBHOST, STAGING_HOST, project_name, source_ref, staging_page_url
from bundle import check as check_bundle


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


def package(dist, target="production", config_path=None, staging_origin=STAGING_HOST):
    config = json.loads((config_path or dist / "config.json").read_bytes())
    if target == "staging":
        config["broker"] = WEBHOST + "/relay-broker-staging"
        config["tunnels"] = staging_page_url(staging_origin) + "tunnels"
    if config != json.loads((dist / "config.json").read_bytes()):
        raise ValueError("Build with PAGE_CONFIG and PAGE_TARGET before packaging target config")
    check_bundle(dist)
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
    parser.add_argument("--target", choices=("staging", "production"), required=True)
    parser.add_argument("--registry-account", help="Existing cast keystore account authorized as PageBundleRegistry publisher")
    parser.add_argument("--skip-registry-publication", action="store_true", help="Staging only: deploy without a configured bundle registry or on-chain publication")
    parser.add_argument("--staging-origin", choices=(STAGING_HOST, WEBHOST), default=STAGING_HOST)
    parser.add_argument("--wait-idle-minutes", type=float, default=10)
    parser.add_argument("--config", type=Path, help="Public page config for this target, including broker signing identities")
    parser.add_argument("--dist", type=Path, default=APP / "dist")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--url", default=WEBHOST)
    parser.add_argument("--operator-token-sha256", required=True)
    parser.add_argument("--page-env", type=Path, required=True, help="Existing private page environment JSON, including email receiver configuration")
    args = parser.parse_args()
    ref = source_ref(APP.parents[1], args.target)
    if args.target != "staging" and (args.skip_registry_publication or args.staging_origin != STAGING_HOST):
        raise ValueError("staging deployment options require --target staging")
    if not args.skip_registry_publication and not args.registry_account:
        raise ValueError("--registry-account is required for bundle publication")
    project_name_value = project_name(PROJECT, args.target)
    if args.operator_token_sha256 and not re.fullmatch(r"[0-9a-f]{64}",args.operator_token_sha256):
        raise ValueError("operator token SHA256 must be lowercase hex")
    page_env = json.loads(args.page_env.read_text())
    if not isinstance(page_env, dict) or set(page_env) - {"EMAIL_RECOVERY_ADDRESS"}:
        raise ValueError("Page environment contains unsupported keys")
    if not page_env.get("EMAIL_RECOVERY_ADDRESS"):
        raise ValueError("The existing page environment must include EMAIL_RECOVERY_ADDRESS")
    if any(not isinstance(value, str) for value in page_env.values()):
        raise ValueError("Page environment values must be strings")
    own_cid = check_bundle(args.dist.resolve())
    config = json.loads((args.dist / "config.json").read_text())
    registry = config.get("pageBundleRegistry")
    if args.skip_registry_publication:
        if "pageBundleRegistry" in config:
            raise ValueError("Remove pageBundleRegistry when skipping staging publication")
    elif not registry or len(registry["rpcs"]) != 2 or registry["rpcs"][0] == registry["rpcs"][1]:
        raise ValueError("Page bundle registry requires two independent RPCs")
    archive = package(args.dist.resolve(), args.target, args.config, args.staging_origin)
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
        "name": project_name_value,
        "source": "tarball://" + project_name_value,
        "ref": ref,
        "runtime": "deno",
        "mode": "attested",
        "entry": "server.ts",
        "isolation": "shared",
        "env": {**page_env, "OPERATOR_TOKEN_SHA256":args.operator_token_sha256},
    }
    boundary = "private-agent-" + secrets.token_hex(16)
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
        + json.dumps(manifest).encode()
        + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="private-agent.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
        + archive
        + f"\r\n--{boundary}--\r\n".encode()
    )
    wait_for_idle(base, args.wait_idle_minutes)
    project = json.loads(api("/_api/projects", method="POST", body=body,
                             kind="multipart/form-data; boundary=" + boundary, auth=True))
    if project["runtime"] != "deno" or project["isolation"] != "shared":
        raise ValueError("Deployment did not select shared Deno")
    if project.get("mode") != "attested":
        wait_for_idle(base, args.wait_idle_minutes)
        project = json.loads(api("/_api/projects/" + project_name_value + "/promote", method="POST", auth=True))
    if project.get("mode") != "attested":
        raise ValueError("Deployment did not enter attested mode")
    for attempt in range(30):
        try:
            page = api("/" + project_name_value + "/")
            if page != (args.dist / "index.html").read_bytes():
                raise RuntimeError("Deployed page has not loaded the built index.html")
            break
        except (RuntimeError, URLError):
            if attempt == 29:
                raise
            time.sleep(2)
    if not args.skip_registry_publication:
        # Publish only after the new page is served; failed transactions propagate.
        subprocess.run(["cast", "send", "--rpc-url", registry["rpcs"][0], "--chain", "84532",
                        "--account", args.registry_account, registry["registry"], "publish(string)", own_cid], check=True)
        read_env = {key: value for key, value in os.environ.items()
                    if key not in {"ETH_PASSWORD", "ETH_KEYSTORE", "ETH_KEYSTORE_ACCOUNT"}}
        for rpc in registry["rpcs"]:
            published = subprocess.check_output(["cast", "call", "--rpc-url", rpc, "--chain", "84532",
                                               registry["registry"], "latestCID()(string)"], text=True, env=read_env).strip().strip('"')
            if published != own_cid:
                raise ValueError("Published bundle CID differs from deployed page")
    summary = {"bundleCID": own_cid, "registry": registry["registry"] if registry else None, "url": (staging_page_url(args.staging_origin) if args.target == "staging" else base + "/private-agent/"), "runtime": project["runtime"],
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
