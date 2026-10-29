#!/usr/bin/env python3
"""Prepare local webhost upload packages and compare public deployment keys."""
import argparse
import ast
import difflib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

APP = Path(__file__).resolve().parent
REPO = APP.parents[1]
SECRET_FIELDS = {"near_management_token", "near_reporting_token", "managementtoken",
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
    args.out.mkdir(parents=True, exist_ok=True)
    for name in ("relay-broker.tgz", "relay-broker.manifest.json"):
        if (args.out / name).exists():
            raise ValueError("output already exists; choose a fresh preparation directory")
    ref = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    # A list of credential NAMES belongs in the manifest; values belong in the CVM.
    manifest = {"name": "relay-broker", "source": "tarball://relay-broker", "ref": ref,
                "runtime": "deno", "entry": "applications/relay-broker/server.ts", "isolation": "shared",
                "env": {"OPERATOR_TOKEN_SHA256": args.operator_token_sha256},
                "env_passthrough": ["NEAR_MANAGEMENT_TOKEN", "NEAR_REPORTING_TOKEN"]}
    if not (APP / "inference.mjs").is_file():
        raise ValueError("inference module is missing")
    with tempfile.TemporaryDirectory(prefix="inference-package-") as temporary:
        bundled = Path(temporary) / "schema.mjs"
        subprocess.run(["deno", "bundle", "--platform=browser", "--minify",
                        str(REPO / "applications/payments/schema.mjs"), "-o", str(bundled)], check=True)
        with tarfile.open(args.out / "relay-broker.tgz", "x:gz") as archive:
            for source in sorted(APP.iterdir()):
                if source.suffix in (".mjs", ".ts") and source.name != "near-attestation.mjs" and not source.name.endswith((".test.mjs", ".test.ts", "_test.ts")):
                    archive.add(source, arcname="applications/relay-broker/" + source.name)
            for name in ("quorum.mjs", "admission.mjs"):
                archive.add(REPO / "applications/payments" / name, arcname="applications/payments/" + name)
            archive.add(bundled, arcname="applications/payments/schema.mjs")
            if (APP / "near-attestation.mjs").is_file():
                attestation = Path(temporary) / "near-attestation.mjs"
                subprocess.run(["deno", "bundle", "--platform=deno", "--minify",
                                str(APP / "near-attestation.mjs"), "-o", str(attestation)], check=True)
                archive.add(attestation, arcname="applications/relay-broker/near-attestation.mjs")
            archive.add(APP / "project.json", arcname="project.json")
            archive.add(REPO / "dstack-compat/secret-release/policy.mjs",
                        arcname="dstack-compat/secret-release/policy.mjs")
            body = json.dumps(config).encode()
            info = tarfile.TarInfo("applications/relay-broker/config.json")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    write_json(args.out / "relay-broker.manifest.json", manifest)
    if args.private_agent_source:
        source = args.private_agent_source.resolve()
        project = json.loads((source / "project.json").read_text())
        public_config(project)
        if project.get("runtime") not in ("static", "deno"):
            raise ValueError("private-agent project.json must select static or deno")
        if project.get("env"):
            raise ValueError("private-agent package must have no environment credential values")
        excluded = {".git", "node_modules", "target", "local-data", "__pycache__"}
        with tarfile.open(args.out / "private-agent.tgz", "x:gz") as archive:
            for path in sorted(source.rglob("*")):
                relative = path.relative_to(source)
                if any(part in excluded for part in relative.parts):
                    continue
                if path.is_symlink():
                    raise ValueError("private-agent source cannot contain symlinks")
                if path.is_file():
                    if path.name.startswith(".env") or path.suffix in (".key", ".pem"):
                        raise ValueError("private-agent source contains a credential filename")
                    archive.add(path, arcname=str(relative), recursive=False)
        write_json(args.out / "private-agent.manifest.json", {
            "name": "private-agent", "source": "tarball://private-agent", "ref": ref,
            "runtime": project["runtime"], "entry": project.get("entry", "." if project["runtime"] == "static" else "server.ts"),
            "isolation": "shared", "env": {}})
    print("Prepared local upload files in " + str(args.out))


def snapshot(args):
    root = args.url.rstrip("/")
    result = {}
    for name, path, fields in (
        ("broker", "/relay-broker/key", ("algorithm", "public_key")),
        ("payments", "/relay-broker/payments/key", ("algorithm", "address", "escrow", "codeHash")),
        ("secret_release", "/secret-release/public-key", None),
        ("secret_release_project", "/_api/projects/secret-release", ("name", "runtime", "isolation", "tree_hash", "ref", "deployed_at")),
    ):
        with urlopen(root + path, timeout=30) as response:
            value = json.load(response)
        result[name] = {key: value.get(key) for key in fields} if fields else value
    write_json(args.out, result)
    print("Saved public deployment snapshot to " + str(args.out))


def compare(args):
    before, after = (json.loads(path.read_text()) for path in (args.before, args.after))
    for field in ("broker", "secret_release", "secret_release_project"):
        if before[field] != after[field]:
            raise ValueError(field + " changed")
    for field in ("algorithm", "address"):
        if before["payments"][field] != after["payments"][field]:
            raise ValueError("payment signing identity changed")
    if before["payments"].get("escrow") != after["payments"].get("escrow"):
        if not args.expected_escrow or after["payments"].get("escrow", "").lower() != args.expected_escrow.lower():
            raise ValueError("payment escrow changed without the expected new token escrow")
    elif before["payments"].get("codeHash") != after["payments"].get("codeHash"):
        raise ValueError("existing payment escrow code hash changed")
    print("Broker signing identities and secret-release are unchanged")


def env_bridge(args):
    """Write an unapplied webhost patch; source and credentials stay untouched."""
    source = (args.webhost_source / "proxy/runtimes.py").read_text()
    old_router = '      envs.set(entry.name, manifest.env || {});'
    new_router = '''      const handlerEnv = { ...(manifest.env || {}) };
      for (const name of manifest.env_passthrough || []) {
        const value = Deno.env.get(name);
        if (value !== undefined) handlerEnv[name] = value;
      }
      envs.set(entry.name, handlerEnv);'''
    old_container = '''            cid = await self.docker.create_container(
                cname, config["image"], cmd, binds, labels, network,
                runtime="")'''
    new_container = '''            # Resolve only requested daemon variables, without persisting their
            # values in project manifests or generated router source.
            passthrough = []
            if config_key in ("deno", "bun"):
                names = {name for project in mode_projects
                         for name in (project.env_passthrough or [])}
                passthrough = [f"{name}={os.environ[name]}"
                               for name in sorted(names) if name in os.environ]
            cid = await self.docker.create_container(
                cname, config["image"], cmd, binds, labels, network,
                runtime="", env=passthrough)'''
    if source.count(old_router) != 1 or source.count(old_container) != 1:
        raise ValueError("webhost source differs; inspect its shared runtime before preparing the bridge")
    changed = source.replace(old_router, new_router).replace(old_container, new_container)
    ast.parse(changed)
    patch = "".join(difflib.unified_diff(source.splitlines(True), changed.splitlines(True),
                                      fromfile="a/proxy/runtimes.py", tofile="b/proxy/runtimes.py"))
    with args.out.open("x") as output:
        output.write(patch)
    print("Prepared unapplied webhost environment bridge patch in " + str(args.out))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("prepare", help="local packaging only; never uploads")
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--operator-token-sha256", required=True)
    p.add_argument("--private-agent-source", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(run=prepare)
    p = sub.add_parser("snapshot", help="read public endpoints; no authentication")
    p.add_argument("--url", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(run=snapshot)
    p = sub.add_parser("compare")
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("--expected-escrow")
    p.set_defaults(run=compare)
    p = sub.add_parser("prepare-env-bridge", help="write an unapplied patch for the existing shared Deno runtime")
    p.add_argument("--webhost-source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(run=env_bridge)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
