#!/usr/bin/env python3
"""Verify a regular release artifact against independently chosen GitHub policy.

Runs trusted gh, never the downloaded artifact. No archive extraction or install.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from inspect_runner import read_regular


def command(gh, artifact, repository, workflow, tag, commit):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.ya?ml", workflow):
        raise ValueError("expected workflow filename only")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
        raise ValueError("expected versioned release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected full lowercase Git source commit")
    identity = f"https://github.com/{repository}/.github/workflows/{workflow}@refs/tags/{tag}"
    return [gh, "attestation", "verify", str(artifact), "--repo", repository,
            "--signer-workflow", f"{repository}/.github/workflows/{workflow}",
            "--cert-identity", identity,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--source-ref", f"refs/tags/{tag}", "--source-digest", commit,
            "--signer-digest", commit, "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"]


def checked_result(process, expected_sha256):
    if process.returncode != 0:
        raise ValueError("GitHub/Sigstore cryptographic verification rejected the artifact")
    data = json.loads(process.stdout)
    if not isinstance(data, list) or not data or any(not isinstance(x, dict) or
            not isinstance(x.get("verificationResult"), dict) for x in data):
        raise ValueError("missing or malformed verified attestation results")
    for entry in data:
        result = entry["verificationResult"]
        signature = result.get("signature")
        statement = result.get("statement")
        if not isinstance(signature, dict) or not signature.get("certificate") or not result.get("verifiedTimestamps"):
            raise ValueError("missing verified certificate/timestamp evidence")
        if not isinstance(statement, dict) or statement.get("predicateType") != "https://slsa.dev/provenance/v1":
            raise ValueError("wrong verified predicate type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not any(isinstance(s, dict) and
                isinstance(s.get("digest"), dict) and s["digest"].get("sha256") == expected_sha256
                for s in subjects):
            raise ValueError("verified statement has wrong artifact digest")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    for name in ("repository", "workflow", "tag", "commit", "expected-sha256"):
        parser.add_argument("--" + name, required=True)
    opts = parser.parse_args()
    try:
        gh = shutil.which("gh")
        if not gh:
            raise ValueError("trusted GitHub CLI >=2.102.0 is required")
        version = subprocess.run([gh, "--version"], check=True, capture_output=True,
                                 text=True, timeout=10)
        match = re.match(r"gh version (\d+)\.(\d+)\.(\d+)(?:\s|$)", version.stdout)
        if not match or tuple(map(int, match.groups())) < (2, 102, 0):
            raise ValueError("require stable gh >=2.102.0; earlier policy checks had identity/ref bugs")
        payload = read_regular(opts.artifact)
        actual = hashlib.sha256(payload).hexdigest()
        if actual != opts.expected_sha256:
            raise ValueError("artifact differs from independently obtained SHA-256 pin")
        with tempfile.TemporaryDirectory(prefix="dsmack-provenance-") as directory:
            snapshot = Path(directory) / "artifact.bin"
            snapshot.write_bytes(payload)
            snapshot.chmod(0o400)
            argv = command(gh, snapshot, opts.repository, opts.workflow, opts.tag, opts.commit)
            result = checked_result(subprocess.run(argv, check=False, capture_output=True,
                                                  text=True, timeout=180), actual)
        print(json.dumps({"schema": "dsmack-release-provenance-check/1", "verified": True,
                          "sha256": actual, "source_commit": opts.commit, "tag": opts.tag,
                          "workflow": opts.workflow, "repository": opts.repository,
                          "verified_attestations": result,
                          "artifact_executed": False}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
