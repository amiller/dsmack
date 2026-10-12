"""Slot -5 probe: does macOS honour XML entitlements (slot -5) that differ from the DER blob (slot -7)?
M binds slot -7 only (scripts/release/measure.py). Run on macOS 27 in an empty directory:
  python3 slot5_probe.py <repo> <workdir>
Builds node/tests/EntitlementProbe.swift, signs it ad hoc with hardened runtime and
{get-task-allow: false, cs.disable-library-validation: false} (custom keys are restricted and
AMFI kills ad hoc code that has them), then rewrites only the XML blob to both true, updates slot -5 in the CodeDirectory
(new ad hoc CDHash) and runs both copies. M is unchanged by the edit.

Result on macOS 27.0 (26A428), mini, 2026-10-12: slot -5 is ignored.
codesign --verify --strict accepts the patched copy. In both copies the kernel's
CS_OPS_ENTITLEMENTS_BLOB returns XML regenerated from the DER blob (both <false/>),
SecTaskCopyValueForEntitlement returns false for both keys, the CS status is 0x22011311 with
CS_GET_TASK_ALLOW clear, and codesign -d --entitlements prints the DER values. So M does not bind
slot -5. Not covered: restricted entitlements under a provisioning profile."""
import base64, hashlib, json, os, plistlib, shutil, struct, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from measure import inputs, measure

def run(*a, **k): return subprocess.run(a, check=True, capture_output=True, text=True, **k)

def patch_xml(path, out):
    b = bytearray(open(path, "rb").read())
    x = inputs(path); cd = x["cd"]
    dataoff = struct.unpack_from("<I", b, x["S"] + 8)[0]
    sb = dataoff; n = struct.unpack_from(">I", b, sb + 8)[0]
    blobs = {struct.unpack_from(">I", b, sb + 12 + 8 * i)[0]: sb + struct.unpack_from(">I", b, sb + 16 + 8 * i)[0] for i in range(n)}
    xo = blobs[5]; assert struct.unpack_from(">I", b, xo)[0] == 0xfade7171
    xl = struct.unpack_from(">I", b, xo + 4)[0]
    xml = bytes(b[xo + 8:xo + xl])
    new = xml.replace(b"<false/>", b"<true/> ")
    assert len(new) == len(xml) and new != xml
    b[xo + 8:xo + xl] = new
    co, off = blobs[0], struct.unpack_from(">I", cd, 0x10)[0]
    b[co + off - 160:co + off - 128] = hashlib.sha256(bytes(b[xo:xo + xl])).digest()
    open(out, "wb").write(b); os.chmod(out, 0o755)

def probe(exe):
    x = inputs(exe)
    r = subprocess.run([exe], capture_output=True, text=True)
    out = {"cdhash": hashlib.sha256(x["cd"]).hexdigest(), "M": measure(**x).hex(), "exit": r.returncode, "stderr": r.stderr.strip()[-300:],
           "verify": subprocess.run(["codesign", "--verify", "--strict", "-v", exe], capture_output=True, text=True).stderr.strip(),
           "codesignEntitlements": subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", exe], capture_output=True, text=True).stdout}
    if r.returncode == 0:
        p = json.loads(r.stdout)
        for k in ("xmlBlob", "derBlob"):
            if p[k] != "empty" and not p[k].startswith("csops"): p[k] = base64.b64decode(p[k]).decode("latin1")
        out["process"] = p
    return out

if __name__ == "__main__":
    repo, work = map(os.path.abspath, sys.argv[1:3])
    os.makedirs(work, exist_ok=True)
    exe, patched = os.path.join(work, "entitlement-probe"), os.path.join(work, "entitlement-probe-xml-patched")
    env = dict(os.environ, TMPDIR=work)
    run("xcrun", "swiftc", "-O", "-module-cache-path", os.path.join(work, "mc"), os.path.join(repo, "node/tests/EntitlementProbe.swift"), "-o", exe, env=env)
    ent = os.path.join(work, "probe.entitlements")
    plistlib.dump({"com.apple.security.get-task-allow": False, "com.apple.security.cs.disable-library-validation": False}, open(ent, "wb"))
    run("codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", ent, "--generate-entitlement-der", exe, env=env)
    patch_xml(exe, patched)
    json.dump({"original": probe(exe), "xmlPatched": probe(patched)}, sys.stdout, indent=1); print()
