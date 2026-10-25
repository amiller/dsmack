"""Solc standard JSON input for the deployed registry contracts, with repo-relative source names. Run from the checkout root."""
import json, posixpath, re, sys
from pathlib import Path
REMAP = {"attest/": "app-attest/contracts/src/"}
def resolve(frm, imp):
    for k, v in REMAP.items():
        if imp.startswith(k): return v + imp[len(k):]
    assert imp.startswith("."), imp
    return posixpath.normpath(posixpath.join(posixpath.dirname(frm), imp))
srcs, todo = {}, ["contracts/src/CDRegistry.sol", "contracts/src/AppleAttestRegistryV1.sol", "contracts/src/Canary.sol"]
while todo:
    p = todo.pop()
    if p in srcs: continue
    t = Path(p).read_text(); srcs[p] = {"content": t}
    todo += [resolve(p, m) for m in re.findall(r'import\s+(?:\{[^}]*\}\s+from\s+)?"([^"]+)"', t)]
sys.stdout.write(json.dumps({"language": "Solidity", "sources": dict(sorted(srcs.items())), "settings": {
    "remappings": ["attest/=app-attest/contracts/src/"], "optimizer": {"enabled": True, "runs": 200}, "viaIR": True,
    "evmVersion": "shanghai", "metadata": {"bytecodeHash": "ipfs", "appendCBOR": True},
    "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}}}}))
