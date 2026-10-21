import json, subprocess
from pathlib import Path

pin = json.loads((Path(__file__).resolve().parent / "verifier/pin.json").read_text())
for tool in ("nargo", "bb"):
    actual = subprocess.check_output([tool, "--version"], text=True).splitlines()[0].split()[-1]
    assert actual == pin[tool], (tool, actual, pin[tool])
