#!/usr/bin/env python3
"""Check local Markdown links and heading fragments in first-party documentation.
Vendored component documentation keeps its upstream scope and is checked separately.
"""
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SKIP = ("contracts/lib/", "runner/verify/vendor/")
LINK = re.compile(r'!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)')

def prose(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match:
            marker = match[1][0]
            fence = None if fence == marker else marker
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)

def anchors(text):
    result, counts = set(), {}
    for heading in re.findall(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", prose(text), re.M):
        heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading).lower()
        slug = "".join(c for c in heading if c in "_- " or c.isalnum() or unicodedata.category(c).startswith("M")).replace(" ", "-")
        count = counts.get(slug, 0)
        result.add(slug + (f"-{count}" if count else ""))
        counts[slug] = count + 1
    return result

paths = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
errors, checked = [], 0
for name in sorted(set(paths)):
    source = ROOT / name
    if not name or source.suffix != ".md" or name.startswith(SKIP) or not source.is_file():
        continue
    text = prose(source.read_text())
    for match in LINK.finditer(text):
        target = match[1].strip("<>")
        url = urlsplit(target)
        if url.scheme or url.netloc:
            continue
        checked += 1
        dest = (source.parent / unquote(url.path)).resolve() if url.path else source
        if not dest.is_relative_to(ROOT):
            errors.append(f"{name}: outside repository: {target}")
        elif not dest.exists():
            errors.append(f"{name}: missing: {target}")
        elif url.fragment and dest.suffix == ".md" and unquote(url.fragment) not in anchors(dest.read_text()):
            errors.append(f"{name}: missing heading: {target}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"PASS {checked} local Markdown links and fragments in first-party documentation")
