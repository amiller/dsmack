"""Safely extract an explicitly supplied reviewed dependency archive for CI."""
import argparse
from pathlib import Path
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('archive', type=Path)
parser.add_argument('destination', type=Path)
args = parser.parse_args()
if args.archive.stat().st_size > 2_000_000 or args.destination.exists():
    raise SystemExit('invalid paired source archive or destination')
with tarfile.open(args.archive, 'r:gz') as archive:
    members, size, names = [], 0, set()
    for member in archive:
        members.append(member); size += member.size
        if len(members) > 50 or size > 4_000_000:
            raise SystemExit('paired source archive exceeds bounds')
        parts = Path(member.name).parts
        if not member.isfile() or not parts or member.name.startswith('/') or '..' in parts:
            raise SystemExit('paired source archive requires regular relative files')
        normalized = str(Path(member.name))
        if normalized in names: raise SystemExit('duplicate paired source path')
        names.add(normalized)
    args.destination.mkdir(parents=True)
    # The package builder separately authenticates every selected source hash.
    for member in members:
        file = args.destination / member.name
        if file.exists(): raise SystemExit('duplicate paired source path')
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(archive.extractfile(member).read())
