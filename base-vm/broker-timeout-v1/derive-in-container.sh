#!/bin/bash
set -euo pipefail
umask 0022
LEG=/w/build/legs/diagnostic
[ ! -e "$LEG" ] && [ ! -L "$LEG" ]
mkdir -p "$LEG/files" "$LEG/work"
printf '%s\n' 'f20ef2e7fe1bd743258de97c9471ae62aec7cd4ec929be170320804818ace952  /prior-image/rootfs.squashfs.verity' 'c7e9e1d37253e05c1d756231aa7171808985a566366a9a646cb69b7807afba07  /w/sentinel.py' | sha256sum -c -
unsquashfs -no-progress -processors 4 -d "$LEG/work/rootfs" /prior-image/rootfs.squashfs.verity
TARGET="$LEG/work/rootfs/usr/local/lib/dsmack/sentinel/harness/sentinel/sentinel.py"
printf '%s  %s\n' '4cbd5f439cca3f899533e4c2e8ac1674c798a69b4b9a881eaa2f11234b0bc06b' "$TARGET" | sha256sum -c -
install -m0644 /w/sentinel.py "$TARGET"
# Preserve all unrelated inventory bytes; update only the changed source row.
python3 - "$LEG/work/rootfs/usr/local/lib/dsmack/sentinel/SHA256SUMS" <<'PY_INVENTORY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);b=p.read_bytes()
old=b'4cbd5f439cca3f899533e4c2e8ac1674c798a69b4b9a881eaa2f11234b0bc06b  ./harness/sentinel/sentinel.py'
new=b'c7e9e1d37253e05c1d756231aa7171808985a566366a9a646cb69b7807afba07  ./harness/sentinel/sentinel.py'
if b.count(old)!=1:raise SystemExit('sentinel inventory row mismatch')
p.write_bytes(b.replace(old,new))
PY_INVENTORY
cp /prior-image/Image /prior-image/config-6.18.40-dstack "$LEG/files/"
bash /w/source/build/assemble_leg.sh diagnostic
chmod 0644 "$LEG/files/"*
