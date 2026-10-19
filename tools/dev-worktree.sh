#!/usr/bin/env bash
# Canonical private development worktree; never shares mutable build inodes.
set -euo pipefail
usage() { echo "usage: tools/dev-worktree.sh <name> [--copy-builds]" >&2; exit 2; }
[[ $# -ge 1 && $# -le 2 ]] || usage
name=$1
[[ $name =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ $# == 1 || $2 == --copy-builds ]] || usage
root=$(git -C "$(dirname "$0")" worktree list --porcelain | sed -n '1s/^worktree //p')
project=dsmack
configured=$(git -C "$root" config --get development.worktreeRoot || true)
parent=${DEV_WORKTREE_ROOT:-${configured:-${root}-worktrees}}
target="$parent/$name"
mkdir -p "$parent"
git -C "$root" worktree add -b "work/$name" "$target" main
if [[ ${2:-} == --copy-builds ]]; then
  python3 - "$root" "$target" <<'PY_COPY'
import glob, os, pathlib, shutil, sys
source, target = map(pathlib.Path, sys.argv[1:])
patterns = ['node_modules', 'pi/node_modules', 'pi/packages/*/dist', 'aci/node_modules', 'aci/*/dist', 'aci/*/dist-test', 'contracts/lib']
for pattern in patterns:
    for entry in glob.glob(str(source / pattern)):
        origin = pathlib.Path(entry)
        if origin.is_dir():
            for item in [origin, *origin.rglob('*')]:
                if item.is_symlink():
                    if pathlib.Path(os.readlink(item)).is_absolute():
                        raise SystemExit(f'Refusing absolute build symlink: {item}')
                    try:
                        item.resolve().relative_to(source.resolve())
                    except ValueError:
                        raise SystemExit(f'Refusing build symlink outside source checkout: {item}')
            destination = target / origin.relative_to(source)
            shutil.copytree(origin, destination, symlinks=True, dirs_exist_ok=False)
PY_COPY
fi
mkdir -p "$target/local-data"
if [[ $project == abalone ]]; then mkdir -p "$target/local-data/abalone"; fi
if [[ -f "$target/tools/hooks/pre-commit" ]]; then
  common=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)
  for hook in pre-commit post-commit; do
    if [[ -f "$target/tools/hooks/$hook" ]]; then
      # Preserve an existing hook; new installs dispatch in each worktree.
      if [[ ! -e "$common/hooks/$hook" ]]; then
        printf '#!/bin/sh\nexec tools/hooks/%s\n' "$hook" > "$common/hooks/$hook"
        chmod +x "$common/hooks/$hook"
      fi
    fi
  done
fi
printf 'Worktree: %s\nBranch: work/%s\n' "$target" "$name"
if [[ $project == abalone ]]; then
  printf 'Use isolated runtime state: export ABALONE_DIR=%q\n' "$target/local-data/abalone"
else
  printf 'Keep component state/output below %s/local-data; set each component state/output flag explicitly.\n' "$target"
fi
echo 'Credentials and live state were not copied. Install/build dependencies unless --copy-builds was used.'
