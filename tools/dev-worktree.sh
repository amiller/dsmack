#!/usr/bin/env bash
# Create a development worktree on branch work/<name> from main.
set -euo pipefail
[[ $# == 1 && $1 =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "usage: tools/dev-worktree.sh <name>" >&2; exit 2; }
root=$(git -C "$(dirname "$0")" worktree list --porcelain | sed -n '1s/^worktree //p')
parent=${DEV_WORKTREE_ROOT:-$(git -C "$root" config --get development.worktreeRoot || echo "${root}-worktrees")}
target="$parent/$1"
mkdir -p "$parent"
git -C "$root" worktree add -b "work/$1" "$target" main
mkdir -p "$target/local-data"
printf 'Worktree: %s\nBranch: work/%s\n' "$target" "$1"
