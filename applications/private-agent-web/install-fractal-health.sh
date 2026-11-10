#!/bin/bash
# Run from the laptop after Andrew establishes the Fractal SSH master.
set -euo pipefail
app=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$app/../.." && pwd)
remote='dsmack-directory-health'
ssh fractal "mkdir -p ~/$remote/applications/private-agent-web ~/$remote/applications/browser-p2p ~/$remote/bin"
rsync -a --bwlimit=20000 \
  "$app/directory-health.mjs" "$app/chain-directory.mjs" "$app/directory-notify.sh" \
  "$app/install-directory-health.py" "fractal:$remote/applications/private-agent-web/"
rsync -a --bwlimit=20000 "$repo/applications/browser-p2p/tunnels.mjs" "fractal:$remote/applications/browser-p2p/"
if ssh fractal 'command -v deno >/dev/null'; then
  ssh fractal "python3 ~/$remote/applications/private-agent-web/install-directory-health.py"
else
  test "$(ssh fractal uname -m)" = x86_64
  rsync -a --bwlimit=20000 "$HOME/.deno/bin/deno" "fractal:$remote/bin/deno"
  ssh fractal "python3 ~/$remote/applications/private-agent-web/install-directory-health.py --deno \$HOME/$remote/bin/deno"
fi
# Confirm the real Matrix transport on the credential-owning host.
ssh fractal "~/$remote/applications/private-agent-web/directory-notify.sh 'Dsmack staging capacity FAILED (installation test): simulated empty target.'"
ssh fractal "~/$remote/applications/private-agent-web/directory-notify.sh 'Dsmack staging capacity RECOVERED (installation test): notification transport verified.'"
