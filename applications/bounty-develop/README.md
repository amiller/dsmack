# Pinned develop application

This application turns a typed S0 `develop` request (`candidate:null`) and an
immutable full base tree into a proposed candidate. It runs inside the existing
measured VM/container architecture. It does not change or sign the Mac app, select
a task, import credentials, authorize acceptance or claim a reward.

The measured launcher is `/workspace/inputs/driver`. Independently selected request,
stage-profile, driver and common-plan digests are mandatory flags. The eight public
semantic inputs and full base tree are checked before materialization. The exact
`dsmack-bounty-develop-profile/1` selects canonical `claude-opus-4-8`,480 seconds,
30 turns and `Read,Write,Edit,Glob,Grep,Bash`. No prior session, imported settings,
MCP configuration or hooks are loaded. Provider OAuth remains in the existing guest
broker; the child receives only a run-local sentinel capability.

The entrypoint requires UID/GID1000 and PID1 in a private Linux container PID
namespace. Before any subprocess it sets and verifies Linux nondumpable mode
for the trusted parent, rather than relying on same-UID ptrace defaults. The
container must not grant SYS_PTRACE or privileged mode. After Claude exits it kills and confirms the absence of every other
live process in that namespace before reading candidate source. Unknown or foreign
process identity refuses capture. This requires the ordinary private PID namespace
from the generic runner; host PID sharing and an injected init process are not
supported. The external VM/container deadline remains independent.

Candidate delivery uses the existing strict source-tree and USTAR grammar. Only
replacements of existing `apps/board/index.html`, `apps/board/logic.js` and
`apps/board/ui.js` are admissible; no additions, deletions or mode changes. A
successful CLI exit with no admissible change is infrastructure/unknown, not task
success. The external admission adapter must reconstruct the relation from both
retained trees; job-authored JSON grants no authority.

Outputs include the original bounded transcript, exact observed model identity,
full candidate manifest/bundle and transform2. They use the reviewed flat result
bundle with native `result-files`, `stage-checks`, `public-input-audit` exports.
Any provider error, turn/deadline bound, model mismatch, output overflow or uncertain
writer shutdown returns exit2 with incomplete checks. A completed develop run does
not establish acceptance: the independent ten-stage review follows separately.

Build on Zed `/data` only with an independently selected CAND7 generator parent.
The Dockerfile installs no dependencies. Source tests use synthetic CLI results and
never contact a provider:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s applications/bounty-develop -p 'test_*.py'
```

Actual model execution, private input staging and native launch require a separately
selected request, image, nonce and operator admission. This source has not yet been
qualified with a real model or native Mac run.
