# Develop application

This application takes a typed S0 `develop` request (`candidate:null`) and an
immutable full base tree, runs Claude Code inside the measured VM/container, and
returns a proposed candidate. Review of the candidate is a separate ten-stage
run (see `applications/bounty-judges`).

## Runtime

The measured launcher is `/workspace/inputs/driver`. Request, stage-profile,
driver and common-plan digests are mandatory flags. The eight public semantic
inputs and the full base tree are checked before materialization. The exact
`dsmack-bounty-develop-profile/1` selects canonical `claude-opus-4-8`, 480 seconds,
30 turns and `Read,Write,Edit,Glob,Grep,Bash`. No prior session, imported
settings, MCP configuration or hooks are loaded. Provider OAuth stays in the
guest broker; the child receives only a run-local sentinel capability.

The entrypoint requires UID/GID1000 and PID1 in a private Linux container PID
namespace (the generic runner's default; host PID sharing and an injected init
are refused). Before any subprocess it sets and verifies Linux nondumpable mode
for the trusted parent. The container must not have SYS_PTRACE or privileged
mode. After Claude exits, the parent kills every other live process in the
namespace and confirms they are gone before reading candidate source; an unknown
process identity refuses capture. The VM/container deadline applies on top.

Candidate delivery uses the strict source-tree and USTAR grammar. The only
admissible changes are replacements of `apps/board/index.html`,
`apps/board/logic.js` and `apps/board/ui.js`: no additions, deletions or mode
changes. A successful CLI exit with no admissible change is an
infrastructure/unknown outcome. The admission adapter reconstructs the relation
from both retained trees and ignores job-authored JSON.

Outputs are the bounded transcript, the observed model identity, the full
candidate manifest/bundle and transform2, in the flat result bundle with native
`result-files`, `stage-checks` and `public-input-audit` exports. A provider error,
turn/deadline bound, model mismatch, output overflow or uncertain writer shutdown
exits 2 with incomplete checks.

Build on Zed `/data` with the CAND7 generator parent; the Dockerfile installs no
dependencies. Source tests use synthetic CLI results and never contact a provider:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s applications/bounty-develop -p 'test_*.py'
```

## Host helpers

Run with `python3 -I`.

- `substring_inputs.py`, `transport_v2_inputs.py`, `paid480_inputs.py`,
  `guided_inputs.py`, `serialization_inputs.py`: lower a task's public
  documents into stage inputs (`fixtures/<task>/`).
- `build_public.py`: build the public develop disk on Zed from a preparation,
  OCI layout and guest transport source.
- `export_subscription.py --source FILE --emit-credential-stdout`: emit only the
  Claude subscription auth fields to a pipe.
- `credential_health.py` / `models_health.py --source FILE --validator-source
  reference/claude_subscription_document.py`: one OAuth profile or `/v1/models`
  request, status only.
- `renew_private.py --source FILE --out NEW --oauth-source FILE --validator-source
  reference/claude_subscription_document.py`: one-shot token refresh into a new file.

## Preparing a run

Before importing OAuth, the requester policy and Store terms are selected, the
task is funded and durably claimed, and the complete request/manifest is chosen.

`prepare.py` takes the eight public files and fixed request, profile, driver and
plan hashes. It audits the full base and emits a manifest and a public-file
projection. The projection has no broker credential; `stage_private.py` adds it.

`build_public.py` runs on Zed `/data` and puts the pinned f62b develop OCI layout
on the new disk. It verifies the OCI layout with the publisher code, normalizes
only its repository annotation, and checks the manifest consumes that exact
loopback repository and digest. The measured disk holds only public channels:
manifest, admitted base bytes, OCI, closure context and the files-only task
commitment declaration. It has no develop envelope in `public-inputs`,
`envelopes` or `broker`.

`stage_private.py` (run with `python3 -I -B`) reads the credential document on
stdin after public inputs, source pins and private namespace checks pass. It
uses the strict subscription schema, requires at least 1200 seconds of remaining
token lifetime before and after staging, and adds only the broker-audience env
value to the full runtime envelope. The same canonical credential goes to the
guest-root sentinel. The private packer and guest parser validate the resulting
transport. No other client may refresh this subscription during the run.

The owned `0700` output namespace keeps `0600` private files and the private
image, including after a refusal once staging has started. These bytes are
private: they never go into public evidence or a checksum inventory. The report
contains only public hashes, a lifetime count and presence flags. Staging trusts
the host user: Python memory is not erased, and another process running as the
same user can read the files.

The default `linux-memfd-v1` backend uses Linux sealed descriptors. On a Mac,
pass `darwin-owned-tempfile-v1`, the portable module and an owned `0700`
temporary parent; the backend is never chosen automatically. The portable source
is pinned and initialized before any credential is read. It keeps the same wire
format and guest parser, using unlinked owned temporary files in place of kernel
write seals. Keep the credential on the subscriber's Mac.

The original subscription-document source is kept under `reference/`. The
transport loader verifies and compiles the selected raw source bytes, including
its private reader dependencies, and does not execute bytecode caches. The
operator provides source ownership, the interpreter/library closure and a stable
staging directory. Nothing is downloaded or signed automatically.

## Generation reliability diagnostic

`diagnose_generation_reliability.py` measures how often the generator finishes.
It is nonfunded and produces no suite for a bounty. It loads the pinned image's
`generate.py` into a fresh private module, changes only its process observer and
wall allowance (180 to 480 seconds), and reuses its CLI 2.1.187, Opus 4.8, two
turns, candidate-blind prompt, environment, model observer and strict suite
validator.

The manifest measures three readonly files: the driver and the held GEN1
`base.json` and `spec.txt`. Mount them flat at
`/workspace/inputs/{driver,base.json,spec.txt}` and invoke
`--public /workspace/inputs --flat-public --snapshot-sha256` with the held
snapshot digest. After the empty-state checks, only the bounded base/spec bytes
are copied to a fresh closed public directory; extra flat files are ignored.
Public copies and raw output are removed before export. The profile uses compose
timeout 550, native 600, and the existing B44/d912/app.

Only `generation-reliability.json` is exported: counts, booleans, coarse
outcome/exit categories, byte counts and elapsed milliseconds. Timestamps are
CLI-observed event arrival, since the broker buffers SSE. No exception text,
endpoint, token, header, event content, prompt or suite is exported. The run
returns 0 when observation completes, even if generation fails;
`bounty_acceptance` is false.

Budget: about 54 seconds boot + 480 generation + 10 CLI version probe + 5 reap +
5 validator + 5 export = 559 seconds, 41 under native 600. The broker limits
(upstream 210, handler 220, idle 10) still apply, so one API request may close
before 480 seconds. On timeout the owned CLI group is killed and reaped.

```sh
python3 -B applications/bounty-develop/test_generation_reliability.py
```

## paid480 fixtures

`fixtures/paid480/` holds the public task documents and the bounty-arcade source
projection so the lowering tests run from this repository alone.
`policy.json` and `terms.json` select the paid480 version. The tests create synthetic claim IDs and nonces in memory.

```sh
python3 -B applications/bounty-develop/test_paid480_lowering.py
```

It runs offline and removes its temporary files on exit.
