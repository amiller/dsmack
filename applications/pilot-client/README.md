# Pilot client

Host-side pieces that install a signed alpha runtime on a participant's Mac, run
one task in the `browser-sandbox-v1` guest, verify the evidence on Linux and
retire scratch disks afterwards. `applications/bounties/runner` drives these
pieces for the live Arcade task.

| Path | Role |
| --- | --- |
| `alpha-bootstrap.mjs` | Checks the maintainer key and Node runtime, writes `bootstrap/` including `alpha_stage.py`. |
| `alpha_stage.py` | Authenticates a signed release inventory and unpacks its archive into the install root. |
| `alpha-release.mjs`, `alpha-release-cli.mjs`, `alpha-profile.mjs` | Release inventory/signature checks and profile selection, shared by bootstrap and coordinator. |
| `alpha_coordinator.py`, `alpha_signing_policy.py` | Entry point inside the installed release: `--prepare`, `--check-only`, `--execute`, `--resume` for one task. |
| `coordinator/` | Coordinator modules shipped in the release (signing policy, session parser, approved run, native helper). |
| `public_task.py` | Builds and inspects the public USTAR task disk. |
| `friend.py` | Operator-assisted single-invitation run (`inspect`, `prepare`, `check`, `run`, `resume`). |
| `retire-scratch.mjs` | Deletes the two scratch files of a finished attempt after the full verifier report and process quiescence check out. |
| `verifier-browser/` | Linux verifier; see `verifier/README.md`. |

Arcade setup invokes bootstrap and staging:

```sh
python3 -I applications/bounties/runner/setup.py --api URL --home DIR \
  --node /path/to/node --public-key maintainer.pem
```

Scratch retirement, as run by `bounties/runner/cleanup.py`:

```sh
node applications/pilot-client/retire-scratch.mjs /abs/selection.json SELECTION_SHA256
```

Tests:

```sh
node --test applications/pilot-client/*.test.mjs
python3 -m pytest applications/pilot-client
```

`workload/` prepares public workload disks and private credential inputs.
See its [README](workload/README.md).
