# Bounty runtime

The application layer that runs inside a bounty stage. It consumes the bridge's
nine semantic slots: `request`, `task_terms`, `acceptance_profile`, `plan`,
`stage_profile`, `driver`, `source_manifest`, `source_bundle`, `suite`.
Generation and primary omit `suite`. Every public file is a required read-only
workload slot covered by the whole `dsmack.task-commitment/3` object. Provider
credentials arrive in the private broker input and never appear in the public
projection.

Before work, `audit_stage.audit` checks four pins: the domain-separated request
SHA, and the raw SHA of the stage profile, trusted driver and plan. Child stages
use a `dsmack-bounty-child-request/1` request; primary uses the S0 request. Terms,
profile and source bytes are recomputed. Source bundles are bounded regular-only
USTAR with exact manifest membership and two terminators; the manifest binds
every source file's mode, length and content hash.

What each stage sees:

- Generation: the stage profile carries `specification: {text, sha256}`. The
  generator gets `base.json` (the three board assets projected from the full base
  tree) and `spec.txt`.
- Base/candidate browser stages: the same three board assets plus the selected
  generated suite.
- Primary: the full candidate projection, every app and fixture included. Its
  delivered archive and manifest are the original committed bytes.

The primary profile carries `admission_transform: {record, sha256}` in
`dsmack-bounty-admission-transform/2`: only existing-file replacements within the
three fixed board paths. The primary stage holds only the candidate tree, so the
coordinator decodes the retained base and candidate trees and recomputes
`admission_relation` before admitting stages.

`entrypoint.py` invokes the generator, browser or primary harness from fixed
image-owned paths. A measured thin launcher runs at `/workspace/inputs/driver`
with Python `-I -B`; implementation imports stay in the pinned image. Primary
projects the candidate under `/workspace/state/candidate-projection` and runs in
an initially empty `/workspace/state/primary-run`. Only the built-in state and
artifacts writable mounts are needed. After the child exits, the original
delivery and the public-input observation are exported with the other artifacts.
The generic base VM has no bounty-specific hooks.

Tests (no installs, browser or credentials):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s applications/bounty-runtime -p 'test_*.py'
```
