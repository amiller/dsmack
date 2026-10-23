# One local invitation, one credential-free run

The operator-assisted starter uses the existing signed runner and alpha runtime.
It needs no Claude subscription, bounty claim or payment. It still needs an
authenticated installation and this Mac's independently verified enrollment and
fresh admitted task. The operator supplies **one local `invitation.json` and its
SHA-256 through an independently trusted channel** after those prerequisites.
The existing [handoff procedure](operator-assisted-mac.md) explains that exchange.

Use the reviewed checkout and trusted Python 3. Replace `OPERATOR_DIGEST` with
the supplied invitation digest; do not calculate your own expected value from an
untrusted invitation:

```sh
python3 -I applications/pilot-client/friend.py inspect invitation.json --sha256 OPERATOR_DIGEST
python3 -I applications/pilot-client/friend.py prepare invitation.json --sha256 OPERATOR_DIGEST
python3 -I applications/pilot-client/friend.py check invitation.json --sha256 OPERATOR_DIGEST
python3 -I applications/pilot-client/friend.py run invitation.json --sha256 OPERATOR_DIGEST
```

Inspect authenticates the installed release and workload admission and uses the
original full public-payload checker. Prepare/check use the existing coordinator;
they do not launch a VM. Run delegates its once-only execute route. To observe the
same attempted run later, use `resume` with the same invitation and digest. A
lost connection or nonzero return never grants permission to launch again.
Check/run/resume also require the existing plan's complete task and release
bindings to match that invitation; a valid plan for a different task is refused.

The adapter accepts only the selected primary starter aliases, public profile/2,
task/2, network disabled and no credential/environment inputs. It does not
download or install software, enroll a device, issue a challenge, change a policy,
run a model or contact a bounty/payment service. Other workloads need their own
reviewed interface, not a command or profile override here.

## What the one-file handoff contains

`dsmack-friend-invitation/1` has exactly these fields:

| Field | Operator-selected value |
| --- | --- |
| `native_execution_id`, `profile_id` | Fresh execution identity and the signed credential-free starter profile |
| `install_root`, `run_parent` | Actual protected absolute directories on this Mac |
| `bootstrap`, `inventory`, `signature`, `task` | Each an exact `{path, bytes, sha256}` descriptor |

The task binds the public workload disk, signed admission, signature, closure and
checker contexts, enrolled key ID and fresh challenge. All paths are local; there
is no executable command string, private-input field or approval override in the
invitation. The file cannot be transplanted from the qualification Mini to another
Mac. The operator must bind that participant's actual paths and enrollment.

Use the existing [bootstrap CLI](alpha-install.md) to record the participant's
trusted local Node 24/runtime closure. Do not distribute the Mini's bootstrap
paths or loaded-library list as universal setup. The maintainer's signing keys,
service token, replay state and enrollment authority stay with the operator.

## Keep the real proof

After controller exit, `friend-summary-NATIVE_ID.json` records the invitation
digest, controller return code and original output directory. It deliberately says
`operator-verification-required`; **that summary is not cryptographic proof**.
Keep the complete original evidence. The operator transports it and performs the
original full verification, then supplies the signed report, independently selected
context and retained public evidence for the existing
[Linux x86-64 offline check](operator-assisted-mac.md#one-task-and-its-proof).
The Mac adapter does not implement that Linux verifier.

Execution evidence, matching the pinned expected outcome, application acceptance
and payment are distinct. This starter makes no payout claim. After evidence is
preserved, the operator confirms VM/helper quiescence and performs bounded cleanup;
do not delete originals, credentials, queued inputs or uncertain VM state.
