# Portable arcade pilot runner

This is a **new deterministic browser-only testnet bonus**, not the published
three-judge Bounty Arcade reward. No model/subscription credentials are used.
The existing signed Mac app and Linux B44 remain unchanged. Wallet, task,
registration, queue and settlement logic remain outside the app.

These sources are an implementation candidate: offline tests do not establish
live registration, valid execution, payout or hostile-host result integrity.
Independent review and actual public-API qualification are required before release.
An enrolled Mini test also does not qualify first-open on another normally secured
Mac. Do not disable Gatekeeper or strip quarantine.

## Worker-owned Mac

Prerequisites: Apple silicon/macOS27+, trusted Python3 and Node24, enough disk for
one expanded runtime, public task and working disks plus12GiB reserve. Obtain the
maintainer public key independently (SHA256
`4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df`).
The service must first publish the reviewed signed runtime in `GET /api/task`.

From this source directory, replace only the deployment origin and local Node path:

```sh
python3 -I setup.py --api https://PUBLISHED-PILOT-ORIGIN \
  --home "$HOME/.dsmack-arcade" --node /PATH/TO/TRUSTED/NODE24 \
  --public-key /PATH/TO/INDEPENDENTLY-CHECKED/release-public.pem
```

Setup authenticates the runtime, derives this Mac's bootstrap/paths and installs
one selected runtime. It does not create a key or launch a VM. It never downloads
an interpreter. Partial installs are retained and never overwritten automatically.

Use `client.py --config "$HOME/.dsmack-arcade/client.json" COMMAND ...`:

1. `authorization --purpose registration --payee 0xYOURADDRESS --out REG-AUTH.json`
   obtains the exact domain/task/policy/payee/nonce/expiry-bound wallet message.
   Sign that message in your own wallet and save only its signature in a file.
2. `register --authorization REG-AUTH.json --wallet-signature REG-SIGNATURE.txt
   --out REGISTRATION.json` generates a fresh key through the existing signed
   app's LaunchServices enrollment mode and submits its original Apple attestation.
   Registration is automatic under the common app policy, with no worker allowlist.
   A queued registration is not an admitted key; inspect
   `GET /api/registrations/REGISTRATION_ID` for its actual terminal result.
3. Obtain/sign an `authorization --purpose attempt --payee 0xYOURADDRESS
   --candidate-commit FULL40HEXCOMMIT --out ATTEMPT-AUTH.json`, then
   `attempt --authorization ATTEMPT-AUTH.json --wallet-signature ATTEMPT-SIGNATURE.txt
   --out ATTEMPT.json`. No wallet private key enters this client or the service.
4. `prepare --attempt ATTEMPT.json --registration REGISTRATION.json` requests the
   server's closed signed task. If preparation is pending, inspect status and
   repeat the same prepare request; it reuses its saved request id. The client
   downloads only hash-bound public inputs, makes its own local task/2 paths and
   invokes the original coordinator's full prepare checks.
5. `check --attempt ATTEMPT.json`, `run --attempt ATTEMPT.json`, then
   `submit --attempt ATTEMPT.json`. `resume` observes the same attempted run;
   it never implicitly launches again. Original21 are retained and uploaded in
   bounded chunks; the same server full verifier/checker decides either route.
6. After status contains a complete full verdict, `cleanup --attempt ATTEMPT.json`
   authenticates the original signed report, confirms owned helper quiescence,
   invokes unchanged guarded scratch retirement and retires only four exact public
   copies. Original evidence, credentials, archive and active runtime remain.
   Record `CLEANUP-COMPLETE.json` before another test. Refusal means preserve state,
   not broaden deletion. This is storage hygiene, not secure erase.

The exact candidate commit is fetched from the single published repository.
The executable candidate is explicitly **frozen base39 files plus only its three
`apps/board/{index.html,logic.js,ui.js}` files**. Candidate package/test/runtime files
are not executed or imported. The signed task binds both requested commit and
canonical projected-tree hash. A protected driver runs frozen tests on baseline
and candidate sequentially in one VM, requiring typed baseline assertion failure
and all candidate assertions passing; crashes/timeouts never count as baseline success.

## Optional best-effort route

A participant can request `prepare --attempt ATTEMPT.json --mode best_effort`
without a Mac registration. This queues an optional execution, not a service or
reward guarantee. The maintainer's Mac is a normal registered node:

```sh
python3 -I node_worker.py --config LOCAL-CLIENT.json \
  --registration LOCAL-NODE-REGISTRATION.json --wait-seconds 600
```

It leases one prepared task through the public API with its private node capability,
runs the same portable coordinator, submits the same original21 and awaits the same
full verdict. Evidence-preserving cleanup is mandatory before a next lease. The
participant's payee/candidate stay immutable; the node cannot redirect the reward.

## Zed service bridge

`worker.py` polls the public HTTPS lease API with a separate protected root worker
credential. The web pod holds no Apple verifier, release private key or report key.
`configure.py` creates private goal-owned configs/stores, signing disabled initially.
The worker runs only pinned handlers and config; uncertain enrollment/challenge/
verification/signing actions are never repeated automatically. Completed results
can be posted again only from their retained matching cache.

`server_adapter.py` invokes the original selected Linux verifier CLI. The selected
`task_factory.py` resolves repository source, freezes checker/runtime inputs and
uses the qualified public packer. `authority.py` can sign only the factory-derived
workload admission under an explicitly authorized config and the existing release
key, kept on Zed. `prepare_release.py` prepares unsigned manifest/profile/provenance
changes around the existing app/base; it neither signs nor installs.

A full verifier result authenticates execution; protected checker and delivered
candidate binding establish the bonus outcome. The current WorkEscrow settlement
is an openly trusted EOA verdict bridge. It is not fully contract-verified Apple
execution. This bounded TESTNET pilot explicitly assumes a trusted execution host; self-run and best-effort routes have the SAME experimental integrity policy. It does not claim hostile-host tamper resistance or production permissionless security. A final disk hash alone must not be assumed to prove a hostile host could not forge receipt/check bytes before that hash was attested. A bounded native primitive test now confirms an external write to the same retained inode is included by the current finalizer. It used dummy bytes, not a VM or Apple assertion, and is not an end-to-end exploit claim. The current binary remains trusted-host-only for this boundary. A generic native block-integrity upgrade is separate research; it does not block this explicitly experimental trusted-host testnet pilot.

## Offline controls

```sh
python3 -B -m unittest discover -s . -p 'test_*.py' -v
```

Controls cover duplicate JSON, unprotected/symlink paths, HTTPS/origin restrictions,
exact original membership, saved-plan binding, uncertain-job non-reexecution,
candidate projection and closed protected checker execution. They do not launch a
VM, enroll a key, sign, fund or verify a fabricated Apple proof.
