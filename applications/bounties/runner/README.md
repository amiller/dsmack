# Bounty Mac client

The runner checks a contributor's Bounty Arcade board-search commit on a Mac and
submits the evidence for a deterministic, browser-only testnet bonus. It uses no
model or subscription credentials. Wallet, task, registration, queue and
settlement logic live in the service, not in the signed Mac app.

## Worker-owned Mac

Prerequisites: Apple silicon on macOS 27+, trusted Python 3 and Node 24, and disk
for one expanded runtime, the public task and working disks plus 12 GiB reserve.
Get the maintainer public key (SHA256
`4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df`) from a source
other than the service. The service publishes the signed runtime in `GET /api/task`.

From this source directory, replace the deployment origin and local Node path:

```sh
python3 -I setup.py --api https://PUBLISHED-PILOT-ORIGIN \
  --home "$HOME/.dsmack-arcade" --node /PATH/TO/TRUSTED/NODE24 \
  --public-key /PATH/TO/INDEPENDENTLY-CHECKED/release-public.pem
```

Setup authenticates the runtime, derives this Mac's bootstrap and paths, and
installs one runtime. State goes in `--home` plus `/s`, short enough for native
Unix socket paths; setup checks the helper-path length before any network access.
If your home path is too long, pass `--state-dir /SHORT/OWNED/PATH`, a fresh
directory under an existing protected parent. Setup does not create a key, launch
a VM or download an interpreter. It keeps a partial install rather than
overwriting it. Leave Gatekeeper and quarantine enabled.

Use `client.py --config "$HOME/.dsmack-arcade/client.json" COMMAND ...`:

1. `authorization --purpose registration --payee 0xYOURADDRESS --out REG-AUTH.json`
   fetches a wallet message bound to domain, task, policy, payee, nonce and
   expiry. Sign it in your own wallet and save only the signature to a file.
2. `register --authorization REG-AUTH.json --wallet-signature REG-SIGNATURE.txt
   --out REGISTRATION.json` generates a fresh key through the signed app's
   LaunchServices enrollment mode and submits its Apple attestation. Any Mac that
   passes the common app policy is registered; there is no worker allowlist.
   Registration is queued; `GET /api/registrations/REGISTRATION_ID` shows the result.
3. Get and sign `authorization --purpose attempt --payee 0xYOURADDRESS
   --candidate-commit FULL40HEXCOMMIT --out ATTEMPT-AUTH.json`, then run
   `attempt --authorization ATTEMPT-AUTH.json --wallet-signature ATTEMPT-SIGNATURE.txt
   --out ATTEMPT.json`. Your wallet private key stays in your wallet.
4. `prepare --attempt ATTEMPT.json --registration REGISTRATION.json` requests the
   server's signed task. If preparation is pending, check status and repeat the
   same command; it reuses its saved request id. The client downloads the
   hash-bound public inputs, makes its local task/2 paths and runs the
   coordinator's prepare checks.
5. `check --attempt ATTEMPT.json`, `run --attempt ATTEMPT.json`, then
   `submit --attempt ATTEMPT.json`. `resume` observes the same run without
   launching it again. The 21 original files upload in bounded chunks, and the
   server's full verifier and checker decide the result for either route.
   At any point, `progress --attempt ATTEMPT.json` prints the stage (preparing,
   ready to run, executing, submitting, verifying, reward step, paid), elapsed
   time and the one next command. It only reads; `--json` gives the stage for
   scripts. `paid` appears only after the service observes your withdrawal.
6. Once status shows a full verdict, `cleanup --attempt ATTEMPT.json`
   authenticates the signed report, confirms the helper has stopped, runs the
   guarded scratch retirement and removes the four public copies. Original
   evidence, credentials, archive and active runtime stay. It writes
   `CLEANUP-COMPLETE.json`; run it before the next test. If it refuses, keep the
   state as is.

The service fetches the commit from the published repository and runs the frozen
39-file base with that commit's three `apps/board/{index.html,logic.js,ui.js}`
files overlaid. The commit's package, test and runtime files are ignored. The
signed task binds both the commit and the projected-tree hash. One VM runs the
frozen tests on the base, then on the commit: the base must fail a typed
assertion (a crash or timeout does not count) and the commit must pass them all.

## Best-effort route

A participant without a Mac can request `prepare --attempt ATTEMPT.json --mode
best_effort`, which queues the attempt for any registered node. The maintainer's
Mac runs as an ordinary node:

```sh
python3 -I node_worker.py --config LOCAL-CLIENT.json \
  --registration LOCAL-NODE-REGISTRATION.json --wait-seconds 600
```

It leases one prepared task through the public API with its private node
capability, runs the same coordinator, submits the same 21 originals and waits
for the full verdict, then cleans up before the next lease. The participant's
payee and commit are fixed in the attempt, so the node cannot redirect the reward.

## Zed service bridge

`worker.py` polls the public HTTPS lease API with its own protected root worker
credential. The web pod holds no Apple verifier, release private key or report
key. `configure.py` creates private configs and stores with signing off at first.
The worker runs only pinned handlers and config. It never repeats an enrollment,
challenge, verification or signing action whose outcome is uncertain; it can
re-post a completed result only from its matching cache.

`server_adapter.py` calls the Linux verifier CLI. The configured factory, currently
[`examples/arcade/task_factory.py`](../examples/arcade/task_factory.py), resolves the
repository source, freezes checker and runtime inputs and runs the public packer.
`authority.py` signs only the factory-derived workload admission, using the
release key kept on Zed and only when its config authorizes signing.
[`examples/arcade/prepare_release.py`](../examples/arcade/prepare_release.py) prepares unsigned manifest, profile and provenance changes
around the existing app and base; it does not sign or install.

The full verifier result authenticates execution, and the protected checker plus
the delivered-commit binding decide the bonus. Settlement goes through WorkEscrow
with a trusted EOA relaying the verdict. Both routes trust the Mac host: the
finalizer hashes the result disk after the run, so a host that rewrites the
retained inode before finalization changes what gets attested.

## Offline tests

```sh
python3 -B -m unittest discover -s . -p 'test_*.py' -v
```

These cover duplicate JSON, unprotected and symlinked paths, HTTPS and origin
checks, exact original membership, saved-plan binding, no re-execution of
uncertain jobs, commit projection and the protected checker. They run without a
VM, key, signature, funds or Apple proof.

## Selecting the task adapter

`configure.py` requires operator-selected `factory` and `guest_driver` source descriptors (`path`, `bytes`, `sha256`) in addition to the publisher inputs. For the working Board-search configuration, select `examples/arcade/task_factory.py` and `examples/arcade/guest_driver.py`. Other task code is selected by the operator, never supplied by an attempt. See the [Arcade example](../examples/arcade/README.md) for its checker and workload inputs.

## Serving several tasks from one Mac

`fleet.py` polls fixed service registrations in order and runs one task at a time:

```sh
python3 -I fleet.py --config /absolute/private/fleet.json --state /short/owned/fleet
```

Create the private state directory first. `fleet.json` contains `services`, a list of `{name,config,registration}` entries naming each service's client configuration and enrolled node registration file. Use short distinct names such as `undo`, `deadlock` and `segments`. Client configurations can share one installed runtime; each service registration keeps its own node capability.

The normal node worker locks the installation's parent directory before taking a lease and holds that lock through verification and cleanup. The fleet polls empty queues without waiting, advances to fresh run state only after guarded cleanup, and stops on an uncertain child outcome for inspection. Its own lock prevents duplicate fleet controllers. Worker logs rotate at 1 MiB, keeping one previous file beside each run. Original run evidence remains in the run directory.
