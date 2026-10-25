# Claim a testnet bounty

This page walks a first-time participant from a funded task to a Base Sepolia
test ETH payment. It is written so a person or a coding agent can follow it
as-is. Everything it links already exists; anything not yet available is listed
under [Not yet available](#not-yet-available).

The reward pays for a code change that passes the task's checks. Running a Mac
earns nothing on its own: the reward goes to the wallet named when the commit is
registered, whoever runs the checks.

## 1. Read the task

| | |
|---|---|
| Claim page | <https://pod.dstack.soc1024.com/arcade-pilot/> |
| Agent entry | <https://pod.dstack.soc1024.com/arcade-pilot/agent.json>, then `GET api/task` |
| Repository | [`amiller/bounty-arcade`](https://github.com/amiller/bounty-arcade) |
| Feature request | [Issue #1](https://github.com/amiller/bounty-arcade/issues/1): search box for the Board app |
| Testnet offer | [Issue #66](https://github.com/amiller/bounty-arcade/issues/66) |
| Files that count | `apps/board/index.html`, `apps/board/logic.js`, `apps/board/ui.js` |
| Success check | Seven fixed browser checks; the unchanged base must fail one, your commit must pass all seven. Listed on the claim page and in [`checker/`](../applications/bounties/examples/arcade/checker/) |
| Reward | `payout_wei` in `GET api/task`, shown on the claim page. The completed demonstration paid 0.0001 test ETH. |
| Chain and contract | Base Sepolia (84532); `contract` in `GET api/task` |
| Payee | The wallet you connect when you register a commit. It cannot be changed later, and the Mac that runs the checks cannot redirect it. |

Your other files, package scripts and tests are ignored. The three files are laid
over a fixed 39-file base.

**One payment per task.** The escrow holds one reward and assigns it once. The
first verified passing attempt to start its reward steps gets the assignment
([claim worker](../applications/bounties/chain/CLAIM-WORKER.md), step 2); after
that, other attempts cannot be paid from this task. The
[dashboard](https://pod.dstack.soc1024.com/bounties/) shows observed tasks,
attempts and payments. Check it before starting. Once assigned, the result must
be submitted within the task's submit window (`submit_seconds` in the escrow
terms).

## 2. Write the change

Use whatever coding tool and subscription you have, on your own machine. Dsmack
does not run, see or pay for your coding agent. What decides the reward is the
fixed browser checker running in an attested Linux VM, not a model's judgement.

Push the change to a branch or pull request in `amiller/bounty-arcade` and copy
the full 40-character commit SHA. A fork that is not reachable through the
repository or its PR refs cannot be fetched.

## 3. Register the commit and payee

On the claim page: connect a browser wallet, paste the SHA, and press
**Register this commit and wallet**. The wallet signs an expiring message. No
transaction is sent and no ETH moves.

An agent can do the same through the API in the
[service README](../applications/bounties/service/README.md#participant-http-api)
(steps 2–3), signing the message locally with EIP-191 `personal_sign`. Never
upload a private key.

## 4. Run the checks

Both routes run the same pinned checks and produce the same evidence.

**Your own Mac** (Apple silicon, macOS 27+, Python 3, Node 24, about 12 GiB free
plus the runtime). Follow the
[Mac client instructions](../applications/bounties/runner/README.md#worker-owned-mac):
`setup.py`, then enroll the Mac with `authorization --purpose registration` and
`register`. On the claim page press **Save private attempt file**, then from
`applications/bounties/runner`:

```sh
chmod 600 attempt.json
python3 -I client.py --config "$HOME/.dsmack-arcade/client.json" prepare --attempt attempt.json --registration REGISTRATION.json
python3 -I client.py --config "$HOME/.dsmack-arcade/client.json" check --attempt attempt.json
python3 -I client.py --config "$HOME/.dsmack-arcade/client.json" run --attempt attempt.json
python3 -I client.py --config "$HOME/.dsmack-arcade/client.json" submit --attempt attempt.json
```

`run` is the local verification: the base and your commit both go through the
checker in the VM, and the outputs stay on your Mac. `submit` uploads the 21
original files. After the verdict, run `cleanup --attempt attempt.json`.

**Best-effort Mac** (no Mac needed). Press **Request a best-effort Mac run**. The
attempt waits until an enrolled Mac picks it up. There is no promised start time.

Run time for either route: not measured for first-time installs.

## 5. Claim

When the claim page shows **All seven checks passed**, press **Prepare my reward
steps**. The page then offers one signing button per transaction:

1. **Submit verified result**: from your payee wallet.
2. **Relay reward approval**: anyone may send this; it may already be done.
3. **Withdraw reward to my wallet**: from your payee wallet.

The operator pays for the assignment transaction. Steps 1 and 3 are sent from
your wallet on Base Sepolia and need a small amount of test ETH for gas. Each
transaction has value 0 and goes to the task contract.

## Not yet available

- **Sponsored claim.** The current page and claim worker have no gas
  sponsorship; submit and withdraw need test ETH in the payee wallet.
- **Availability on the claim page.** `GET api/task` does not say whether the
  escrow task is still unassigned. Use the dashboard.
- **Release public key source.** `setup.py` needs the maintainer key (SHA256
  `4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df`) from a
  source other than the service. No such download is published yet.
- **Checker without a VM.** There is no packaged way to run the seven checks
  before registering; use the own-Mac route.
