# Claim a testnet bounty

This page takes a participant from a funded task to a Base Sepolia test ETH
payment. A person or a coding agent can follow it step by step.

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
| Reward | `payout_wei` in `GET api/task` (0.0001 test ETH for task 10) |
| Chain and contract | Base Sepolia (84532); `contract` and `task_id` in `GET api/task` |
| Payee | The wallet you connect when you register a commit. It cannot be changed later, and the Mac that runs the checks cannot redirect it. |

Your other files, package scripts and tests are ignored. The three files are laid
over a fixed 39-file base.

**Availability.** The escrow holds one assignment at a time and keeps paying
until its deposit runs out. Task 10 was funded with 0.0002 test ETH and has paid
one 0.0001 reward. The claim page shows how many funded rewards remain and
whether an assignment is active, read from the
[dashboard](https://pod.dstack.soc1024.com/bounties/). This can change until
your own reward steps reserve the assignment. Then you must submit within the
task's submit window.

## 2. Write the change

Use whatever coding tool and subscription you have, on your own machine. Dsmack
does not run, see or pay for your coding agent. The reward is decided by the
fixed browser checker running in an attested Linux VM, not by a model's judgement.

Push the change to a branch or pull request in `amiller/bounty-arcade` and copy
the full 40-character commit SHA. The service fetches commits from the
repository and its PR refs.

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

**Best-effort Mac** (no Mac needed). Press **Request a best-effort Mac run**. The
attempt waits until an enrolled Mac picks it up. There is no promised start time.

**Your own Mac** (Apple silicon, macOS 27+, Python 3.9+, Node 24, about 17 GiB free
for this runtime and its working disks; preflight calculates the requirement). The runtime was qualified on the maintainer's
Mac. A freshly enrolled Mac has not been qualified yet, so expect to report
problems. Start in a checkout of Dsmack:

```sh
git clone https://github.com/amiller/dsmack.git
cd dsmack/applications/bounties/runner
```

Fetch the release public key from GitHub and check its hash:

```sh
curl -fLo release-public.pem https://github.com/amiller/dsmack/releases/download/arcade-browser-v0.1.0-alpha.1/release-public.pem
chmod 600 release-public.pem
shasum -a 256 release-public.pem
# 4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df
```

Follow the [preflight guide](../applications/bounties/runner/INSTALL.md)
to find your Node path, then run the small check before installing:

```sh
python3 -I doctor.py --api https://pod.dstack.soc1024.com/arcade-pilot \
  --home "$HOME/.dm" --node /PATH/TO/NODE24 --public-key "$PWD/release-public.pem"
```

Doctor downloads only the signed inventory and signature, checks compatibility,
and prints the installation command. It starts no VM and uses no model credits.
Run that command. Setup creates the private directory `"$HOME/.dm"`; keep every
request, signature and attempt file there and pass full paths, because the client
refuses relative ones. Enroll the Mac with `authorization --purpose registration`
and `register`
([steps 1–2](../applications/bounties/runner/README.md#worker-owned-mac)). To
sign with a browser wallet, open the claim page, connect the payee wallet, and
under **Enroll your Mac** choose `"$HOME/.dm/REG-AUTH.json"`. The page checks that
the service holds that exact challenge for this task and wallet, then the wallet
shows the message. Signing sends no transaction. Move the downloaded signature
into the private directory and pass it to `register`:

```sh
test ! -e "$HOME/.dm/REG-SIGNATURE.txt" && mv "$HOME/Downloads/REG-SIGNATURE.txt" "$HOME/.dm/REG-SIGNATURE.txt"
chmod 600 "$HOME/.dm/REG-SIGNATURE.txt"
```

The signature file holds only the 0x signature. Your wallet private key stays in
your wallet.

On the claim page press **Save private attempt file**. Move it from your browser's
download folder into `"$HOME/.dm"` without replacing an earlier attempt file:

```sh
test ! -e "$HOME/.dm/attempt.json" && mv "$HOME/Downloads/attempt.json" "$HOME/.dm/attempt.json"
chmod 600 "$HOME/.dm/attempt.json"
```

If `"$HOME/.dm/attempt.json"` already exists from an earlier attempt, keep it,
move the new file to a new name such as `"$HOME/.dm/attempt-2.json"` and use that
name below. Then:

```sh
python3 -I client.py --config "$HOME/.dm/client.json" prepare --attempt "$HOME/.dm/attempt.json" --registration "$HOME/.dm/REGISTRATION.json"
python3 -I client.py --config "$HOME/.dm/client.json" check --attempt "$HOME/.dm/attempt.json"
python3 -I client.py --config "$HOME/.dm/client.json" run --attempt "$HOME/.dm/attempt.json"
python3 -I client.py --config "$HOME/.dm/client.json" submit --attempt "$HOME/.dm/attempt.json"
```

To see the current stage and next action between commands:

```sh
python3 -I client.py --config "$HOME/.dm/client.json" progress --attempt "$HOME/.dm/attempt.json" \
  --registration "$HOME/.dm/REGISTRATION.json"
```

Add `--json` for your agent. A requested launch is reported separately from a
completed run; do not restart a launch whose outcome is unknown.

`run` is the local verification: the base and your commit both go through the
checker in the VM, and the outputs stay on your Mac. `submit` uploads the 21
original files. After the verdict, free the task disks:

```sh
python3 -I client.py --config "$HOME/.dm/client.json" cleanup --attempt "$HOME/.dm/attempt.json"
```

The time a first install and run takes has not been measured.

## 5. Claim

When the claim page shows **All seven checks passed**, press **Prepare my reward
steps**. This reserves the assignment if one is free.

The operator may send a fixed amount of testnet gas to the payee wallet once the
assignment is reserved. The page then shows **Testnet gas being sent to your
wallet**; press **Check testnet gas grant** until it finishes. No grant is sent
if the wallet already holds that amount. If the page goes straight to the signing
buttons and your wallet has no test ETH, add some before signing. Either way,
your wallet still signs every step:

1. **Submit verified result**: from your payee wallet.
2. **Relay reward approval**: anyone may send this; it may already be done.
3. **Withdraw reward to my wallet**: from your payee wallet.

The operator pays for the reservation. Each of your transactions has value 0 and
goes to the task contract.

If a step refuses or stays uncertain, keep the page open and your attempt file.
Don't resend a transaction. Report the attempt ID shown under **Your progress**
on [issue #66](https://github.com/amiller/bounty-arcade/issues/66).
