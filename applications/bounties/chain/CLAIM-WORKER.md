# Zed claim worker

`claim_handler.py` is the `claim` handler for the privileged pull worker. Its
stdin is exactly `{action:"claim",input,job_dir,input_sha256}` and its stdout
exactly `{public_result:<claim packet>,artifacts:[]}`. It receives the same
protected `--config`/`--config-sha256` binding as the other worker actions, which
selects a `claim_bridge` descriptor:

```
claim_bridge: {
  script: {path: <absolute worker.py>, bytes: <actual>, sha256: <actual>},
  config: {path: <private bridge JSON>, bytes: <actual>, sha256: <actual>}
}
```

The bridge validator points at an immutable runtime adapter config that has no
claim_bridge descriptor, which keeps the config digests acyclic. On every claim
observation it calls the adapter's `settlementBinding` action in a fresh job
directory under the adapter's state_dir. The adapter authenticates the original
report, verifies retained outputs, recomputes the checker/input binding and
rehashes the delivered commit.

## Bridge config

The operator fills these in after the task receipt; this source contains no
working config or keys.

- schema `dsmack-arcade-claim-worker/1`; chain_id 84532; contract
  `0x62fedc157f275abb8f8b4543696e6f0c717d391b`; runtime_sha256
  `dd3596a61b94402a0161b950319d726fed7ffd0fd384774fa562d07b06aa6daa`.
- task_id: positive decimal string >= 10; task_created_block: hex block;
  package_hash/policy_hash: lowercase 64-hex; requester: lowercase address;
  payout_wei: positive decimal string; rpc_url: HTTPS Base Sepolia endpoint.
- terms: effort_pay `"0"`, completion_pay equal to payout_wei,
  submit_seconds/review_seconds/adjudication_seconds integers, adjudicator
  lowercase address. Every term must match the chain.
- roles: allocator/execution/review/delivery, each `{address,key_file}`. Keys
  stay in their private 0700 Zed directory; each 0600 JSON is exactly
  `{address,private_key}`. Keys are read into memory by eth_account only, never
  passed in argv or environment, logged or returned to the service.
- journal_root: private 0700 directory, separate from web state.
  max_allocator_fee_wei: positive, <= 10^15 (covers signed L2 gas plus Base L1
  and operator fee quotes).
- validator: `{python,script,script_sha256,config,config_sha256,job_root}`, using
  the existing actor-tools-venv interpreter.

Task terms must state that execution trusts the Mac host.

Optional testnet gas grant: add `gas_grant: {grant_wei, max_fee_wei,
max_total_wei, max_grants}` (wei strings at most 10^15, `max_grants` 1–100) and a
`roles.gas_sponsor` `{address,key_file}` distinct from the four task roles. Without
`gas_grant` the bridge behaves as before. The sponsor wallet's own balance is the
outer risk bound; fund it separately.

## State progression

Each capability-authenticated `POST /claim` queues a new observation; exact
retries reuse the same service job. A nonblocking file lock serializes access to
the task/key journal.

1. Repeat runtime and delivery validation and fresh chain, runtime and task checks.
2. If unassigned, sign one allocator transaction, recover its signer, check the
   signed rollup fees and that nonce and block are unchanged. Store the signed
   transaction privately and fsync a broadcast intent before sending once. After
   a lost response, later calls look for that same hash; they never re-sign, take
   a new nonce or resend.
3. Require a successful canonical Assigned receipt and current task, assignment,
   parent, payee and reservation state, then return a `submit` packet for the
   participant's wallet to sign. With `gas_grant`, first send `grant_wei` once per
   assignment from the sponsor to the payee, unless the payee already holds that
   much. The budget scan counts every intent under `journal_root/gas-grants/`,
   pending or uncertain included, against `max_grants` and `max_total_wei`
   (value plus actual signed L2+L1+operator fee). The signed transfer is fsynced
   as `<task>-<assignment>.intent.json` before one broadcast; later calls only
   look up that hash's canonical receipt. Until it is confirmed the packet stage
   is `gas_grant_pending` with no wallet transaction and a public
   `gas_grant: {tx_hash, value_wei, status}`.
4. Once the task is Submitted with the expected commit, evidence and delivery
   commitments inside the review window, issue the three EIP-712 Decision v2
   signatures. Validation runs again immediately before signing, and the derived
   digest is compared with the deployed `decisionDigest`. Signatures are cached,
   and every role is recovered again on cache reads. Returns relayable resolve
   calldata.
5. Withdraw is offered after a Completion Resolved event for this assignment and
   payout. Received status requires a successful canonical Withdrawn event signed
   by the worker after that resolution, for at least the payout.

"Included" means canonical inclusion as seen through the configured HTTPS RPC
endpoint; the worker does not run a light client. Public claim packets contain
no raw allocator transaction, private key, journal path or service credential.

## Tests

On Zed, with the existing dependencies:

```
/data/amiller/dsmack/bounty-payment-prep-20261022/actor-tools-venv/bin/python -I \
  applications/bounties/chain/test_worker.py
```

Tests use synthetic unused keys and mock RPC responses. They cover single
allocation and lost broadcast response, the Submitted prerequisite, role
recovery, wrong chain/runtime/funding/old-task refusal, invalid report or payee,
digest and deadline rejection, cached-signature corruption, lock contention, the
runtime and worker JSON envelopes, and Completion/Withdrawn progression. The
runtime fixture is the deployed WorkEscrow bytecode (7657 bytes), matching the
runtime SHA above.
