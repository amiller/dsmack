# Zed claim worker — selected source, not activated authority

`claim_handler.py` plugs into the existing privileged pull worker's `claim`
handler. Its stdin is exactly `{action:"claim",input,job_dir,input_sha256}` and
stdout exactly `{public_result:<claim packet>,artifacts:[]}`. It receives the
same protected `--config`/`--config-sha256` binding as the other worker actions.
That binding selects a separate `claim_bridge` descriptor:

```
claim_bridge: {
  script: {path: <absolute worker.py>, bytes: <actual>, sha256: <actual>},
  config: {path: <private bridge JSON>, bytes: <actual>, sha256: <actual>}
}
```

The bridge validator references a **separate immutable runtime adapter config**
without the claim_bridge descriptor, avoiding cyclic config digests. It calls
the runtime adapter's `settlementBinding` action, with a fresh owned job directory
under that adapter's selected state_dir. The adapter must authenticate the
original report, verify retained outputs, recompute the fixed checker/input
binding and rehash the candidate delivery on every claim observation. No
certificate-only or worker-selected trust root is substituted.

Bridge config fields (operator fills actual values after task receipt/review):

- schema `dsmack-arcade-claim-worker/1`; chain_id84532; contract
  `0x62fedc157f275abb8f8b4543696e6f0c717d391b`; runtime_sha256
  `dd3596a61b94402a0161b950319d726fed7ffd0fd384774fa562d07b06aa6daa`.
- task_id actual positive decimalstring >=10; task_created_block actual hexblock;
  package_hash/policy_hash lowercase64hex; requester lowercase address;
  payout_wei positive decimalstring; rpc_url selected HTTPS Base Sepolia transport.
- terms: effort_pay `"0"`, completion_pay matching payout_wei,
  submit_seconds/review_seconds/adjudication_seconds actual integers,
  adjudicator selected lowercase address. Every onchain term must match.
- roles: allocator/execution/review/delivery each `{address,key_file}`. Keys remain
  in their existing private Zed0700 directory; each0600 JSON has exactly
  `{address,private_key}`. Scalars are read in memory by eth_account only and
  never supplied in argv/environment/logs or returned to the service.
- journal_root private0700 directory, separate from web state; max_allocator_fee_wei
  positive <=10^15 (bounds signed L2 gas plus actual Base L1/operator fee quotes).
- validator: `{python,script,script_sha256,config,config_sha256,job_root}`.
  Use the existing qualified actor-tools-venv interpreter; no dependency install.

No operative config/key is supplied in this source. New task terms must explicitly
state the current experimental trusted-host assumption. This bridge cannot cure
or upgrade native execution integrity, and does not assert an untrusted-host
production guarantee.

## State progression

Each cap-authenticated POST claim refresh queues a new observation; exact request
retries reuse the same service job. The bridge serializes access to its task/key
journal with a nonblocking file lock.

1. Repeat genuine runtime/delivery validation and fresh chain/runtime/task checks.
2. If unassigned, sign one allocator transaction, recover its signer, check actual
   signed rollup fees and late nonce/block equality. Persist signed transaction
   privately and fsync a broadcast intent **before one send**. A lost response
   only observes that same hash on later calls; no resign/new nonce/resend.
3. Require a canonical successful Assigned receipt and fresh task/assignment
   parent/payee/reservation state. Return a wallet-signed `submit` packet only.
4. Only actual Submitted state with exact candidate/evidence/delivery commitments
   and live reviewer window can issue the three EIP712 Decision v2 signatures.
   Repeat genuine validation immediately before signing; compare the derived
   digest to deployed decisionDigest. Cache signatures and recover every role
   again on cache reads. Return relayable resolve calldata.
5. Actual Completion Resolved event for this assignment/payout is mandatory
   before withdraw is offered. Zero withdrawable credit alone never means paid.
   Received status requires a canonical successful worker-signed Withdrawn event
   after that resolution, with amount at least the selected payout.

Canonical inclusion is explicitly reported as inclusion, not economic finality.
The current worker uses a selected HTTPS RPC transport; it is not a consensus
light client. Public claim packets contain no raw signed allocator transaction,
private key, journal path or service credential.

## Offline checks

On Zed with existing qualified dependencies:

```
/data/amiller/dsmack/bounty-payment-prep-20261022/actor-tools-venv/bin/python -I \
  applications/arcade-pilot/chain/test_worker.py
```

Tests use synthetic known-unused keys and mock RPC responses only. They cover
once allocation/lost broadcast response, actual Submitted prerequisite, real
synthetic role recovery, wrong chain/runtime/funding/oldtask refusal, invalid
report/payee, digest/deadline rejection, cached-signature corruption, lock
contention, exact runtime/worker JSON envelopes and Completion/Withdrawn receipt
progression. No operational config, key, RPC, funding or transaction is used.
The runtime fixture is the reviewed WorkEscrow deployed bytecode (7657bytes),
matching the exact onchain runtime SHA above; no compilation is needed.
