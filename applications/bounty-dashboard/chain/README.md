# Read-only bounty chain collector

Run with Python3 (standard library only):

```sh
python3 applications/bounty-dashboard/chain/collect.py \
  --state-dir /absolute/persistent/chain-checkpoints \
  --out /absolute/output/chain.json --event-pages 200
```

No wallet, signing, transaction sending, keys or installs. Registry entries select HTTPS RPC, chain ID, exact runtime SHA256, deployment block/transaction and supported codec. A wrong chain, runtime or unsupported codec is `unknown`, with no invented balances. Additional networks/contracts can be registered explicitly; this is a known-deployment inventory, not a claim to discover every contract on the internet.

Every successful getter snapshot reads **all task and assignment IDs at one pinned block**, checks the runtime and verifies the block hash again. Values in wei and ABI uint fields remain decimal strings. Getter data is available while history indexing remains incomplete. `deposited_wei`, creation time/transaction and assignment payouts remain null until their original events have been indexed; null does not mean zero. A resolved payout is a credit, not proof that funds reached a wallet.

Event queries use inclusive windows of at most200blocks (the official Base Sepolia RPC limit). The persistent checkpoint resumes after its last canonical block; a changed anchor discards/rebuilds indexed history from deployment. Each event requires the original successful canonical receipt and exact log membership. A bounded invocation scans at most `--event-pages` windows; run it again to continue. `contracts[].coverage.events_complete` states whether indexing reaches this snapshot. Failures leave incomplete coverage and an error; they never masquerade as empty complete history. Checkpoints are replaced atomically only after a successful scan batch. Preserve the state directory across invocations; use one collector process per state/output directory.

`TaskClosed` is a requester refund **credit** in activity. Only original `Withdrawn` events become `payments`: they are pooled account withdrawals, with `task_key:null` and `assignment_key:null`. The contract does not emit enough information to attribute a pooled withdrawal to a particular task. Do not total resolved credits as received payments or assign a whole withdrawal to the last task. Ethereum inclusion/canonical observations are not finality claims.

`abi.json` contains only the selected read methods and static event ABI from the reviewed WorkEscrow artifact. It includes fixed selectors/event topics so runtime collection needs no Keccak dependency. Registry/source provenance identifies the actual successful deployment; the default registry has one confirmed bounty escrow on Base Sepolia and makes no mainnet claim. Other issuer/attestation deployments are not bounty escrows.

Tests: `python3 -m unittest discover -s applications/bounty-dashboard/chain -p 'test_*.py'`.
