# Usage escrow

`../src/UsageEscrow.sol` sells bounded byte or second allowances on Base Sepolia.
The owner registers a broker once and immutable node classes with payout,
measurements, floor price and epoch capacity target. Purchases finalize before
a VM starts. The broker verifies fresh guest attestation and signs each run
binding; settlement verifies it after the VM exits. Cumulative
EIP-712 guest receipts credit operators at the floor; congestion premiums stay
locked. A final receipt refunds unused funds immediately; timeout refunds open
one hour after purchase expiry. Payees pull credits with `withdraw()`.

Run the contract tests from the repository root:

```sh
forge test --root contracts --match-contract UsageEscrowTest --offline -vv
python3 -m unittest discover -s contracts/payments -p 'test_*.py' -v
```

Deployment uses Python 3, Foundry and `requirements.txt`. Prepare a payments
directory with `funding-wallet.address` containing the testnet funding wallet
address, then run:

```sh
bash contracts/payments/deploy-and-fund.sh /path/to/payments/funding-wallet.key /path/to/payments-dir
bash contracts/payments/verify.sh 0xDEPLOYED_CONTRACT
```

The signing process checks the owner address before network access, requires a
finalized Base Sepolia RPC quorum, deploys, compares the deployed runtime against
the compiled artifact. The funding wallet is the owner. Deployment requires
0.02 testnet ETH and preserves a 0.02 ETH reserve.
Transaction hashes and receipts go under `payments-dir/contract/`. Source
verification reads the existing API key at `~/.config/basescan/api-key`.
`PAYMENTS_RPC_URLS` can name three comma-separated independently operated HTTPS
RPCs. Defaults are Base, PublicNode and dRPC. Reads must agree at a common
finalized block hash no older than 30 minutes.
