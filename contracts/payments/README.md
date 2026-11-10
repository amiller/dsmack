# Prepaid USDC rail

`../src/UsageEscrow.sol` holds user deposits and pays broker-signed cumulative
weekly claims. Each user's deposits cap its payouts; the EIP-712 domain salt
isolates users. Users can close their account and withdraw after a 14 day claim
window without any further broker signature. Node measurements and operator
addresses are immutable; posted prices live in broker configuration.

Run from the repository root:

```sh
forge test --root contracts
python3 -m unittest discover -s contracts/payments -p 'test_*.py' -v
```

Deployment uses Python 3, Foundry and `requirements.txt`. The coordinator uses the
agent testnet funding wallet (0x1FBe7a7b3f7a37A967F3d927Abd6f04DB2766c5b) and the
Base Sepolia USDC token. Prepare `PAYMENTS_DIR/funding-wallet.address` with that
wallet's public address, set `PAYMENTS_USDC` to the token address, then run:

```sh
export PAYMENTS_USDC=0xBASE_SEPOLIA_USDC_ADDRESS
bash contracts/payments/deploy-and-fund.sh AGENT_WALLET_KEY PAYMENTS_DIR
bash contracts/payments/verify.sh 0xNEW_ESCROW
```

The constructor is `(address usdc, address owner)`. Deployment checks the wallet
identity before network access, pins a finalized Base Sepolia block, deploys,
and checks the compiled runtime plus immutable owner/token. It requires 0.02
Sepolia ETH plus gas and preserves a 0.02 ETH reserve. Transaction records and
`deployment.json` go under `PAYMENTS_DIR/contract/`.

Use a fresh output directory for this deployment. Generate broker payment config
from `deployment.json` with `applications/payments/configure.mjs`; configure
`inferenceOperator`, S1 prices and registered classes. The first
`register-class.mjs` invocation pins the attested broker's secp256k1 address with
`registerBroker`. Rebuild and repack Linux compute guests with the new escrow and
register their new compose/image measurements before the Mac pool offers them.
Broker and guest deployment commands are in
[applications/payments](../../applications/payments/README.md#run).

`PAYMENTS_RPC_URLS` selects an ordered, comma-separated list of Base Sepolia RPCs.
One healthy provider is enough; rate-limited providers back off for 1–60 seconds
(or longer with `Retry-After`). State reads retain the finalized block hash.
Defaults are Base, PublicNode and dRPC. Source verification uses the coordinator's
existing Basescan API key.
